package engine

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// maxRouteLookups bounds the target's addresses whose host routes are
// looked up (WR013).
const maxRouteLookups = 2

// RoutesElsewhere is the message of a route record where Docker's networks
// aren't routed by the machine whyreach runs on: on Docker Desktop, its VM
// routes them (INITIAL.md §3.7).
const RoutesElsewhere = "Docker Desktop routes its containers' traffic inside its own VM, so the routes of the machine whyreach runs on say nothing about how Docker's networks overlap a VPN's or a LAN's"

// RoutesElsewhereAdvice says how to check by hand what whyreach can't.
const RoutesElsewhereAdvice = "Compare the subnets of Docker's networks (docker network inspect) with the routes of the VPN or LAN where the traffic should go: on Windows, route print shows them. A Docker subnet that a VPN or LAN route also covers takes that range away from the VPN or LAN for containers."

// routes records how the host routes the target's addresses that lie in a
// Docker bridge network's subnet and that no container holds (WR013: a
// Docker subnet overlaps a VPN or LAN route). It runs after the probes,
// since the source's lookup may give the address, and needs none of them:
// a literal address or an extra_hosts entry is enough.
func (r *run) routes(ctx context.Context) error {
	if ctx.Err() != nil || r.docker == nil || r.e.d.Routes == nil {
		return nil
	}
	view := evidence.NewView(r.q, r.store.Snapshot())
	if _, ok := view.HostTarget(); ok {
		return nil // an address of the host's own: not routed into a Docker network
	}
	cands := targetAddrs(view)
	if len(cands) == 0 {
		return nil
	}
	if r.networks == nil {
		r.networks = r.networkList(ctx) // a diagnosis from the host hasn't read it
	}
	if r.networks == nil {
		return nil
	}
	bridges := map[string]bool{}
	for _, n := range r.networks {
		if n.Bridge != "" {
			bridges[n.Bridge] = true
		}
	}
	for _, a := range r.routeTargets(view, cands) {
		ev := evidence.Evidence{
			Kind: evidence.KindHostRoute, Context: r.host(), Subject: a.String(),
			Source: "the kernel's routing tables (netlink RTM_GETROUTE), in whyreach's own network namespace",
		}
		if !r.engineHere {
			ev.Status, ev.ObservedAt = evidence.StatusUnsupported, time.Now()
			ev.Err = &evidence.Error{Code: evidence.CodeUnsupported, Message: RoutesElsewhere}
			r.store.Add(ev)
			continue
		}
		start := time.Now()
		rt, err := r.e.d.Routes(a)
		ev.Duration, ev.ObservedAt = time.Since(start), time.Now()
		if err != nil {
			ev.Status, ev.Err = probe.Classify(err)
			r.store.Add(ev)
			continue
		}
		rt.Dst, rt.Networks = a, r.dockerSubnets(a)
		// A default route covers every address: it says nothing about
		// whose range the address is in, and isn't kept.
		rt.Covering = slices.DeleteFunc(rt.Covering, evidence.Route.Default)
		if rt.Chosen != nil {
			rt.Chosen.Docker = bridges[rt.Chosen.Dev]
		}
		for i := range rt.Covering {
			rt.Covering[i].Docker = bridges[rt.Covering[i].Dev]
		}
		ev.Status, ev.Data = evidence.StatusOK, rt
		r.store.Add(ev)
	}
	return nil
}

// targetAddrs lists the addresses the target means in the source, as far as
// whyreach knows them: the literal address, the one the source's
// extra_hosts map the name to, and what the source's lookup gave.
func targetAddrs(v evidence.View) []netip.Addr {
	q := v.Question()
	var cands []netip.Addr
	if q.To.Addr.IsValid() {
		cands = append(cands, q.To.Addr)
	}
	if q.To.Class == evidence.TargetName {
		if owner, ok := v.NetnsOwner(); ok {
			if e, ok := owner.C.HostsEntry(q.To.Host); ok {
				if a, err := netip.ParseAddr(e); err == nil {
					cands = append(cands, a)
				}
			}
		}
		if d, ok := v.SourceDNS(q.To.Host); ok {
			cands = append(cands, d.P.Answers...)
		}
	}
	return slices.DeleteFunc(cands, func(a netip.Addr) bool { a = a.Unmap(); return !a.IsValid() || a.IsLoopback() })
}

// routeTargets keeps the addresses whose routes WR013 needs: in a Docker
// bridge network's subnet, not that network's gateway (the host's side),
// and held by no container, running or as a stopped container's fixed
// address (those are destinations).
func (r *run) routeTargets(v evidence.View, cands []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range cands {
		a = a.Unmap()
		switch {
		case !a.IsValid(), a.IsLoopback(), a.IsUnspecified(), a.IsLinkLocalUnicast(), a.IsMulticast(), slices.Contains(out, a):
			continue
		case len(r.dockerSubnets(a)) == 0, r.dockerGateway(a), r.heldByContainer(v, a):
			continue
		}
		out = append(out, a)
		if len(out) == maxRouteLookups {
			break
		}
	}
	return out
}

// dockerSubnets lists the Docker bridge networks whose subnets hold a, the
// most specific first.
func (r *run) dockerSubnets(a netip.Addr) []evidence.DockerSubnet {
	var out []evidence.DockerSubnet
	for _, n := range r.networks {
		if n.Bridge == "" {
			continue // macvlan, ipvlan, overlay: not routed through a bridge of the host's
		}
		for _, s := range n.Subnets {
			if s.Contains(a) {
				out = append(out, evidence.DockerSubnet{Network: n.Name, Subnet: s, Bridge: n.Bridge, Project: n.Compose})
			}
		}
	}
	slices.SortFunc(out, func(x, y evidence.DockerSubnet) int {
		return cmp.Or(cmp.Compare(y.Subnet.Bits(), x.Subnet.Bits()), strings.Compare(x.Network, y.Network))
	})
	return out
}

// dockerGateway reports a Docker network's gateway: the bridge's own side.
func (r *run) dockerGateway(a netip.Addr) bool {
	for _, n := range r.networks {
		if slices.Contains(n.Gateways, a) {
			return true
		}
	}
	return false
}

// heldByContainer reports a container that holds a: in the container list,
// or among the containers inspected.
func (r *run) heldByContainer(v evidence.View, a netip.Addr) bool {
	for _, s := range r.list {
		if s.HasAddr(a) || s.HasFixedAddr(a) {
			return true
		}
	}
	return slices.ContainsFunc(v.Containers(), func(c evidence.ContainerEv) bool {
		_, fixed := c.C.FixedOn(a)
		return fixed || slices.Contains(c.C.Addrs(), a)
	})
}
