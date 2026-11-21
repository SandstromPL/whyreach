package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR013: a Docker subnet overlaps a VPN or LAN route. Docker gives each
// bridge network a subnet and the host a route into it. When the range is a
// VPN's or a LAN's as well, traffic meant for a machine there goes into
// Docker's bridge instead: from the host and from containers on other
// networks, because the host prefers Docker's route (more specific, or
// metric 0 at equal length), and from containers on that network, whose own
// subnet it is. The host's route lookup and the routes that cover the
// address show it (Probe? no). Frequency rank 15.
//
// Only that direction is WR013's: a VPN route more specific than a Docker
// subnet, which takes host-to-container traffic away from the bridge, and a
// VPN client's routes inside a container's own namespace aren't judged.
type wr013 struct{}

func (wr013) ID() string                { return "WR013" }
func (wr013) Layer() Layer              { return LayerPath }
func (wr013) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindHostRoute} }

// Supersedes WR016: the route explains the silent drop. And WR024, which
// fires only alongside a competing route here: that route shows the address
// is meant to be a machine on the VPN or LAN, not a container's old one.
func (wr013) Supersedes() []string { return []string{"WR016", "WR024"} }

func (r wr013) Evaluate(v evidence.View) []Finding {
	d := v.Destinations()
	if d.Host != nil || len(d.All()) > 0 {
		return nil // the host itself, or a container holds the address
	}
	owner, haveOwner := v.NetnsOwner()
	hostNetns := v.HostSource()
	if haveOwner && !hostNetns && onlyInternal(owner.C) {
		return nil // nothing leaves an internal network: WR015's
	}
	for _, rt := range v.HostRoutes() {
		h := rt.R
		if len(h.Networks) == 0 {
			continue
		}
		n := h.Networks[0]
		onOwn := false
		if haveOwner && !hostNetns {
			_, onOwn = owner.C.Attachment(n.Network)
		}
		// Where the traffic goes: a container sends an address on its own
		// subnet straight onto that network; anything else reaches the host,
		// whose routing table decides.
		if !onOwn && (h.Chosen == nil || !h.Chosen.Docker || h.Chosen.Dev != n.Bridge) {
			continue // the host sends it elsewhere (a VPN route that wins): not this direction
		}
		var competing []evidence.Route
		for _, c := range h.Covering {
			if !c.Docker && !c.Default() {
				competing = append(competing, c)
			}
		}
		if onOwn && len(competing) == 0 {
			continue // an address on the source's own network that no container holds: WR024's
		}
		f := Finding{RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: Medium, Supporting: []string{rt.ID}}
		if len(competing) > 0 {
			f.Confidence = High
		}
		var noAnswer []string
		for _, t := range v.SourceTCP() {
			if t.P.Addr.Addr().Unmap() != h.Dst {
				continue
			}
			switch t.P.Outcome {
			case evidence.OutcomeConnected, evidence.OutcomeRefused, evidence.OutcomeClosed, evidence.OutcomeReset:
				return nil // something answers at the address after all
			case evidence.OutcomeTimeout, evidence.OutcomeUnreachable:
				noAnswer = append(noAnswer, t.ID)
			}
		}
		if dns, ok := v.SourceDNS(v.Question().To.Host); ok && slices.Contains(dns.P.Answers, h.Dst) {
			f.Supporting = append(f.Supporting, dns.ID) // the name means that address
		}
		if src, ok := v.Source(); ok {
			f.Supporting = append(f.Supporting, src.ID)
		}
		if haveOwner {
			f.Supporting = append(f.Supporting, owner.ID)
		}
		f.Supporting = ids(append(f.Supporting, noAnswer...)...)
		if v.Incomplete() {
			f.Confidence = f.Confidence.Lower() // a container whyreach couldn't read might hold it
		}
		r.describe(&f, v, h, n, competing, onOwn, len(noAnswer) > 0)
		return []Finding{f}
	}
	return nil
}

func (wr013) describe(f *Finding, v evidence.View, h evidence.HostRoute, n evidence.DockerSubnet, competing []evidence.Route, onOwn, noAnswer bool) {
	addr := h.Dst.String()
	label := "Docker network " + n.Network
	if n.Network == evidence.NetworkBridge {
		label = "Docker's default bridge network"
	}
	netText := fmt.Sprintf("%s (%s, bridge %s)", label, n.Subnet, n.Bridge)
	src := sourceName(v)
	var c evidence.Route
	dev := ""
	if len(competing) > 0 {
		c = competing[0]
		dev = c.Dev
		if dev == "" {
			dev = "several interfaces"
		}
	}
	cText := c.Prefix.String()
	if c.Table != 0 {
		cText += fmt.Sprintf(" (table %d)", c.Table)
	}

	if len(competing) > 0 {
		f.Title = fmt.Sprintf("%s (%s) overlaps the route %s, so %s goes into Docker's bridge", label, n.Subnet, c, addr)
	} else {
		f.Title = fmt.Sprintf("%s is in the subnet of %s (%s), where no container holds it", addr, label, n.Subnet)
	}

	var e strings.Builder
	switch {
	case onOwn:
		fmt.Fprintf(&e, "%s is on %s's own network, %s, so %s sends it straight onto that network", addr, src, netText, src)
		if len(competing) > 0 {
			fmt.Fprintf(&e, ", never to the host's route via %s (%s) that covers it too.", dev, cText)
		} else {
			e.WriteString(".")
		}
	default:
		switch {
		case v.HostSource() && src != v.HostLabel():
			fmt.Fprintf(&e, "%s uses the host's network namespace (network_mode: host), and %s's routing table sends %s into %s", src, v.HostLabel(), addr, netText)
		case v.HostSource():
			fmt.Fprintf(&e, "%s's routing table sends %s into %s", src, addr, netText)
		default:
			fmt.Fprintf(&e, "%s's traffic to %s leaves through its gateway to %s, whose routing table sends it into %s", src, addr, v.HostLabel(), netText)
		}
		switch {
		case len(competing) == 0:
			e.WriteString(", and no other route there covers the address.")
		case h.Chosen != nil && c.Table == h.Chosen.Table:
			fmt.Fprintf(&e, " rather than through %s, whose route %s covers it as well: the more specific route wins, and Docker's at equal length.", dev, cText)
		default:
			fmt.Fprintf(&e, " rather than through %s, whose route %s covers it as well: the routing rules reach Docker's route first.", dev, cText)
		}
		if !v.HostSource() {
			e.WriteString(" Docker drops traffic between its networks.")
		}
	}
	if len(competing) > 0 {
		fmt.Fprintf(&e, " No container on %s holds %s: it looks like a machine on the network behind %s, whose range Docker's subnet takes over.", n.Network, addr, dev)
	} else {
		fmt.Fprintf(&e, " No container on %s holds %s. If it's a machine on your LAN or VPN, the network's subnet covers its address, and the route to it isn't on the host now (a VPN that is down, say); if it was a container's address, that container is gone.", n.Network, addr)
	}
	if noAnswer {
		fmt.Fprintf(&e, " The connect from %s got no answer.", src)
	}
	f.Explanation = sentence(e.String())

	var move string
	switch {
	case n.Network == evidence.NetworkBridge:
		move = "Move Docker's default bridge to a range none of your VPN or LAN routes use: set bip in /etc/docker/daemon.json, and restart Docker."
	case n.Project != "":
		move = fmt.Sprintf("Move %s to a range none of your VPN or LAN routes use: in its Compose file, set networks: %s: ipam: config: [{subnet: <free range>}], then recreate it (docker compose down, then docker compose up -d).", n.Network, stripProject(n.Project, n.Network))
	default:
		move = fmt.Sprintf("Move %s to a range none of your VPN or LAN routes use: once its containers are gone, docker network rm %s, then docker network create --subnet <free range> %s.", n.Network, n.Network, n.Network)
	}
	pools := " To keep Docker from picking such a range again, set default-address-pools in /etc/docker/daemon.json to ranges your VPN and LAN don't use, and restart Docker."
	if len(competing) > 0 {
		f.Fix = move + pools
	} else {
		f.Fix = fmt.Sprintf("If %s is a machine on your LAN or VPN, Docker's network is in its way. %s%s If it was a container's address, connect by the container's name instead.", addr, move, pools)
	}
}
