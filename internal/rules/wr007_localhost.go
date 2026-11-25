package rules

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR007: localhost (or 127.0.0.1, ::1) used inside a container to reach
// another container or the host. Inside a container, localhost is the
// container's own network namespace. Frequency rank 1.
//
// The fix depends on where the service actually runs: another container on
// a shared network (use its service name), a container whose published
// port it is (use that container's name and its own port), or the host
// (use host.docker.internal). Source listeners settle the cause; the other
// containers' and the host's listeners, and the published ports, choose the
// fix. Where nothing anywhere listens on the port, it can't choose, so the
// finding drops to medium; and where the source is alone as well, its own
// server isn't running, WR001's case (loneLoopback; the real-case check).
type wr007 struct{}

func (wr007) ID() string                { return "WR007" }
func (wr007) Layer() Layer              { return LayerAddressing }
func (wr007) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }
func (wr007) Supersedes() []string      { return []string{"WR001"} }

func (r wr007) Evaluate(v evidence.View) []Finding {
	q := v.Question()
	if q.To.Class != evidence.TargetLoopback && q.To.Class != evidence.TargetName {
		return nil
	}
	src, ok := v.Source()
	if !ok {
		return nil
	}
	owner, ok := v.NetnsOwner()
	if !ok || owner.C.HostNetwork() {
		return nil // with network_mode: host, localhost is the host
	}
	// A name can mean loopback too: through the source's extra_hosts, or
	// through DNS (a name such as localtest.me, which points at 127.0.0.1).
	entry, viaHosts, loopAddr := "", false, ""
	if q.To.Class == evidence.TargetName {
		if e, ok := owner.C.HostsEntry(q.To.Host); ok {
			a, err := netip.ParseAddr(e)
			if err != nil || !a.Unmap().IsLoopback() {
				return nil
			}
			entry, viaHosts, loopAddr = e, true, a.Unmap().String()
		} else if dns, ok := v.SourceDNS(q.To.Host); ok && len(dns.P.Answers) > 0 && allLoopback(dns.P.Answers) {
			loopAddr = dns.P.Answers[0].String()
		} else {
			return nil
		}
	}
	port := q.To.Port
	if connectedByName(v) {
		return nil // something in the source's netns answers
	}
	if _, _, _, ok := loneLoopback(v); ok {
		return nil // nothing else could have been meant: WR001
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()),
		Confidence: Medium,
		Supporting: []string{src.ID, owner.ID},
	}
	srcName := src.C.DisplayName()
	local, haveLocal := v.ListenersIn(owner.C.ID)
	if !haveLocal && owner.C.ID != src.C.ID {
		// The source shares another container's network namespace (a
		// sidecar setup): localhost there is that container's as well, and
		// without the namespace's listeners nothing shows whether it serves
		// the port (on Docker Desktop without probe containers, say).
		return nil
	}
	if haveLocal {
		if local.L.AcceptsLoopback(port) {
			return nil // localhost:port reaches a listener in the source itself
		}
		f.Confidence = High
		f.Supporting = append(f.Supporting, local.ID)
	}
	f.Supporting = append(f.Supporting, sourceConnects(v, evidence.OutcomeRefused)...)

	type candidate struct {
		name, listen, network string
		named                 bool // the container answers to the target name
	}
	var cands []candidate
	for _, c := range v.Containers() {
		if c.C.ID == owner.C.ID || c.C.NetnsOwner() == owner.C.ID || !c.C.Running() {
			continue
		}
		shared := sharedNetworks(owner.C, c.C)
		if len(shared) == 0 {
			continue
		}
		l, ok := v.ListenersIn(c.C.ID)
		if !ok || !l.L.AcceptsRemote(port) {
			continue
		}
		cands = append(cands, candidate{name: c.C.DisplayName(), listen: socketList(l.L.OnPort(port)), network: shared[0],
			named: q.To.Class == evidence.TargetName && c.C.Matches(q.To.Host)})
		f.Supporting = append(f.Supporting, c.ID, l.ID)
	}
	hostListen := ""
	hostLoopbackOnly := false
	hl, hostRead := v.HostListeners()
	if hostRead {
		if socks := hl.L.OnPort(port); len(socks) > 0 {
			hostListen = socketList(socks)
			hostLoopbackOnly = !hl.L.AcceptsRemote(port)
			f.Supporting = append(f.Supporting, hl.ID)
		}
	}
	// A container that publishes the port on the host: the host's listener
	// there is Docker's, and the service is that container's own port.
	type publisher struct {
		name, shared, network string
		port                  uint16
	}
	var pub *publisher
	for _, c := range v.Containers() {
		if c.C.ID == owner.C.ID || !c.C.Running() || len(cands) > 0 {
			continue
		}
		b := c.C.PublishedAs(port)
		if len(b) == 0 {
			continue
		}
		p := publisher{name: c.C.DisplayName(), port: b[0].ContainerPort}
		if shared := sharedNetworks(owner.C, c.C); len(shared) > 0 {
			p.shared = shared[0]
		} else if nets := c.C.UserDefinedNetworks(); len(nets) > 0 {
			p.network = nets[0]
		}
		f.Supporting = append(f.Supporting, c.ID)
		if l, ok := v.ListenersIn(c.C.ID); ok && len(l.L.OnPort(p.port)) > 0 {
			f.Supporting = append(f.Supporting, l.ID)
		}
		pub = &p
		break
	}
	// Nothing anywhere listens on the port: no container on a shared
	// network, no published port, nothing on the host, and every container's
	// sockets were read. localhost may still be meant for another container
	// whose server listens on another port, or for the source's own server:
	// the evidence can't tell which.
	var elsewhere []string
	nowhere := f.Confidence == High && len(cands) == 0 && pub == nil && hostRead && hostListen == "" && !v.UnreadContainerListeners()
	if nowhere {
		f.Confidence = Medium
		f.Supporting = append(f.Supporting, hl.ID)
		for _, c := range v.Containers() {
			if c.C.ID == owner.C.ID || c.C.NetnsOwner() == owner.C.ID || !c.C.Running() || len(sharedNetworks(owner.C, c.C)) == 0 {
				continue
			}
			l, ok := v.ListenersIn(c.C.ID)
			if !ok {
				continue
			}
			var ports []string
			for _, s := range l.L.Sockets {
				if s.IsLoopback() || s.IsDockerDNS() {
					continue
				}
				if hp := hostPort(c.C.DisplayName(), s.Local.Port()); !slices.Contains(ports, hp) {
					ports = append(ports, hp)
				}
			}
			if len(ports) > 0 && len(elsewhere) < 6 {
				elsewhere = append(elsewhere, ports...)
				f.Supporting = append(f.Supporting, c.ID, l.ID)
			}
		}
	}
	f.Supporting = ids(f.Supporting...)

	target := hostPort(q.To.Host, port)
	var expl strings.Builder
	switch {
	case viaHosts:
		fmt.Fprintf(&expl, "%s's extra_hosts map %s to %s, and inside a container %s is the container's own network namespace, not the host's or another container's. ", srcName, q.To.Host, entry, loopAddr)
	case loopAddr != "":
		fmt.Fprintf(&expl, "%s resolves to %s in %s, and inside a container %s is the container's own network namespace, not the host's or another container's. ", q.To.Host, loopAddr, srcName, loopAddr)
	default:
		fmt.Fprintf(&expl, "Inside a container, %s is the container's own network namespace, not the host's or another container's. ", q.To.Host)
	}
	if haveLocal {
		fmt.Fprintf(&expl, "Nothing in %s listens on port %d", srcName, port)
	} else {
		fmt.Fprintf(&expl, "%s's own listeners could not be read, so it is not certain that nothing in %s listens on port %d", srcName, srcName, port)
	}
	var names []string
	for _, c := range cands {
		names = append(names, fmt.Sprintf("%s (listening on %s in %s, network %s)", c.name, c.listen, c.name, c.network))
	}
	switch {
	case len(cands) > 0 && hostListen != "":
		fmt.Fprintf(&expl, ", while %s and %s (%s) do.", quoteList(names), v.HostLabel(), hostListen)
	case len(cands) > 0:
		fmt.Fprintf(&expl, ", while %s %s.", quoteList(names), plural(len(cands), "does", "do"))
	case hostListen != "" && pub != nil:
		fmt.Fprintf(&expl, ", while %s does (%s): %s's port %d, published there.", v.HostLabel(), hostListen, pub.name, pub.port)
	case pub != nil:
		fmt.Fprintf(&expl, ", while %s publishes its port %d there.", pub.name, pub.port)
	case hostListen != "":
		fmt.Fprintf(&expl, ", while %s does (%s).", v.HostLabel(), hostListen)
	case nowhere:
		fmt.Fprintf(&expl, ", and nothing else whyreach can see listens on it either: no container on a network %s is on, no published port, nothing on %s. So localhost may be meant for another container whose server listens on another port, or for %s's own server, which isn't listening.", srcName, v.HostLabel(), srcName)
	default:
		expl.WriteString(".")
	}
	f.Explanation = expl.String()

	switch {
	case loopAddr != "":
		f.Title = fmt.Sprintf("%s means %s inside %s, which is %s itself", q.To.Host, loopAddr, srcName, srcName)
	case len(cands) == 1:
		f.Title = fmt.Sprintf("%s inside %s is %s itself, not %s", q.To.Host, srcName, srcName, cands[0].name)
	case pub != nil:
		f.Title = fmt.Sprintf("%s inside %s is %s itself, not %s", q.To.Host, srcName, srcName, pub.name)
	default:
		f.Title = fmt.Sprintf("%s inside %s refers to %s itself", q.To.Host, srcName, srcName)
	}

	var fixes []string
	for _, c := range cands {
		fixes = append(fixes, hostPort(c.name, port))
	}
	hostFix := fmt.Sprintf("host.docker.internal:%d (on Docker Engine, also give %s extra_hosts: [\"host.docker.internal:host-gateway\"])", port, srcName)
	switch {
	case len(cands) > 0 && hostListen != "":
		f.Fix = fmt.Sprintf("Connect to %s instead of %s if you meant the container, or to %s if you meant the host service.", quoteList(fixes), target, hostFix)
	case len(cands) > 0:
		f.Fix = fmt.Sprintf("Connect to %s instead of %s: the Compose service name resolves on the shared network.", quoteList(fixes), target)
	case pub != nil && pub.shared != "":
		f.Fix = fmt.Sprintf("Connect to %s instead of %s: port %d on %s is %s's port %d, published, and on the network you share (%s) %s's own port reaches it directly.",
			hostPort(pub.name, pub.port), target, port, v.HostLabel(), pub.name, pub.port, pub.shared, pub.name)
	case pub != nil:
		where := "a network it is on"
		if pub.network != "" {
			where = fmt.Sprintf("a network %s is on (%s; in Compose, declare it under networks with external: true)", pub.name, pub.network)
		}
		f.Fix = fmt.Sprintf("Put %s on %s, then connect to %s instead of %s: port %d on %s is %s's port %d, published. Going through the host also works: %s.",
			srcName, where, hostPort(pub.name, pub.port), target, port, v.HostLabel(), pub.name, pub.port, hostFix)
	case nowhere && len(elsewhere) > 0:
		f.Fix = fmt.Sprintf("If the service runs in another container, connect to its name and the port its server listens on instead of %s; on %s's networks, these listen: %s. If it should run in %s itself, it isn't listening on %d: check that it started (docker logs %s).",
			target, srcName, strings.Join(elsewhere, ", "), srcName, port, owner.C.Name)
	case nowhere:
		f.Fix = fmt.Sprintf("If the service runs in another container, connect to that container's name and its server's port instead of %s; if it should run in %s itself, it isn't listening on %d: check that it started (docker logs %s).",
			target, srcName, port, owner.C.Name)
	case hostListen != "":
		f.Fix = fmt.Sprintf("If the service runs on the host, connect to %s instead of %s.", hostFix, target)
		if hostLoopbackOnly {
			f.Fix += fmt.Sprintf(" The host service listens only on loopback (%s), so it must also listen on an address containers can reach, such as the docker0 address or 0.0.0.0.", hostListen)
		}
	default:
		f.Fix = fmt.Sprintf("Connect to the name of the container that runs the service (its Compose service name) instead of %s, or to %s if it runs on the host.", target, hostFix)
	}
	if viaHosts {
		f.Fix = fmt.Sprintf("Remove %s from %s's extra_hosts (Compose extra_hosts, docker run --add-host) and recreate it. ", hostsLine(q.To.Host, entry), srcName)
		named := false
		for _, c := range cands {
			named = named || c.named
		}
		switch {
		case named:
			f.Fix += fmt.Sprintf("Docker's DNS then answers %s with the container on the shared network.", q.To.Host)
		case len(cands) > 0:
			f.Fix += fmt.Sprintf("Then connect to %s, which runs the service.", quoteList(fixes))
		case hostListen != "":
			f.Fix += fmt.Sprintf("If the service runs on the host, map the name to the host instead: extra_hosts: [\"%s:host-gateway\"].", q.To.Host)
		default:
			f.Fix += "Map the name to the address of the machine or container that runs the service."
		}
	}
	return []Finding{f}
}

func allLoopback(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if !a.Unmap().IsLoopback() {
			return false
		}
	}
	return true
}

// hostsLine renders an extra_hosts entry.
func hostsLine(name, value string) string {
	if strings.Contains(value, ":") {
		return name + "=" + value
	}
	return name + ":" + value
}
