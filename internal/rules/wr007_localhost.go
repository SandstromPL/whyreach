package rules

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR007: localhost (or 127.0.0.1, ::1) used inside a container to reach
// another container or the host. Inside a container, localhost is the
// container's own network namespace. Frequency rank 1.
//
// The fix depends on where the service actually runs: another container on
// a shared network (use its service name) or the host (use
// host.docker.internal). Source listeners settle the cause; the other
// containers' and the host's listeners choose the fix.
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
	// through DNS (names under .localhost, say).
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
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()),
		Confidence: Medium,
		Supporting: []string{src.ID, owner.ID},
	}
	srcName := src.C.DisplayName()
	local, haveLocal := v.ListenersIn(owner.C.ID)
	if haveLocal {
		if local.L.AcceptsLoopback(port) {
			return nil // localhost:port reaches a listener in the source itself
		}
		f.Confidence = High
		f.Supporting = append(f.Supporting, local.ID)
	}
	for _, t := range fromSource(v) {
		if t.P.Outcome == evidence.OutcomeRefused {
			f.Supporting = append(f.Supporting, t.ID)
		}
	}

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
	if hl, ok := v.HostListeners(); ok {
		if socks := hl.L.OnPort(port); len(socks) > 0 {
			hostListen = socketList(socks)
			hostLoopbackOnly = !hl.L.AcceptsRemote(port)
			f.Supporting = append(f.Supporting, hl.ID)
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
		fmt.Fprintf(&expl, ", while %s and the host (%s) do.", quoteList(names), hostListen)
	case len(cands) > 0:
		fmt.Fprintf(&expl, ", while %s %s.", quoteList(names), plural(len(cands), "does", "do"))
	case hostListen != "":
		fmt.Fprintf(&expl, ", while the host does (%s).", hostListen)
	default:
		expl.WriteString(".")
	}
	f.Explanation = expl.String()

	switch {
	case loopAddr != "":
		f.Title = fmt.Sprintf("%s means %s inside %s, which is %s itself", q.To.Host, loopAddr, srcName, srcName)
	case len(cands) == 1:
		f.Title = fmt.Sprintf("%s inside %s is %s itself, not %s", q.To.Host, srcName, srcName, cands[0].name)
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
