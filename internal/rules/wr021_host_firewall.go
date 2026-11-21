package rules

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR021: the host's firewall rejects (or drops) container-to-host traffic.
// A container's connect to one of the host's own addresses (its docker0
// address through host-gateway, a bridge network's gateway, a LAN address)
// is rejected with "no route to host" (the reject of firewalld and of
// RHEL's iptables rules: icmp-host-prohibited or admin-prohibited), dropped
// (ufw's default "deny incoming": a timeout), or refused by a rule that
// answers with a reset (ufw's reject rules), while whyreach's own connect
// from the host to the same address and port gets an answer: the host serves
// the port to itself, and filters what comes in from Docker's networks.
// Firewalls let the host's own traffic through, since it arrives on the
// loopback interface, so the comparison stands in for the rules, which
// whyreach doesn't read: that would need root, and parsing firewall rules
// is out of scope (INITIAL.md §2.2). Measured in M6 (ADR 0002).
//
// Docker Engine only (a Linux host, or a WSL2 distro whose host is the WSL2
// VM): on Docker Desktop the host the containers reach is Windows or macOS,
// behind Docker Desktop's own network stack. Probe? yes: the source's
// connect is the evidence. Frequency rank 9.
type wr021 struct{}

func (wr021) ID() string                { return "WR021" }
func (wr021) Layer() Layer              { return LayerPath }
func (wr021) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindTCP} }

// Supersedes: a timeout the host's firewall explains isn't left to WR016,
// the last resort for timeouts.
func (wr021) Supersedes() []string { return []string{"WR016"} }

// How the host's side turned the source's connect away.
const (
	turnedRejected = "rejects" // EHOSTUNREACH: a reject rule's ICMP error
	turnedDropped  = "drops"   // a timeout
	turnedRefused  = "refuses" // a reset, while the host's own connect is accepted
)

func (r wr021) Evaluate(v evidence.View) []Finding {
	if v.HostSource() {
		return nil // the host's own connect: WR019's and WR016's
	}
	src, ok := v.Source()
	if !ok {
		return nil
	}
	d := v.Destinations()
	if d.Host == nil || d.Host.Via == evidence.HostViaLoopback || len(d.Published) > 0 {
		return nil // not the host's own service: a published port goes through Docker's NAT
	}
	if p, _, ok := platformOf(v); !ok || !p.EngineHere() {
		return nil // Docker Desktop: the host is Windows or macOS, behind Docker Desktop's network stack
	}
	var failed []evidence.TCPEv
	for _, t := range v.SourceTCP() {
		if !t.P.ByName() {
			continue
		}
		switch {
		case t.P.Outcome == evidence.OutcomeConnected:
			return nil
		case !v.HostHolds(t.P.Addr.Addr()):
			continue
		case turnedAway(t.P) == "":
			return nil // ENETUNREACH (WR015), a listener that accepted and closed, a local error
		}
		failed = append(failed, t)
	}
	if len(failed) == 0 {
		return nil
	}
	t := failed[0]
	how := turnedAway(t.P)
	port := t.P.Addr.Port()
	ctl, ran := v.HostControl(t.P.Addr)
	hl, read := v.HostListeners()
	var accept []evidence.Socket
	if read {
		for _, s := range hl.L.OnPort(port) {
			if s.Accepts(t.P.Addr.Addr()) && s.Queued == 0 {
				accept = append(accept, s)
			}
		}
	}

	f := Finding{RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID())}
	host := v.HostLabel()
	srcName := src.C.DisplayName()
	var e strings.Builder
	fmt.Fprintf(&e, "%s's connect to %s %s", srcName, describeHostAddr(v, t.P.Addr), connectResult(how))
	hostToo := false
	accepted := ran && (ctl.P.Outcome == evidence.OutcomeConnected || ctl.P.Outcome == evidence.OutcomeClosed || ctl.P.Outcome == evidence.OutcomeReset)
	switch {
	case accepted || ran && ctl.P.Outcome == evidence.OutcomeRefused:
		if how == turnedRefused && !accepted {
			return nil // refused from both sides: nothing takes the port (WR001, WR012)
		}
		f.Confidence = High
		if accepted {
			fmt.Fprintf(&e, ", while whyreach's own connect from %s to the same address and port was accepted", host)
			if len(accept) > 0 {
				fmt.Fprintf(&e, " (%s listens on %s)", host, socketList(accept))
			}
			e.WriteString(".")
		} else {
			fmt.Fprintf(&e, ", while whyreach's own connect from %s to the same address and port was refused: %s answers it, though nothing there takes port %d at that address either.", host, host, port)
		}
		e.WriteString(" " + firewallVerdict(how, host, srcName))
	case ran && ctl.P.Outcome == evidence.OutcomeUnreachable && ctl.P.Errno == "EHOSTUNREACH":
		if how == turnedRefused {
			return nil
		}
		f.Confidence, hostToo = High, true
		fmt.Fprintf(&e, ", and whyreach's own connect from %s to the same address and port was rejected too: a rule of %s's firewall rejects the port for every source, %s itself included.", host, host, host)
	case ran:
		if how != turnedRejected {
			return nil // the host doesn't answer its own connect either: WR016 (a stuck app, or a rule for every source)
		}
		f.Confidence = Medium
		fmt.Fprintf(&e, ", while whyreach's own connect from %s to the same address and port %s, so the app may also have stopped accepting connections. The reject most likely comes from %s's firewall (firewalld, or iptables INPUT rules), which by default doesn't let Docker's networks in.", host, outcomeWords(ctl.P), host)
	default:
		switch {
		case how == turnedRefused, how == turnedDropped && len(accept) == 0:
			return nil // without the host's own connect, WR001's, WR012's or WR016's
		case len(accept) > 0:
			f.Confidence = Medium
			fmt.Fprintf(&e, ". %s listens on %s with no connection waiting to be accepted, so it would have accepted the connect.", sentence(host), socketList(accept))
		case read:
			f.Confidence = Medium
			fmt.Fprintf(&e, ". Nothing on %s takes port %d at that address either.", host, port)
		default:
			f.Confidence = Low
			fmt.Fprintf(&e, ". %s's listening sockets couldn't be read.", sentence(host))
		}
		fmt.Fprintf(&e, " whyreach's own connect from %s couldn't be made for comparison. Something on the way turned the connect away, most likely %s's firewall (ufw, firewalld or iptables INPUT rules), which by default doesn't let Docker's networks in.", host, host)
	}

	f.Supporting = append(f.Supporting, src.ID)
	owner, haveOwner := v.NetnsOwner()
	if haveOwner {
		f.Supporting = append(f.Supporting, owner.ID)
	}
	for _, x := range failed {
		f.Supporting = append(f.Supporting, x.ID)
	}
	f.Supporting = append(f.Supporting, d.Host.Evidence...)
	if q := v.Question(); q.To.Class == evidence.TargetName {
		if dns, ok := v.SourceDNS(q.To.Host); ok && len(dns.P.Answers) > 0 {
			f.Supporting = append(f.Supporting, dns.ID)
		}
	}
	if ran {
		f.Supporting = append(f.Supporting, ctl.ID)
	}
	if read {
		f.Supporting = append(f.Supporting, hl.ID)
	}
	f.Supporting = ids(f.Supporting...)

	// A firewall in the network namespace the source shares (a VPN client's
	// kill switch) does the same; only the host's own connect, rejected
	// too, rules it out.
	sidecar := haveOwner && owner.C.ID != src.C.ID
	if sidecar && !hostToo {
		f.Confidence = f.Confidence.Lower()
		fmt.Fprintf(&e, " %s uses %s's network namespace (network_mode: container), and a firewall there (a VPN client's kill switch) would do the same: whyreach can't tell them apart.", srcName, owner.C.DisplayName())
	}

	f.Title = fmt.Sprintf("%s's firewall %s %s's connections to port %d", host, how, srcName, port)
	if how == turnedRefused {
		f.Title += " with a reset"
	}
	f.Explanation = sentence(e.String())
	f.Fix = firewallFix(v, src, host, port, hostToo)
	if ran && ctl.P.Outcome == evidence.OutcomeRefused {
		f.Fix += fmt.Sprintf(" Then make the service on %s listen on %s too: nothing does yet.", host, t.P.Addr.Addr())
	}
	if sidecar && !hostToo {
		f.Fix += fmt.Sprintf(" If %s's firewall allows it, look at %s's: a VPN client's kill switch needs %s's address allowed (its outbound allowlist).", host, owner.C.DisplayName(), host)
	}
	return []Finding{f}
}

// turnedAway says how a failed connect was turned away, in the terms of
// WR021's title: rejected (EHOSTUNREACH), dropped (a timeout) or refused;
// "" for any other failure.
func turnedAway(p evidence.TCPProbe) string {
	switch {
	case p.Outcome == evidence.OutcomeUnreachable && p.Errno == "EHOSTUNREACH":
		return turnedRejected
	case p.Outcome == evidence.OutcomeTimeout:
		return turnedDropped
	case p.Outcome == evidence.OutcomeRefused:
		return turnedRefused
	}
	return ""
}

// connectResult describes what the source's connect got.
func connectResult(how string) string {
	switch how {
	case turnedRejected:
		return `was rejected with "no route to host" (EHOSTUNREACH), the answer of a firewall's reject rule (nothing else between a container and its host answers that way)`
	case turnedDropped:
		return "timed out: nothing answered, not even with a refusal"
	default:
		return "was refused"
	}
}

// firewallVerdict concludes when the host answered its own connect.
func firewallVerdict(how, host, src string) string {
	switch how {
	case turnedRejected:
		return fmt.Sprintf("So %s answers its own connect and rejects %s's: its firewall (firewalld, or iptables INPUT rules) turns away what comes in from Docker's networks, and lets %s's own traffic through, which arrives on the loopback interface.", host, src, host)
	case turnedDropped:
		return fmt.Sprintf("So %s answers its own connect and drops %s's: its firewall drops what comes in from Docker's networks, as ufw's default \"deny incoming\" does, and lets %s's own traffic through, which arrives on the loopback interface.", host, src, host)
	default:
		return fmt.Sprintf("So something refuses %s alone: a firewall rule that rejects with a reset, as ufw's reject rules do, while %s's own traffic, which arrives on the loopback interface, gets through.", src, host)
	}
}

// outcomeWords describes a failed connect after "the connect".
func outcomeWords(p evidence.TCPProbe) string {
	switch p.Outcome {
	case evidence.OutcomeTimeout:
		return "timed out"
	case evidence.OutcomeUnreachable:
		return "found no route (" + p.Errno + ")"
	default:
		return "failed (" + p.Outcome + ")"
	}
}

// describeHostAddr names a host address with its interface: "172.17.0.1:5432
// (the host's docker0 address)".
func describeHostAddr(v evidence.View, a netip.AddrPort) string {
	if ha, ok := v.HostAddrs(); ok {
		if i, ok := ha.H.Owner(a.Addr()); ok {
			return fmt.Sprintf("%s (%s's %s address)", a, v.HostLabel(), i.Name)
		}
	}
	return a.String()
}

// firewallFix says how to let the source's networks in, with the commands
// of the usual firewalls.
func firewallFix(v evidence.View, src evidence.ContainerEv, host string, port uint16, hostToo bool) string {
	allow, subnet := allowSubnets(v, src.C.DisplayName(), src.C.DisplayName()+"'s network")
	check := fmt.Sprintf("Check %s's firewall for port %d (sudo ufw status verbose, sudo firewall-cmd --list-all, or sudo iptables -S INPUT)", host, port)
	if hostToo {
		check = fmt.Sprintf("Find the rule of %s's firewall that rejects port %d (sudo nft list ruleset, or sudo iptables -S INPUT)", host, port)
	}
	return fmt.Sprintf("%s and allow %s in to it: with ufw, sudo ufw allow from %s to any port %d proto tcp; with firewalld, sudo firewall-cmd --permanent --zone=trusted --add-source=%s, then sudo firewall-cmd --reload; with iptables, an ACCEPT rule for that subnet before the one that rejects or drops it. Run the same diagnosis afterwards.",
		check, allow, subnet, port, subnet)
}

// allowSubnets says what a firewall should let in from the source: the
// IPv4 subnets of its network namespace's networks, "who's networks
// (172.18.0.0/16 and 172.19.0.0/16)", or fallback when none is known; and
// the subnet a command can name, "<that subnet>" unless there is just one.
func allowSubnets(v evidence.View, who, fallback string) (allow, subnet string) {
	allow, subnet = fallback, "<that subnet>"
	owner, ok := v.NetnsOwner()
	if !ok {
		return allow, subnet
	}
	var nets []string
	for _, a := range owner.C.Networks {
		for _, p := range a.Subnets {
			if p.Addr().Is4() {
				nets = append(nets, p.String())
			}
		}
	}
	if len(nets) > 0 {
		allow = fmt.Sprintf("%s's %s (%s)", who, plural(len(nets), "network", "networks"), quoteList(nets))
	}
	if len(nets) == 1 {
		subnet = nets[0]
	}
	return allow, subnet
}
