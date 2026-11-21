package rules

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR016: a timeout means a silent drop. Every connect the source made
// through the target's name or literal address timed out: nothing answered,
// neither the destination (it accepts, or its kernel refuses) nor anything
// on the way ("no route to host", "network is unreachable": an ICMP error,
// or a reject rule). Something drops the traffic without a word: a firewall
// in either network namespace, Docker's own rules (a network that disables
// inter-container communication), the host's; or, the one alternative on
// the destination's side, a listener whose app has stopped accepting, whose
// full accept queue makes the kernel drop new connections.
//
// It is the last resort for timeouts: every rule that explains one
// supersedes it (WR004, WR005, WR008, WR009, WR011, WR013, WR015, WR024,
// and WR021 for the host's firewall). Probe? yes: without the source's
// connect it isn't evaluated. Frequency not measured.
//
// Only timeouts: EHOSTUNREACH and ENETUNREACH are answers (WR024, WR013,
// WR015, WR021), and EACCES, EPERM and EINVAL are the source's own kernel
// refusing to send (a prohibit or blackhole route).
type wr016 struct{}

func (wr016) ID() string                { return "WR016" }
func (wr016) Layer() Layer              { return LayerPath }
func (wr016) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindTCP} }
func (wr016) Supersedes() []string      { return nil }

func (r wr016) Evaluate(v evidence.View) []Finding {
	var timedOut []evidence.TCPEv
	for _, t := range fromSource(v) {
		if !t.P.ByName() {
			continue // an address from Docker's metadata isn't how the app connects
		}
		if t.P.Outcome != evidence.OutcomeTimeout {
			return nil // something answered, or the source's kernel refused to send
		}
		timedOut = append(timedOut, t)
	}
	if len(timedOut) == 0 {
		return nil
	}
	addrs := make([]netip.Addr, 0, len(timedOut))
	for _, t := range timedOut {
		addrs = append(addrs, t.P.Addr.Addr().Unmap())
	}
	p, _, _ := platformOf(v)
	q := v.Question()
	owner, haveOwner := v.NetnsOwner()
	hostSide := v.HostSource()
	if !hostSide && addrs[0].IsLoopback() {
		return nil // a container's own loopback: nothing on a path to judge
	}
	f := Finding{RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID())}
	for _, t := range timedOut {
		f.Supporting = append(f.Supporting, t.ID)
	}
	if src, ok := v.Source(); ok {
		f.Supporting = append(f.Supporting, src.ID)
	}
	if haveOwner {
		f.Supporting = append(f.Supporting, owner.ID)
	}
	if q.To.Class == evidence.TargetName {
		if dns, ok := v.SourceDNS(q.To.Host); ok && slices.ContainsFunc(dns.P.Answers, func(a netip.Addr) bool { return slices.Contains(addrs, a.Unmap()) }) {
			f.Supporting = append(f.Supporting, dns.ID) // the name means those addresses
		}
	}
	s := silence{v: v, f: &f, addrs: addrs, port: timedOut[0].P.Addr.Port()}
	d := v.Destinations()
	switch dst, ok := destinationHolding(v, d, addrs); {
	case d.Host != nil:
		// On Docker Desktop the host's side is reached through its VM's
		// own network stack, and the host the containers mean is Windows,
		// whose state whyreach can't read: a timeout there says nothing
		// whyreach could stand behind.
		if p.Desktop {
			return nil
		}
		s.host(d)
	case ok && !hostSide:
		s.container(dst, owner)
	case ok:
		if p.Desktop {
			return nil // the host's side reaches containers through Docker Desktop's forwarding
		}
		s.fromHost(dst)
	default:
		ownNet := ""
		if haveOwner && !hostSide {
			ownNet, _ = owner.C.SubnetHolding(addrs[0])
		}
		if p.Desktop && ownNet == "" {
			return nil // the traffic leaves Docker Desktop's VM through its own network stack
		}
		s.outside(ownNet)
	}
	f.Supporting = ids(f.Supporting...)
	f.Explanation = sentence(f.Explanation)
	return []Finding{f}
}

// netnsHolder is a destination container and the one whose network
// namespace it uses: itself, or X for network_mode container:X.
type netnsHolder struct {
	m     evidence.Match
	netns evidence.ContainerEv
}

// destinationHolding returns a running destination whose network namespace
// holds one of addrs: the container the connect went to.
func destinationHolding(v evidence.View, d evidence.Destinations, addrs []netip.Addr) (netnsHolder, bool) {
	for _, m := range d.All() {
		if !m.C.Running() || m.Published != nil {
			continue
		}
		netns := m.ContainerEv
		if o := m.C.NetnsOwner(); o != "" {
			oc, ok := v.Container(o)
			if !ok {
				continue
			}
			netns = oc
		}
		if slices.ContainsFunc(addrs, func(a netip.Addr) bool { return slices.Contains(netns.C.Addrs(), a) }) {
			return netnsHolder{m: m, netns: netns}, true
		}
	}
	return netnsHolder{}, false
}

// silence builds WR016's finding for one kind of destination.
type silence struct {
	v     evidence.View
	f     *Finding
	addrs []netip.Addr
	port  uint16
}

// connects names the timed-out connects: "worker's connect to
// 172.22.0.3:8080" (or connects, to several addresses).
func (s silence) connects() string {
	var parts []string
	for _, a := range s.addrs {
		parts = append(parts, hostPort(a.String(), s.port))
	}
	noun := "connect"
	if len(parts) > 1 {
		noun = "connects"
	}
	return fmt.Sprintf("%s's %s to %s", s.source(), noun, quoteList(parts))
}

func (s silence) timedOut() string {
	if len(s.addrs) > 1 {
		return "timed out: nothing answered any of them, not even with a refusal"
	}
	return "timed out: nothing answered, not even with a refusal"
}

func (s silence) source() string {
	if src, ok := s.v.Source(); ok {
		return src.C.DisplayName()
	}
	return s.v.HostLabel()
}

// listening sorts the listeners on the port into those that take a
// connection to the timed-out addresses and, of those, the ones whose
// accept queue holds connections already.
func (s silence) listening(l evidence.Listeners, port uint16) (accept, queued []evidence.Socket) {
	for _, sock := range l.OnPort(port) {
		if !slices.ContainsFunc(s.addrs, sock.Accepts) {
			continue
		}
		accept = append(accept, sock)
		if sock.Queued > 0 {
			queued = append(queued, sock)
		}
	}
	return accept, queued
}

// container: a running container on a network the source shares holds the
// address. Docker's metadata names the dropper when that network disables
// inter-container communication (high); otherwise the listeners show that
// the destination would have answered (medium), unless its accept queue
// holds connections already (low: the app may have stopped accepting).
func (s silence) container(dst netnsHolder, owner evidence.ContainerEv) {
	v, f := s.v, s.f
	name := dst.m.C.DisplayName()
	f.Supporting = append(f.Supporting, dst.m.ID, dst.netns.ID)
	var shared evidence.NetAttachment
	sharedOK := false
	sharedNets := sharedNetworks(owner.C, dst.netns.C)
	for _, a := range dst.netns.C.Networks {
		if !slices.Contains(sharedNets, a.Network) {
			continue
		}
		if slices.Contains(s.addrs, a.IPv4) || slices.Contains(s.addrs, a.IPv6) {
			shared, sharedOK = a, true
			break
		}
	}
	if !sharedOK {
		// The address is the destination's on a network the source isn't
		// on (WR004's case: Docker drops traffic between networks).
		f.Confidence = Low
		f.Title = fmt.Sprintf("nothing answered %s at %s", name, quoteListAddrs(s.addrs, s.port))
		f.Explanation = fmt.Sprintf("%s %s %s holds that address on a network %s isn't on, and Docker drops traffic between its networks.", s.connects(), s.timedOut()+".", name, s.source())
		f.Fix = fmt.Sprintf("Put %s and %s on a network together, and connect by %s's name.", s.source(), name, name)
		return
	}
	if shared.ICCDisabled {
		s.icc(dst, owner, shared)
		return
	}
	l, read := v.ListenersIn(dst.netns.C.ID)
	if read {
		f.Supporting = append(f.Supporting, l.ID)
	}
	accept, queued := s.listening(l.L, dst.m.Port)
	if read && len(queued) > 0 {
		s.queue(name, name+"'s app", queued, dst.m.Port)
		return
	}
	f.Title = fmt.Sprintf("something drops the traffic between %s and %s silently", s.source(), name)
	var e strings.Builder
	where := "runs on network " + shared.Network
	if dst.netns.ID != dst.m.ID {
		where = fmt.Sprintf("runs in %s's network namespace (network_mode: container), on network %s", dst.netns.C.DisplayName(), shared.Network)
	}
	fmt.Fprintf(&e, "%s %s %s %s, which %s shares", s.connects(), s.timedOut()+".", name, where, s.source())
	switch {
	case !read:
		f.Confidence = Low
		e.WriteString(", but its listening sockets couldn't be read, so an app that has stopped accepting connections (its accept queue full, the kernel then drops new ones) can't be ruled out.")
	case len(accept) > 0:
		f.Confidence = Medium
		fmt.Fprintf(&e, ", and listens on %s with no connection waiting to be accepted, so it would have accepted the connect.", socketList(accept))
	default:
		f.Confidence = Medium
		fmt.Fprintf(&e, ", and nothing in it listens on port %d for that address, so its kernel would have refused the connect.", dst.m.Port)
	}
	e.WriteString(" Something on the way drops the traffic without a word: a firewall in either container's network namespace (a VPN client's kill switch drops what it doesn't expect, for example), a rule in the host's DOCKER-USER chain, or another of Docker's rules.")
	f.Explanation = e.String()
	f.Fix = fmt.Sprintf("Find what drops the traffic between %s and %s on %s: firewall rules in either container's network namespace (a VPN or security container sharing it), the host's DOCKER-USER chain (sudo iptables -S DOCKER-USER), or the network's options (docker network inspect %s). Run the same diagnosis after each change: the connect times out as long as something drops it.",
		s.source(), name, shared.Network, shared.Network)
}

// icc: the shared network disables inter-container communication, and
// Docker drops the traffic between its containers (measured on Engine
// 29.9.3: a timeout, with the destination listening).
func (s silence) icc(dst netnsHolder, owner evidence.ContainerEv, n evidence.NetAttachment) {
	f := s.f
	name := dst.m.C.DisplayName()
	f.Confidence = High
	if l, ok := s.v.ListenersIn(dst.netns.C.ID); ok {
		f.Supporting = append(f.Supporting, l.ID)
	}
	label := "Docker network " + n.Network
	setting := "its option com.docker.network.bridge.enable_icc=false"
	if n.Network == evidence.NetworkBridge {
		label = "Docker's default bridge network"
		setting = `the daemon's "icc": false`
	}
	f.Title = fmt.Sprintf("%s disables inter-container communication, so Docker drops the traffic between %s and %s", label, s.source(), name)
	f.Explanation = fmt.Sprintf("%s and %s share %s, and %s tells Docker to drop the traffic between its containers. Docker drops it without an answer, so %s %s",
		s.source(), name, label, setting, s.connects(), s.timedOut()+".")
	alt := fmt.Sprintf(" If the isolation is on purpose, publish %s's port and connect through the host instead.", name)
	switch {
	case n.Network == evidence.NetworkBridge:
		f.Fix = fmt.Sprintf(`If the containers are meant to talk, remove "icc": false from /etc/docker/daemon.json and restart Docker, or put %s and %s on a user-defined network together, where they also reach each other by name.`, s.source(), name) + alt
	case projectOf(owner.C) != "":
		key := composeKey(owner.C, n.Network)
		f.Fix = fmt.Sprintf("If the containers are meant to talk, delete com.docker.network.bridge.enable_icc from networks: %s: driver_opts in the Compose file and recreate the network (docker compose down, then docker compose up -d), or put %s and %s on another network together, one without that option.", key, s.source(), name) + alt
	default:
		f.Fix = fmt.Sprintf("If the containers are meant to talk, create the network again without the option (once its containers are gone, docker network rm %s, then docker network create %s), or put %s and %s on another network together.", n.Network, n.Network, s.source(), name) + alt
	}
}

// queue: the listener that takes the connect holds connections in its
// accept queue already. An app that keeps up accepts them at once; once
// the queue is full, the kernel drops new connections without an answer
// (measured: a listener whose app never accepts times out from the second
// connect on), so the timeout may well be the app's, not the path's.
func (s silence) queue(name, app string, queued []evidence.Socket, port uint16) {
	f := s.f
	f.Confidence = Low
	n := 0
	for _, sock := range queued {
		n = max(n, sock.Queued)
	}
	f.Title = fmt.Sprintf("the connect timed out, and %s's listener on port %d has %d %s waiting to be accepted", name, port, n, plural(n, "connection", "connections"))
	f.Explanation = fmt.Sprintf("%s %s %s's listener on %s has %d %s waiting to be accepted, where an app that keeps up accepts them at once. When the accept queue is full, the kernel drops new connections without an answer, which times out just like a firewall's drop: %s may have stopped accepting (stuck, or every worker busy).",
		s.connects(), s.timedOut()+".", name, socketList(queued), n, plural(n, "connection", "connections"), app)
	f.Fix = fmt.Sprintf("Check %s: its logs, and whether it is stuck or out of workers; restarting it empties the queue. If the queue stays empty and the connect still times out, something on the way drops it: a firewall.", app)
}

// host: the target is the host's own address (or a port published there).
// The host's listeners show that it would have answered (medium); what
// drops the traffic is most often the host's firewall, which doesn't let
// Docker's networks in: WR021's case, which supersedes this one when the
// host answers its own connect to the same address and port. When that
// connect timed out too, the drop covers the host's own traffic as well.
func (s silence) host(d evidence.Destinations) {
	v, f := s.v, s.f
	host := v.HostLabel()
	f.Supporting = append(f.Supporting, d.Host.Evidence...)
	for _, m := range d.Published {
		f.Supporting = append(f.Supporting, m.ID)
	}
	l, read := v.HostListeners()
	if read {
		f.Supporting = append(f.Supporting, l.ID)
	}
	port := v.Question().To.Port
	accept, queued := s.listening(l.L, port)
	// whyreach's own connect from the host, made for comparison (WR021):
	// timed out too, it says the drop isn't only for Docker's networks.
	ctl, ran := v.HostControl(netip.AddrPortFrom(s.addrs[0], port))
	hostToo := ran && ctl.P.Outcome == evidence.OutcomeTimeout
	if hostToo {
		f.Supporting = append(f.Supporting, ctl.ID)
	}
	if read && len(queued) > 0 {
		s.queue(host, "the app listening on "+host, queued, port)
		if hostToo {
			f.Explanation += fmt.Sprintf(" whyreach's own connect from %s to the same address and port timed out as well.", host)
		}
		return
	}
	src := s.source()
	fromHost := v.HostSource()
	what := "the host's firewall"
	if v.HostLabel() != "the host" {
		what = host + "'s firewall"
	}
	if fromHost {
		f.Title = fmt.Sprintf("something on %s drops its own connect to %s silently", host, quoteListAddrs(s.addrs, port))
	} else {
		f.Title = fmt.Sprintf("something drops the traffic from %s to %s silently, most likely %s", src, host, what)
	}
	var e strings.Builder
	if fromHost {
		fmt.Fprintf(&e, "%s, %s, %s", s.connects(), plural(len(s.addrs), "one of its own addresses", "its own addresses"), s.timedOut()+".")
	} else {
		fmt.Fprintf(&e, "%s on %s %s", s.connects(), host, s.timedOut()+".")
	}
	switch {
	case !read:
		f.Confidence = Low
		fmt.Fprintf(&e, " %s's listening sockets couldn't be read, so an app that has stopped accepting connections can't be ruled out.", sentence(host))
	case len(accept) > 0:
		f.Confidence = Medium
		fmt.Fprintf(&e, " %s listens on %s with no connection waiting to be accepted, so it would have accepted the connect.", sentence(host), socketList(accept))
	default:
		f.Confidence = Medium
		fmt.Fprintf(&e, " Nothing on %s listens on port %d for that address, so its kernel would have refused the connect.", host, port)
	}
	if fromHost {
		e.WriteString(" Something drops it on the way: a firewall rule on the host itself.")
		f.Explanation = e.String()
		f.Fix = fmt.Sprintf("Check the host's own firewall rules for port %d (sudo nft list ruleset, or sudo iptables -S).", port)
		return
	}
	if hostToo {
		fmt.Fprintf(&e, " whyreach's own connect from %s to the same address and port timed out as well, so what drops the traffic drops %s's own too: a firewall rule for the port that covers every source, or an app that has stopped accepting connections since its sockets were read.", host, host)
		f.Explanation = e.String()
		f.Fix = fmt.Sprintf("Check %s for a rule about port %d that covers every source (sudo nft list ruleset, or sudo iptables -S INPUT), and whether the app on port %d still accepts connections (its logs; restarting it empties its queue).", what, port, port)
		return
	}
	fmt.Fprintf(&e, " Something drops the traffic on the way, most often %s (ufw, firewalld or iptables INPUT rules), which by default doesn't let Docker's networks in.", what)
	f.Explanation = e.String()
	allow, subnet := "Docker's networks", "<that subnet>"
	if owner, ok := v.NetnsOwner(); ok {
		var nets []string
		for _, a := range owner.C.Networks {
			for _, p := range a.Subnets {
				if p.Addr().Is4() {
					nets = append(nets, p.String())
				}
			}
		}
		if len(nets) > 0 {
			allow = fmt.Sprintf("%s's %s (%s)", src, plural(len(nets), "network", "networks"), quoteList(nets))
		}
		if len(nets) == 1 {
			subnet = nets[0]
		}
	}
	f.Fix = fmt.Sprintf("Check %s for port %d (sudo ufw status verbose, sudo firewall-cmd --list-all, or sudo iptables -S INPUT) and allow connections from %s to it; with ufw, for example: sudo ufw allow from %s to any port %d proto tcp.", what, port, allow, subnet, port)
}

// fromHost: the host (or a host-network container) connects to a running
// container's address. Nothing of Docker's stands between the host and a
// container on a bridge network, so the drop is most likely in the
// container's own network namespace; and on a macvlan or ipvlan network
// the host can't reach its own containers at all. Whyreach can't tell
// which (low).
func (s silence) fromHost(dst netnsHolder) {
	f := s.f
	name := dst.m.C.DisplayName()
	f.Supporting = append(f.Supporting, dst.m.ID, dst.netns.ID)
	f.Confidence = Low
	if l, ok := s.v.ListenersIn(dst.netns.C.ID); ok {
		f.Supporting = append(f.Supporting, l.ID)
		if _, queued := s.listening(l.L, dst.m.Port); len(queued) > 0 {
			s.queue(name, name+"'s app", queued, dst.m.Port)
			return
		}
	}
	f.Title = fmt.Sprintf("nothing answered %s at %s, so something drops the traffic silently", name, quoteListAddrs(s.addrs, dst.m.Port))
	via := ""
	if src, ok := s.v.Source(); ok {
		via = fmt.Sprintf(" %s uses %s's network namespace (network_mode: host).", src.C.DisplayName(), s.v.HostLabel())
	}
	f.Explanation = fmt.Sprintf("%s %s %s holds that address.%s From %s, nothing of Docker's stands between it and a container on a bridge network, so the drop is most likely in %s's own network namespace: a firewall there. On a macvlan or ipvlan network, %s can't reach its own containers at all, by the driver's design.",
		s.connects(), s.timedOut()+".", name, via, s.v.HostLabel(), name, s.v.HostLabel())
	f.Fix = fmt.Sprintf("Check the firewall rules in %s's network namespace (a VPN or security container sharing it, for example). If its network is a macvlan or ipvlan one, reach it from a container on that network instead, or give the host a macvlan interface of its own there.", name)
}

// outside: no container holds the address, and it isn't the host's. The
// host's route for it, when looked up, shows where the traffic goes; that
// is as far as whyreach sees (low). On the source's own network (ownNet),
// nothing there answers: WR024's stale address, which supersedes this.
func (s silence) outside(ownNet string) {
	v, f := s.v, s.f
	host := v.HostLabel()
	f.Confidence = Low
	if ownNet != "" {
		f.Title = fmt.Sprintf("nothing answered the connect to %s on %s's own network", quoteListAddrs(s.addrs, s.port), s.source())
		f.Explanation = fmt.Sprintf("%s %s %s lies on %s's own network %s, where no container holds it: nothing there answers.",
			s.connects(), s.timedOut()+".", s.addrs[0], s.source(), ownNet)
		f.Fix = fmt.Sprintf("Connect by the name of the container %s means, not by an address: addresses change when containers are recreated.", s.source())
		return
	}
	f.Title = fmt.Sprintf("nothing answered the connect to %s, so something on the way drops it silently", quoteListAddrs(s.addrs, s.port))
	var e strings.Builder
	fmt.Fprintf(&e, "%s %s No container holds %s, and %s %s's, so whyreach can't see the rest of the way: something drops the traffic on the way or at the destination (its firewall, or a network that isn't reachable from here).",
		s.connects(), s.timedOut()+".", plural(len(s.addrs), "that address", "those addresses"), plural(len(s.addrs), "it isn't", "they aren't"), host)
	if !v.HostSource() {
		fmt.Fprintf(&e, " From a container, the traffic leaves through its network's gateway, and %s's routing table and firewall (its FORWARD chain) decide the rest of the way.", host)
	}
	for _, rt := range v.HostRoutes() {
		if !slices.Contains(s.addrs, rt.R.Dst) || len(rt.R.Networks) > 0 || rt.R.Chosen == nil {
			continue
		}
		f.Supporting = append(f.Supporting, rt.ID)
		c := *rt.R.Chosen
		dev := c.Dev
		if dev == "" {
			dev = "several interfaces"
		}
		switch {
		case c.Default() && privateAddr(rt.R.Dst):
			fmt.Fprintf(&e, " %s has no route for %s but its default one (via %s), although it is a private address: if it's behind a VPN or on another network, the route to it is missing (a VPN that is down, say).", sentence(host), rt.R.Dst, dev)
		case c.Default():
			fmt.Fprintf(&e, " %s sends it through its default route (via %s).", sentence(host), dev)
		default:
			fmt.Fprintf(&e, " %s sends it through its route %s.", sentence(host), c)
		}
		break
	}
	f.Explanation = e.String()
	target := hostPort(s.addrs[0].String(), s.port)
	if v.HostSource() {
		f.Fix = fmt.Sprintf("Check that %s is the right address and port. The drop is outside Docker: the destination's firewall, or the network path to it (a VPN that is down, a route that is missing).", target)
		return
	}
	f.Fix = fmt.Sprintf("Check that %s is the right address and port, and whether it answers from %s (nc -vz -w 3 %s %d). If it times out there too, the drop is outside Docker: the destination's firewall, or the network path to it (a VPN that is down). If it answers from %s but not from %s, Docker's forwarding is in the way: ip_forward, or the FORWARD policy of %s's firewall.",
		target, host, s.addrs[0], s.port, host, s.source(), host)
}

// privateAddr reports an address of a private range (RFC 1918, ULA) or the
// shared address space (100.64.0.0/10, which VPNs such as Tailscale use).
func privateAddr(a netip.Addr) bool {
	return a.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// quoteListAddrs renders addresses with a port: "172.22.0.3:8080 and
// [fd00::3]:8080".
func quoteListAddrs(addrs []netip.Addr, port uint16) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, hostPort(a.String(), port))
	}
	return quoteList(parts)
}
