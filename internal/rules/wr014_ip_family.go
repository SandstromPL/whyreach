package rules

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR014: an IPv6/IPv4 mismatch on loopback. localhost means two addresses
// inside a container, where Docker's /etc/hosts maps it to 127.0.0.1 and
// ::1, and on many hosts, while a server often listens on one family only:
// 127.0.0.1 or 0.0.0.0 takes IPv4 alone, and a server told to listen on
// localhost binds the first address it resolves, often ::1 alone. Which
// address a client tries first, and whether it tries the other after a
// refusal, depends on the client, which whyreach can't see (measured on
// Engine 29.9.3: ADR 0002's M6 amendment). What the target means in the
// source, the listener's family and a connect to each address show the
// mismatch (Probe? yes). Frequency rank 18.
//
// Both directions are WR014's: an IPv4-only listener with a client that
// tries ::1, and an IPv6-only one with a client that tries 127.0.0.1.
type wr014 struct{}

func (wr014) ID() string                { return "WR014" }
func (wr014) Layer() Layer              { return LayerListener }
func (wr014) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindTCP} }
func (wr014) Supersedes() []string      { return nil }

// reachesPartly marks WR014's findings as standing when the source's
// connect worked through the target's other address (see ReachesPartly).
func (wr014) reachesPartly() {}

// family is one side of the mismatch: the target's addresses of one
// address family.
type family struct {
	name  string // IPv4 or IPv6
	addrs []netip.Addr
}

func (r wr014) Evaluate(v evidence.View) []Finding {
	q := v.Question()
	port := q.To.Port
	addrs, dns, ok := loopbackTarget(v)
	if !ok {
		return nil
	}
	f := Finding{RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID())}
	srcIn, srcOwn := "on "+v.HostLabel(), v.HostLabel()+"'s"
	if src, ok := v.Source(); ok {
		f.Supporting = append(f.Supporting, src.ID)
		srcIn, srcOwn = "in "+src.C.DisplayName(), src.C.DisplayName()+"'s"
	}
	// Where the connection arrives: the source's own network namespace,
	// or the host's (from the host, or with network_mode: host).
	var l evidence.ListenersEv
	var read bool
	where, shares := "", ""
	var pub *evidence.Match
	if v.HostSource() {
		d := v.Destinations()
		if d.Host == nil {
			return nil
		}
		if len(d.Published) > 0 {
			pub = &d.Published[0] // Docker's proxy listens for it on the host
			f.Supporting = append(f.Supporting, pub.ID)
		} else if publishedOnHost(v, port) {
			return nil // published on another host address: WR019's
		}
		if src, ok := v.Source(); ok {
			if p, _, ok := platformOf(v); ok && !p.EngineHere() {
				return nil // network_mode: host is Docker Desktop's VM, whose sockets whyreach can't read
			}
			shares = fmt.Sprintf(" (whose network namespace %s shares: network_mode: host)", src.C.DisplayName())
		}
		l, read = v.HostListeners()
		where = "on " + v.HostLabel()
	} else {
		owner, ok := v.NetnsOwner()
		if !ok {
			return nil
		}
		f.Supporting = append(f.Supporting, owner.ID)
		l, read = v.ListenersIn(owner.C.ID)
		where = "in " + owner.C.DisplayName()
		if src, ok := v.Source(); ok && src.C.ID != owner.C.ID {
			shares = fmt.Sprintf(" (whose network namespace %s shares)", src.C.DisplayName())
		}
	}
	if dns != nil {
		f.Supporting = append(f.Supporting, dns.ID)
	}
	conns := map[netip.Addr]evidence.TCPEv{}
	for _, t := range v.SourceTCP() {
		if t.P.ByName() && t.P.Addr.Port() == port {
			conns[t.P.Addr.Addr().Unmap()] = t
		}
	}
	var v4, v6 family
	v4.name, v6.name = "IPv4", "IPv6"
	for _, a := range addrs {
		if a.Is4() {
			v4.addrs = append(v4.addrs, a)
		} else {
			v6.addrs = append(v6.addrs, a)
		}
	}
	// The family the listener lacks, and the one it has: an IPv4-only
	// listener with ::1 among the target's addresses, or the converse.
	for _, dir := range [][2]family{{v6, v4}, {v4, v6}} {
		miss, have := dir[0], dir[1]
		if len(miss.addrs) == 0 {
			continue
		}
		refused, ok := allRefused(conns, miss.addrs)
		if !ok {
			continue // a connect to that family wasn't refused: no mismatch there
		}
		worked := []string{}
		if len(have.addrs) > 0 {
			var tried bool
			worked, tried = connectedTo(conns, have.addrs)
			if !tried || len(worked) == 0 {
				return nil // the listener's own family fails too: something else is wrong
			}
		}
		var socks []evidence.Socket
		switch {
		case read:
			socks = l.L.OnPort(port)
			if slices.ContainsFunc(socks, func(s evidence.Socket) bool { return takesFamily(s, miss) }) {
				return nil // a listener takes that family after all: the evidence disagrees
			}
			if !slices.ContainsFunc(socks, func(s evidence.Socket) bool { return takesFamily(s, have) }) {
				return nil // no listener of the other family either (WR001's case, or traffic forwarded elsewhere)
			}
			f.Confidence = Medium
			if len(have.addrs) == 0 {
				f.Confidence = High // every client fails: the target leads only to the missing family
			}
			f.Supporting = append(f.Supporting, l.ID)
		case len(have.addrs) > 0:
			f.Confidence = Low // only the connects show it
		default:
			return nil // no evidence of a listener at all
		}
		f.Supporting = ids(append(append(f.Supporting, refused...), worked...)...)
		r.describe(&f, v, describeArgs{
			all: addrs, miss: miss, have: have, dns: dns, socks: socks, read: read, pub: pub,
			srcIn: srcIn, srcOwn: srcOwn, where: where, shares: shares, port: port,
		})
		return []Finding{f}
	}
	return nil
}

type describeArgs struct {
	all           []netip.Addr // the target's addresses in the source, as looked up
	miss, have    family
	dns           *evidence.DNSEv
	socks         []evidence.Socket
	read          bool
	pub           *evidence.Match
	srcIn, srcOwn string // "in app", "app's" (or "on the host", "the host's")
	where         string // where the listener is: "in proxy", "on the host"
	shares        string // " (whose network namespace app shares)" for a sidecar's
	port          uint16
}

func (wr014) describe(f *Finding, v evidence.View, a describeArgs) {
	q := v.Question()
	port := a.port
	missAddr := a.miss.addrs[0]
	missHP := hostPort(missAddr.String(), port)
	target := q.To.String()
	listen := socketList(a.socks)
	split := len(a.have.addrs) > 0
	haveHP := ""
	if split {
		haveHP = hostPort(a.have.addrs[0].String(), port)
	}
	wild6 := slices.ContainsFunc(a.socks, func(s evidence.Socket) bool {
		return s.Local.Addr().Is6() && s.Local.Addr().IsUnspecified()
	})

	switch {
	case a.dns == nil:
		f.Title = fmt.Sprintf("%s is an %s address, and port %d %s has only an %s listener (%s)", missAddr, a.miss.name, port, a.where, a.have.name, listen)
	case !a.read:
		f.Title = fmt.Sprintf("%s also means %s %s, and only %s takes connections on port %d", q.To.Host, missAddr, a.srcIn, a.have.addrs[0], port)
	case split:
		f.Title = fmt.Sprintf("%s also means %s %s, and port %d has only an %s listener (%s)", q.To.Host, missAddr, a.srcIn, port, a.have.name, listen)
	default:
		f.Title = fmt.Sprintf("%s means %s %s, and port %d has only an %s listener (%s)", q.To.Host, missAddr, a.srcIn, port, a.have.name, listen)
	}

	var e strings.Builder
	switch {
	case a.dns == nil:
		fmt.Fprintf(&e, "The target %s is an %s address", missHP, a.miss.name)
	case a.dns.P.Via == evidence.ViaHosts:
		fmt.Fprintf(&e, "%s /etc/hosts maps %s to %s", a.srcOwn, q.To.Host, addrList(a.all))
	default:
		fmt.Fprintf(&e, "%s resolves to %s %s", q.To.Host, addrList(a.all), a.srcIn)
	}
	switch {
	case !a.read:
		fmt.Fprintf(&e, ", and only %s takes connections on port %d: the connect to %s was refused and the one to %s worked. The listeners %s%s couldn't be read.", a.have.addrs[0], port, missHP, haveHP, a.where, a.shares)
	case a.pub != nil:
		name := a.pub.C.DisplayName()
		fmt.Fprintf(&e, ", but %s publishes its port %d only on %s, so %s Docker's proxy listens only on %s, which takes %s alone", name, a.pub.Published.ContainerPort, a.pub.Published.HostAddr(), a.where, listen, a.have.name)
	default:
		fmt.Fprintf(&e, ", but port %d %s%s has only %s, which takes %s alone", port, a.where, a.shares, listen, a.have.name)
		if wild6 && a.miss.name == "IPv4" {
			e.WriteString(" (IPV6_V6ONLY, which the kernel's socket table doesn't show; the refused IPv4 connect does)")
		}
	}
	if a.read {
		if split {
			fmt.Fprintf(&e, ": the connect to %s was refused and the one to %s worked.", missHP, haveHP)
		} else {
			fmt.Fprintf(&e, ": the connect to %s was refused.", missHP)
		}
	}
	if split {
		if a.miss.name == "IPv6" {
			fmt.Fprintf(&e, " Whether the app fails depends on its client, which whyreach can't see: one that tries ::1 first and doesn't try 127.0.0.1 after the refusal fails with ECONNREFUSED %s:%d (Node.js 17–19, busybox wget), while Go, Python, libpq and Node.js 20+ fall back.", missAddr, port)
		} else {
			fmt.Fprintf(&e, " Whether the app fails depends on its client, which whyreach can't see: one that tries 127.0.0.1 and not ::1 fails with ECONNREFUSED %s:%d.", missAddr, port)
			if _, ok := v.Source(); ok && !v.HostSource() {
				e.WriteString(" Node.js 24 does in a glibc-based container on a network without IPv6, where its lookup leaves ::1 out.")
			}
		}
	}
	f.Explanation = sentence(e.String())

	server := "the server " + a.where
	var listenFix string
	switch {
	case !a.read:
		listenFix = fmt.Sprintf("make %s listen on %s as well", server, missHP)
	case a.pub != nil:
		pm := *a.pub.Published
		name := a.pub.C.DisplayName()
		bind := fmt.Sprintf("%d:%d", pm.HostPort, pm.ContainerPort)
		if a.miss.name == "IPv6" {
			other := "[::1]"
			if !pm.LoopbackOnly() {
				other = "[::]"
			}
			listenFix = fmt.Sprintf("publish the port on %s as well: ports: [\"%s:%s\", \"%s:%s\"] for %s, then docker compose up -d %s",
				strings.Trim(other, "[]"), hostAddrOf(pm), bind, other, bind, name, name)
		} else {
			listenFix = fmt.Sprintf("publish the port on 127.0.0.1 as well, or on every address: ports: [\"%s\"] for %s, then docker compose up -d %s", bind, name, name)
		}
	case a.miss.name == "IPv6" && slices.ContainsFunc(a.socks, func(s evidence.Socket) bool { return s.Local.Addr().Unmap().IsUnspecified() }):
		listenFix = fmt.Sprintf("make %s listen on [::]:%d instead of 0.0.0.0:%d, which takes both IPv4 and IPv6", server, port, port)
	case a.miss.name == "IPv6":
		// Read listeners include one of the other family (Evaluate): a.socks isn't empty.
		listenFix = fmt.Sprintf("make %s listen on [::1]:%d as well as %s", server, port, a.socks[0].Local.String())
	case wild6:
		listenFix = fmt.Sprintf("make %s take IPv4 as well: listen on [::]:%d without IPV6_V6ONLY, or on 0.0.0.0:%d too", server, port, port)
	default:
		listenFix = fmt.Sprintf("make %s listen on 127.0.0.1:%d as well as [::1]:%d (a server told to listen on localhost binds only one of the two)", server, port, port)
	}
	connectTo := hostPort(loopbackOf(a.have.name), port)
	if split {
		connectTo = haveHP
	}
	connectFix := fmt.Sprintf("connect to %s instead of %s", connectTo, target)
	if a.dns == nil {
		f.Fix = upperFirst(connectFix) + ", or " + listenFix + "."
	} else {
		f.Fix = upperFirst(listenFix) + "; or " + connectFix + "."
	}
}

// loopbackTarget is what the target means in the source when it is a
// loopback address: the address itself, or every address a lookup of the
// name gave in the source (127.0.0.1 and ::1 for localhost in a container),
// with that lookup. A name that means anything else isn't one; nor is
// 0.0.0.0.
func loopbackTarget(v evidence.View) ([]netip.Addr, *evidence.DNSEv, bool) {
	q := v.Question()
	if q.To.Addr.IsValid() {
		a := q.To.Addr.Unmap()
		return []netip.Addr{a}, nil, a.IsLoopback()
	}
	if q.To.Class != evidence.TargetLoopback && q.To.Class != evidence.TargetName {
		return nil, nil, false
	}
	d, ok := v.SourceDNS(q.To.Host)
	if !ok || len(d.P.Answers) == 0 {
		return nil, nil, false
	}
	var out []netip.Addr
	for _, a := range d.P.Answers {
		a = a.Unmap()
		if !a.IsLoopback() {
			return nil, nil, false
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, &d, true
}

// allRefused returns the source's connects to addrs when every one that
// ran was refused, and at least one did.
func allRefused(conns map[netip.Addr]evidence.TCPEv, addrs []netip.Addr) ([]string, bool) {
	var out []string
	for _, a := range addrs {
		t, ok := conns[a]
		if !ok {
			continue
		}
		if t.P.Outcome != evidence.OutcomeRefused {
			return nil, false
		}
		out = append(out, t.ID)
	}
	return out, len(out) > 0
}

// connectedTo returns the source's connects to addrs that worked, and
// whether any ran.
func connectedTo(conns map[netip.Addr]evidence.TCPEv, addrs []netip.Addr) ([]string, bool) {
	var out []string
	tried := false
	for _, a := range addrs {
		if t, ok := conns[a]; ok {
			tried = true
			if t.P.Outcome == evidence.OutcomeConnected {
				out = append(out, t.ID)
			}
		}
	}
	return out, tried
}

// takesFamily reports a listener that certainly takes connections to one
// of fam's loopback addresses, or for a family with none, to its loopback
// address. 0.0.0.0 takes every IPv4 address; [::] takes ::1, and IPv4 too
// unless it is IPv6-only (IPV6_V6ONLY), which /proc can't show: it never
// certainly takes IPv4.
func takesFamily(s evidence.Socket, fam family) bool {
	want := fam.addrs
	if len(want) == 0 {
		want = []netip.Addr{netip.MustParseAddr(loopbackOf(fam.name))}
	}
	raw := s.Local.Addr()
	a := raw.Unmap()
	for _, w := range want {
		switch {
		case w.Is4() && a.Is4():
			if a == w || a.IsUnspecified() {
				return true
			}
		case w.Is6() && raw.Is6() && !raw.Is4In6():
			if raw == w || raw.IsUnspecified() {
				return true
			}
		}
	}
	return false
}

// publishedOnHost reports a container that publishes port on the host.
func publishedOnHost(v evidence.View, port uint16) bool {
	return slices.ContainsFunc(v.Containers(), func(c evidence.ContainerEv) bool { return len(c.C.PublishedAs(port)) > 0 })
}

func loopbackOf(fam string) string {
	if fam == "IPv6" {
		return "::1"
	}
	return "127.0.0.1"
}

// hostAddrOf is a binding's host address as Compose writes it: 127.0.0.1,
// or [::1] for IPv6.
func hostAddrOf(pm evidence.PortMap) string {
	a, err := netip.ParseAddr(pm.HostIP)
	switch {
	case err != nil || pm.HostIP == "":
		return "0.0.0.0"
	case a.Is6():
		return "[" + a.String() + "]"
	default:
		return a.String()
	}
}

func addrList(addrs []netip.Addr) string {
	var out []string
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return quoteList(out)
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ReachesPartly reports a rule whose finding stands when the target means
// several addresses and the source's connect worked through one of them:
// the finding is about the others, and the app's own client decides which
// it uses (WR014). The verdict then follows the finding (INITIAL.md §4.4).
func ReachesPartly(ruleID string) bool {
	r, ok := ByID(ruleID)
	if !ok {
		return false
	}
	_, partly := r.(interface{ reachesPartly() })
	return partly
}
