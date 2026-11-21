package rules

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR019: from the host, a container's port is not reachable because it is
// not published, is published under another host port, or is published on
// another host address (127.0.0.1 only, say, while the client uses the
// host's LAN address). Container names don't resolve on the host either.
// Port bindings and the container's listeners settle it. Frequency rank 6.
type wr019 struct{}

func (wr019) ID() string                { return "WR019" }
func (wr019) Layer() Layer              { return LayerAddressing }
func (wr019) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }
func (wr019) Supersedes() []string      { return []string{"WR001"} }

func (r wr019) Evaluate(v evidence.View) []Finding {
	if !v.HostSource() || connectedByName(v) {
		return nil
	}
	q := v.Question()
	port := q.To.Port
	d := v.Destinations()
	if d.Host == nil {
		return r.byName(v, d)
	}
	if len(d.Published) > 0 {
		return nil // the port is published where the client connects
	}
	hl, read := v.HostListeners()
	if read && hostAccepts(hl.L, port, *d.Host, v6Only(v, port)) {
		return nil // something on the host answers there
	}
	if !read && len(sourceConnects(v, evidence.OutcomeRefused)) == 0 {
		// Without the host's listeners, only a refused connect from the
		// host shows that nothing there takes the port; the host's own
		// service might (a gap says why they weren't read).
		return nil
	}
	f := Finding{RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: High}
	target := q.To.String()

	// Published on another host address.
	if pubs := byNameOrder(v, func(c evidence.Container) []evidence.PortMap { return c.PublishedAs(port) }); len(pubs) > 0 {
		c, b := pubs[0].c, pubs[0].b
		var where []string
		for _, pm := range b {
			where = append(where, pm.HostAddr())
		}
		name := c.C.DisplayName()
		f.Supporting = refusedFrom(v, []string{c.ID})
		f.Title = fmt.Sprintf("%s publishes port %d only on %s", name, port, strings.Join(where, ", "))
		f.Explanation = fmt.Sprintf("%s publishes its port %d on %s as %s, which accepts connections only to that address, and %s goes to %s.",
			containerLabel(c.C), b[0].ContainerPort, v.HostLabel(), strings.Join(where, ", "), target, d.Host.Addr)
		if !d.Host.Addr.IsValid() {
			f.Explanation = fmt.Sprintf("%s publishes its port %d on %s as %s, which accepts connections only to that address, not to %s.",
				containerLabel(c.C), b[0].ContainerPort, v.HostLabel(), strings.Join(where, ", "), target)
		}
		instead := b[0].HostAddr()
		if anyIPv6(b[0].HostIP) {
			// docker-proxy binds [::] IPv6-only: from the host, [::1] reaches it
			instead = hostPort("::1", b[0].HostPort)
			f.Explanation += fmt.Sprintf(" On [::] Docker's proxy accepts IPv6 only, and %s resolves to IPv4.", q.To.Host)
		}
		f.Fix = fmt.Sprintf("Connect to %s instead, or publish it on every address: ports: [\"%d:%d\"] for %s in Compose (-p %d:%d), then docker compose up -d %s.",
			instead, port, b[0].ContainerPort, name, port, b[0].ContainerPort, name)
		r.others(&f, pubs)
		return []Finding{f}
	}
	// Its port is published under another host port.
	if pubs := byNameOrder(v, func(c evidence.Container) []evidence.PortMap { return c.PublishesPort(port) }); len(pubs) > 0 {
		c, b := pubs[0].c, pubs[0].b
		name := c.C.DisplayName()
		f.Supporting = refusedFrom(v, []string{c.ID})
		// Prefer a binding that accepts the address the client uses; else
		// name the binding's own address.
		pm := b[0]
		for _, x := range b {
			if d.Host.Addr.IsValid() && x.Covers(d.Host.Addr) {
				pm = x
				break
			}
		}
		covers := d.Host.Addr.IsValid() && pm.Covers(d.Host.Addr)
		host := "localhost"
		switch {
		case covers && !d.Host.Addr.IsLoopback():
			host = d.Host.Addr.String()
		case anyIPv6(pm.HostIP):
			host = "::1" // docker-proxy binds [::] IPv6-only: from the host, [::1] reaches it
		case !covers && !unspecified(pm.HostIP):
			host = pm.HostIP
		}
		f.Title = fmt.Sprintf("%s's port %d is published as %d, not %d", name, port, pm.HostPort, port)
		f.Explanation = fmt.Sprintf("%s publishes its port %d on %s as %s. Port %d on %s is the container port's number, which nothing publishes.",
			containerLabel(c.C), port, v.HostLabel(), publishedList(b), port, v.HostLabel())
		f.Fix = fmt.Sprintf("Connect to %s instead of %s, or change the mapping to ports: [\"%d:%d\"] for %s.",
			hostPort(host, pm.HostPort), target, port, port, name)
		r.others(&f, pubs)
		return []Finding{f}
	}
	// It listens on the port but publishes nothing for it.
	var servers []evidence.ContainerEv
	var listenIDs []string
	for _, c := range v.Containers() {
		if c.C.HostNetwork() || !c.C.Running() {
			continue
		}
		if l, ok := v.ListenersIn(c.C.ID); ok && l.L.AcceptsRemote(port) {
			servers = append(servers, c)
			listenIDs = append(listenIDs, l.ID)
		}
	}
	if len(servers) == 0 {
		return nil
	}
	s := servers[0]
	name := s.C.DisplayName()
	f.Supporting = refusedFrom(v, append([]string{s.ID}, listenIDs...))
	f.Title = fmt.Sprintf("%s listens on port %d but doesn't publish it", name, port)
	addrHint := ""
	// Where Docker Engine runs on whyreach's machine, its bridges are
	// there too; Docker Desktop's container addresses live in its VM.
	if a := s.C.Addrs(); len(a) > 0 {
		if p, _, ok := platformOf(v); !ok || p.EngineHere() {
			addrHint = fmt.Sprintf(" From %s it can also be reached directly at %s.", v.HostLabel(), hostPort(a[0].String(), port))
		}
	}
	f.Explanation = fmt.Sprintf("%s listens on port %d inside its container, but publishes no port for it, so nothing on %s accepts %s.", containerLabel(s.C), port, v.HostLabel(), target)
	if len(servers) > 1 {
		f.Confidence = Medium
		var others []string
		for _, o := range servers[1:] {
			others = append(others, o.C.DisplayName())
		}
		f.Explanation += fmt.Sprintf(" %s %s on port %d too, so it isn't certain which one you mean.", quoteList(others), plural(len(others), "listens", "listen"), port)
	}
	f.Fix = fmt.Sprintf("Publish it: ports: [\"%d:%d\"] for %s in Compose (docker run -p %d:%d), then docker compose up -d %s.%s",
		port, port, name, port, port, name, addrHint)
	return []Finding{f}
}

// published is a container and its bindings that a WR019 case is about.
type published struct {
	c evidence.ContainerEv
	b []evidence.PortMap
}

// byNameOrder lists the containers with bindings that sel picks, in name
// order, so the one a finding names doesn't depend on container IDs.
func byNameOrder(v evidence.View, sel func(evidence.Container) []evidence.PortMap) []published {
	var out []published
	for _, c := range v.Containers() {
		if b := sel(c.C); len(b) > 0 {
			out = append(out, published{c, b})
		}
	}
	slices.SortFunc(out, func(a, b published) int { return strings.Compare(a.c.C.Name, b.c.C.Name) })
	return out
}

// others lowers a finding that picked one of several containers and names
// the rest.
func (wr019) others(f *Finding, pubs []published) {
	if len(pubs) < 2 {
		return
	}
	f.Confidence = Medium
	var names []string
	for _, p := range pubs[1:] {
		names = append(names, fmt.Sprintf("%s (%s)", p.c.C.DisplayName(), publishedList(p.b)))
		f.Supporting = ids(append(f.Supporting, p.c.ID)...)
	}
	f.Explanation += fmt.Sprintf(" %s %s it too, so it isn't certain which one you mean.", quoteList(names), plural(len(names), "publishes", "publish"))
}

func unspecified(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return ip == "" || (err == nil && a.IsUnspecified())
}

// anyIPv6 reports a binding's host address "::": Docker's proxy then
// listens on [::] IPv6-only, so from the host [::1] reaches it, and
// localhost only where it resolves to ::1.
func anyIPv6(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.IsUnspecified() && a.Is6()
}

// byName is the case of a container name used from the host's network
// namespace (the host, or a network_mode: host container), where Docker's
// DNS doesn't answer.
func (r wr019) byName(v evidence.View, d evidence.Destinations) []Finding {
	q := v.Question()
	if q.To.Class != evidence.TargetName || len(d.Elsewhere) == 0 {
		return nil
	}
	f := Finding{RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: Medium}
	if dns, ok := v.SourceDNS(q.To.Host); ok {
		if len(dns.P.Answers) > 0 {
			return nil // the host resolves it after all (/etc/hosts?)
		}
		f.Confidence = High
		f.Supporting = append(f.Supporting, dns.ID)
	}
	m := d.Elsewhere[0]
	name := m.C.DisplayName()
	f.Supporting = append(f.Supporting, m.ID)
	f.Title = fmt.Sprintf("%s can't resolve %s: container names resolve only inside Docker networks", sourceName(v), q.To.Host)
	hl := v.HostLabel()
	f.Explanation = fmt.Sprintf("%s is a container (%s), and Docker's DNS answers its name only inside its networks. From %s's network namespace, reach a container through a port it publishes.", q.To.Host, containerLabel(m.C), hl)
	if src, ok := v.Source(); ok {
		f.Supporting = append(f.Supporting, src.ID)
		f.Explanation = fmt.Sprintf("%s is a container (%s), and Docker's DNS answers its name only inside its networks. %s uses %s's network namespace (network_mode: host), so it resolves names the way %s does; reach the container through a port it publishes.",
			q.To.Host, containerLabel(m.C), src.C.DisplayName(), hl, hl)
	}
	f.Supporting = ids(f.Supporting...)
	if b := m.C.PublishesPort(q.To.Port); len(b) > 0 {
		host := b[0].HostIP
		switch {
		case anyIPv6(host):
			host = "::1"
		case host == "" || host == "0.0.0.0":
			host = "localhost"
		}
		f.Fix = fmt.Sprintf("Connect to %s: %s publishes its port %d there.", hostPort(host, b[0].HostPort), name, q.To.Port)
	} else {
		f.Fix = fmt.Sprintf("Publish the port: ports: [\"%d:%d\"] for %s in Compose (-p %d:%d), then connect to localhost:%d.", q.To.Port, q.To.Port, name, q.To.Port, q.To.Port, q.To.Port)
	}
	return []Finding{f}
}

// hostAccepts reports a host listener that takes connections to the port at
// an address the target stands for. 0.0.0.0 takes IPv4; [::] takes both
// families unless it is IPv6-only (v6only: docker-proxy for a binding on
// "::", which /proc can't show).
func hostAccepts(l evidence.Listeners, port uint16, h evidence.HostTarget, v6only bool) bool {
	targets := h.Addresses()
	for _, s := range l.OnPort(port) {
		a := s.Local.Addr().Unmap()
		if len(targets) == 0 {
			if a.IsUnspecified() {
				return true // the address is unknown: a wildcard takes it either way
			}
			continue
		}
		for _, t := range targets {
			switch {
			case a.IsUnspecified() && a.Is4():
				if t.Is4() {
					return true
				}
			case a.IsUnspecified():
				if t.Is6() || !v6only {
					return true
				}
			case a == t:
				return true
			}
		}
	}
	return false
}

// v6Only reports a container that publishes the host port on "::": Docker's
// proxy then listens on [::] IPv6-only.
func v6Only(v evidence.View, port uint16) bool {
	for _, c := range v.Containers() {
		for _, pm := range c.C.PublishedAs(port) {
			if anyIPv6(pm.HostIP) {
				return true
			}
		}
	}
	return false
}
