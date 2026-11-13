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
	if hl, ok := v.HostListeners(); ok && hostAccepts(hl.L, port, *d.Host) {
		return nil // something on the host answers there
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
		f.Supporting = r.confirm(v, c.ID)
		f.Title = fmt.Sprintf("%s publishes port %d only on %s", name, port, strings.Join(where, ", "))
		f.Explanation = fmt.Sprintf("%s publishes its port %d on the host as %s, which accepts connections only to that address, and %s goes to %s.",
			containerLabel(c.C), b[0].ContainerPort, strings.Join(where, ", "), target, d.Host.Addr)
		if !d.Host.Addr.IsValid() {
			f.Explanation = fmt.Sprintf("%s publishes its port %d on the host as %s, which accepts connections only to that address, not to %s.",
				containerLabel(c.C), b[0].ContainerPort, strings.Join(where, ", "), target)
		}
		f.Fix = fmt.Sprintf("Connect to %s instead, or publish it on every address: ports: [\"%d:%d\"] for %s in Compose (-p %d:%d), then docker compose up -d %s.",
			b[0].HostAddr(), port, b[0].ContainerPort, name, port, b[0].ContainerPort, name)
		r.others(&f, pubs)
		return []Finding{f}
	}
	// Its port is published under another host port.
	if pubs := byNameOrder(v, func(c evidence.Container) []evidence.PortMap { return c.PublishesPort(port) }); len(pubs) > 0 {
		c, b := pubs[0].c, pubs[0].b
		name := c.C.DisplayName()
		f.Supporting = r.confirm(v, c.ID)
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
		case !covers && !unspecified(pm.HostIP):
			host = pm.HostIP
		}
		f.Title = fmt.Sprintf("%s's port %d is published as %d, not %d", name, port, pm.HostPort, port)
		f.Explanation = fmt.Sprintf("%s publishes its port %d on the host as %s. Port %d on the host is the container port's number, which nothing publishes.",
			containerLabel(c.C), port, publishedList(b), port)
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
	f.Supporting = r.confirm(v, append([]string{s.ID}, listenIDs...)...)
	f.Title = fmt.Sprintf("%s listens on port %d but doesn't publish it", name, port)
	addrHint := ""
	if a := s.C.Addrs(); len(a) > 0 {
		addrHint = fmt.Sprintf(" On Linux the host can also reach it directly at %s.", hostPort(a[0].String(), port))
	}
	f.Explanation = fmt.Sprintf("%s listens on port %d inside its container, but publishes no host port for it, so nothing on the host accepts %s.", containerLabel(s.C), port, target)
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
	f.Explanation = fmt.Sprintf("%s is a container (%s), and Docker's DNS answers its name only inside its networks. From the host's network namespace, reach a container through a port it publishes.", q.To.Host, containerLabel(m.C))
	if src, ok := v.Source(); ok {
		f.Supporting = append(f.Supporting, src.ID)
		f.Explanation = fmt.Sprintf("%s is a container (%s), and Docker's DNS answers its name only inside its networks. %s uses the host's network namespace (network_mode: host), so it resolves names the way the host does; reach the container through a port it publishes.",
			q.To.Host, containerLabel(m.C), src.C.DisplayName())
	}
	f.Supporting = ids(f.Supporting...)
	if b := m.C.PublishesPort(q.To.Port); len(b) > 0 {
		host := b[0].HostIP
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "localhost"
		}
		f.Fix = fmt.Sprintf("Connect to %s: %s publishes its port %d there.", hostPort(host, b[0].HostPort), name, q.To.Port)
	} else {
		f.Fix = fmt.Sprintf("Publish the port: ports: [\"%d:%d\"] for %s in Compose (-p %d:%d), then connect to localhost:%d.", q.To.Port, q.To.Port, name, q.To.Port, q.To.Port, q.To.Port)
	}
	return []Finding{f}
}

// confirm adds the refused or closed connects from the host to supporting IDs.
func (wr019) confirm(v evidence.View, base ...string) []string {
	out := slices.Clone(base)
	for _, t := range fromSource(v) {
		if t.P.Outcome == evidence.OutcomeRefused || t.P.Outcome == evidence.OutcomeClosed {
			out = append(out, t.ID)
		}
	}
	return ids(out...)
}

// hostAccepts reports a host listener that takes connections to the port at
// the address the target stands for.
func hostAccepts(l evidence.Listeners, port uint16, h evidence.HostTarget) bool {
	for _, s := range l.OnPort(port) {
		a := s.Local.Addr().Unmap()
		switch {
		case a.IsUnspecified():
			return true
		case h.Addr.IsValid() && a == h.Addr.Unmap():
			return true
		case !h.Addr.IsValid() && h.Via == evidence.HostViaLoopback && a.IsLoopback():
			return true
		}
	}
	return false
}
