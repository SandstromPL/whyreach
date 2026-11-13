package evidence

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
)

// View is the read-only evidence a rule evaluates, plus the question. All
// queries are pure and return results in a deterministic order.
type View struct {
	q     Question
	items []Evidence
}

// NewView builds a view over items, which must already carry their IDs.
func NewView(q Question, items []Evidence) View {
	return View{q: q, items: slices.Clone(items)}
}

// Question is what the user asked.
func (v View) Question() Question { return v.q }

// Items returns every record, in ID order.
func (v View) Items() []Evidence { return slices.Clone(v.items) }

// Get returns the record with the given ID.
func (v View) Get(id string) (Evidence, bool) {
	for _, e := range v.items {
		if e.ID == id {
			return e, true
		}
	}
	return Evidence{}, false
}

// Of returns every record of a kind, whatever its status.
func (v View) Of(k Kind) []Evidence {
	var out []Evidence
	for _, e := range v.items {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// Has reports whether at least one record of the kind holds an observation.
func (v View) Has(k Kind) bool {
	for _, e := range v.items {
		if e.Kind == k && e.OK() {
			return true
		}
	}
	return false
}

// ContainerEv is a docker.container observation with its record ID.
type ContainerEv struct {
	ID string
	C  Container
}

// Containers returns every observed container, in ID order.
func (v View) Containers() []ContainerEv {
	var out []ContainerEv
	for _, e := range v.items {
		if c, ok := e.Data.(Container); ok && e.Kind == KindContainer && e.OK() {
			out = append(out, ContainerEv{ID: e.ID, C: c})
		}
	}
	return out
}

// Container returns the observed container with a reference: its full ID, an
// ID prefix of at least 12 characters, or its name.
func (v View) Container(ref string) (ContainerEv, bool) {
	ref = strings.TrimPrefix(ref, "/")
	if ref == "" {
		return ContainerEv{}, false
	}
	for _, c := range v.Containers() {
		if c.C.ID == ref || c.C.Name == ref || (len(ref) >= 12 && strings.HasPrefix(c.C.ID, ref)) {
			return c, true
		}
	}
	return ContainerEv{}, false
}

// Source returns the source container, when the source is a container.
func (v View) Source() (ContainerEv, bool) {
	if v.q.From.Kind != SourceContainer {
		return ContainerEv{}, false
	}
	return v.Container(v.q.From.ContainerID)
}

// NetnsOwner returns the container whose network namespace the source uses:
// the source itself, or X for network_mode "container:X".
func (v View) NetnsOwner() (ContainerEv, bool) {
	src, ok := v.Source()
	if !ok {
		return ContainerEv{}, false
	}
	if owner := src.C.NetnsOwner(); owner != "" {
		return v.Container(owner)
	}
	return src, true
}

// ListenersEv is a netns.listeners observation with its record ID.
type ListenersEv struct {
	ID      string
	Context ContextRef
	L       Listeners
}

// ListenersIn returns the listeners observed in a container's network
// namespace (by full or short ID).
func (v View) ListenersIn(containerID string) (ListenersEv, bool) {
	short := ShortID(containerID)
	for _, e := range v.items {
		l, ok := e.Data.(Listeners)
		if ok && e.Kind == KindListeners && e.OK() && e.Context.Kind == ContextContainer && e.Context.Container == short {
			return ListenersEv{ID: e.ID, Context: e.Context, L: l}, true
		}
	}
	return ListenersEv{}, false
}

// HostListeners returns the listeners observed in the host's network namespace.
func (v View) HostListeners() (ListenersEv, bool) {
	for _, e := range v.items {
		l, ok := e.Data.(Listeners)
		if ok && e.Kind == KindListeners && e.OK() && e.Context.Kind == ContextHost {
			return ListenersEv{ID: e.ID, Context: e.Context, L: l}, true
		}
	}
	return ListenersEv{}, false
}

// TCPEv is a probe.tcp observation with its record ID.
type TCPEv struct {
	ID      string
	Context ContextRef
	P       TCPProbe
}

// TCP returns the TCP connect observations, in ID order.
func (v View) TCP() []TCPEv {
	var out []TCPEv
	for _, e := range v.items {
		if p, ok := e.Data.(TCPProbe); ok && e.Kind == KindTCP && e.OK() {
			out = append(out, TCPEv{ID: e.ID, Context: e.Context, P: p})
		}
	}
	return out
}

// DNSEv is a probe.dns observation with its record ID.
type DNSEv struct {
	ID      string
	Context ContextRef
	P       DNSProbe
}

// DNS returns the name lookup observations, in ID order.
func (v View) DNS() []DNSEv {
	var out []DNSEv
	for _, e := range v.items {
		if p, ok := e.Data.(DNSProbe); ok && e.Kind == KindDNS && e.OK() {
			out = append(out, DNSEv{ID: e.ID, Context: e.Context, P: p})
		}
	}
	return out
}

// Match is a container that the target refers to in Docker metadata.
type Match struct {
	ContainerEv
	// Networks are where the target applies to it: the user-defined networks
	// where Docker's DNS answers the target name, or the networks where it
	// holds the target address. Empty for a container on the default bridge
	// only, whose name resolves nowhere.
	Networks []string
	// Shared are the networks of any kind, the default bridge included, that
	// it and the source's netns are both attached to. For a container in
	// network_mode container:X, X's networks count.
	Shared []string
}

// Destinations is what the target refers to in Docker metadata, as seen
// from the source.
type Destinations struct {
	OnSourceNets []Match // share a network with the source
	Elsewhere    []Match // match the target, but share no network with the source
	// HostsEntry is set when the source's own extra_hosts map the target name
	// ("192.168.1.50", "host-gateway"). /etc/hosts answers before any DNS, so
	// only a container holding that address is a destination.
	HostsEntry string
}

// All returns the matches on the source's networks, or else the others.
func (d Destinations) All() []Match {
	if len(d.OnSourceNets) > 0 {
		return d.OnSourceNets
	}
	return d.Elsewhere
}

// Destinations resolves the target against the observed containers: a name
// target matches container names, Compose services, aliases and DNSNames
// (unless the source's extra_hosts map the name), and an IP target matches
// the container that holds the address. A loopback target refers to the
// source itself, so it has no destinations. Matches are ordered with the
// source's Compose project first, then by container name.
func (v View) Destinations() Destinations {
	t := v.q.To
	var d Destinations
	if t.Class == TargetLoopback {
		return d
	}
	owner, haveOwner := v.NetnsOwner()
	srcNets := map[string]bool{}
	if haveOwner && !owner.C.HostNetwork() {
		for _, n := range owner.C.NetworkNames() {
			if n != NetworkNone {
				srcNets[n] = true
			}
		}
	}
	addr := t.Addr
	if t.Class == TargetName && haveOwner {
		if entry, ok := owner.C.HostsEntry(t.Host); ok {
			d.HostsEntry = entry
			a, err := netip.ParseAddr(entry)
			if err != nil {
				return d // host-gateway: the name means the host, not a container
			}
			addr = a.Unmap()
		}
	}
	srcProject := ""
	if src, ok := v.Source(); ok && src.C.Compose != nil {
		srcProject = src.C.Compose.Project
	}
	for _, c := range v.Containers() {
		var m Match
		switch {
		case addr.IsValid():
			m.Networks = holdsAddr(c.C, addr)
			if len(m.Networks) == 0 {
				continue
			}
			m.Shared = intersect(m.Networks, srcNets)
		case c.C.Matches(t.Host):
			m.Networks = c.C.AnswersTo(t.Host)
			m.Shared = intersect(v.networksOf(c.C), srcNets)
		default:
			continue
		}
		m.ContainerEv = c
		if len(m.Shared) > 0 {
			d.OnSourceNets = append(d.OnSourceNets, m)
		} else {
			d.Elsewhere = append(d.Elsewhere, m)
		}
	}
	order := func(a, b Match) int {
		return cmp.Or(
			cmp.Compare(otherProject(a.C, srcProject), otherProject(b.C, srcProject)),
			strings.Compare(a.C.Name, b.C.Name),
			strings.Compare(a.C.ID, b.C.ID),
		)
	}
	slices.SortFunc(d.OnSourceNets, order)
	slices.SortFunc(d.Elsewhere, order)
	return d
}

// networksOf lists the networks a container is reachable on: its own, or,
// in network_mode container:X, X's (when X was observed).
func (v View) networksOf(c Container) []string {
	if owner := c.NetnsOwner(); owner != "" {
		if o, ok := v.Container(owner); ok {
			return o.C.NetworkNames()
		}
		return nil
	}
	return c.NetworkNames()
}

func intersect(nets []string, set map[string]bool) []string {
	var out []string
	for _, n := range nets {
		if set[n] {
			out = append(out, n)
		}
	}
	return out
}

func holdsAddr(c Container, addr netip.Addr) []string {
	var out []string
	for _, a := range c.Networks {
		if a.IPv4 == addr || a.IPv6 == addr {
			out = append(out, a.Network)
		}
	}
	slices.Sort(out)
	return out
}

func otherProject(c Container, project string) int {
	if project != "" && c.Compose != nil && c.Compose.Project == project {
		return 0
	}
	return 1
}
