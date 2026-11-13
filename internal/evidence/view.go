package evidence

import (
	"cmp"
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

// Container returns the observed container with a full or short ID.
func (v View) Container(id string) (ContainerEv, bool) {
	if id == "" {
		return ContainerEv{}, false
	}
	for _, c := range v.Containers() {
		if c.C.ID == id || ShortID(c.C.ID) == id {
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
	Networks []string // networks where it answers to the target name or holds the target address
	Shared   []string // the subset the source is attached to
}

// Destinations is what the target refers to in Docker metadata, as seen
// from the source.
type Destinations struct {
	OnSourceNets []Match // reachable by name or address on a network the source is on
	Elsewhere    []Match // match the target, but only on networks the source is not on
}

// All returns the matches on the source's networks, or else the others.
func (d Destinations) All() []Match {
	if len(d.OnSourceNets) > 0 {
		return d.OnSourceNets
	}
	return d.Elsewhere
}

// Destinations resolves the target against the observed containers: by name
// (container name, Compose service, alias, DNSNames) for a name target, by
// address for an IP target. A loopback target refers to the source itself, so
// it has no destinations. Matches are ordered with the source's Compose
// project first, then by container name.
func (v View) Destinations() Destinations {
	t := v.q.To
	if t.Class == TargetLoopback {
		return Destinations{}
	}
	srcNets := map[string]bool{}
	srcProject := ""
	if owner, ok := v.NetnsOwner(); ok && !owner.C.HostNetwork() {
		for _, n := range owner.C.NetworkNames() {
			srcNets[n] = true
		}
	}
	if src, ok := v.Source(); ok && src.C.Compose != nil {
		srcProject = src.C.Compose.Project
	}
	var d Destinations
	for _, c := range v.Containers() {
		var nets []string
		switch t.Class {
		case TargetName:
			nets = c.C.AnswersTo(t.Host)
		case TargetIP:
			nets = holdsAddr(c.C, t)
		}
		if len(nets) == 0 {
			continue
		}
		m := Match{ContainerEv: c, Networks: nets}
		for _, n := range nets {
			if srcNets[n] {
				m.Shared = append(m.Shared, n)
			}
		}
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

func holdsAddr(c Container, t Target) []string {
	var out []string
	for _, a := range c.Networks {
		if a.IPv4 == t.Addr || a.IPv6 == t.Addr {
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
