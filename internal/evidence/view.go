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

// UnreadContainerListeners reports a running container whose listening
// sockets whyreach tried and failed to read (or left unread at a bound):
// "nothing listens" then holds only for the sockets it did read.
func (v View) UnreadContainerListeners() bool {
	for _, e := range v.items {
		if e.Kind != KindListeners || e.Context.Kind != ContextContainer || e.OK() {
			continue
		}
		if e.Status == StatusSkipped && e.Err != nil && e.Err.Code == CodeNotFound {
			continue // a stopped container: it has no sockets
		}
		return true
	}
	return false
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

// HostRouteEv is a host.route observation with its record ID.
type HostRouteEv struct {
	ID string
	R  HostRoute
}

// HostRoutes returns the host's route lookups, in ID order.
func (v View) HostRoutes() []HostRouteEv {
	var out []HostRouteEv
	for _, e := range v.items {
		if r, ok := e.Data.(HostRoute); ok && e.Kind == KindHostRoute && e.OK() {
			out = append(out, HostRouteEv{ID: e.ID, R: r})
		}
	}
	return out
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
	// only, whose name resolves nowhere, and for a published match.
	Networks []string
	// Shared are the networks of any kind, the default bridge included, that
	// it and the source's netns are both attached to. For a container in
	// network_mode container:X, X's networks count.
	Shared []string
	// Port is the port the connection arrives on inside the container: the
	// target's port, or for a published match the container port that the
	// host port forwards to.
	Port uint16
	// Published is the binding the connection goes through when the target
	// is a host address and port that the container publishes.
	Published *PortMap
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
	// Host is set when the target is the host's network namespace (see
	// View.HostTarget); Published then lists the containers whose published
	// ports the connection reaches there.
	Host      *HostTarget
	Published []Match
}

// All returns the matches on the source's networks, or else the others, or
// else the containers reached through a published port.
func (d Destinations) All() []Match {
	switch {
	case len(d.OnSourceNets) > 0:
		return d.OnSourceNets
	case len(d.Elsewhere) > 0:
		return d.Elsewhere
	default:
		return d.Published
	}
}

// Destinations resolves the target against the observed containers: a name
// target matches container names, Compose services, aliases and DNSNames
// (unless the source's extra_hosts map the name), and an IP target matches
// the container that holds the address. A target that is the host (see
// HostTarget) matches the containers that publish the port there. Any other
// loopback target refers to the source itself, so it has no destinations.
// Matches are ordered with the source's Compose project first, then by
// container name.
func (v View) Destinations() Destinations {
	t := v.q.To
	var d Destinations
	owner, haveOwner := v.NetnsOwner()
	if t.Class == TargetName && haveOwner {
		d.HostsEntry, _ = owner.C.HostsEntry(t.Host)
	}
	if ht, ok := v.HostTarget(); ok {
		d.Host = &ht
		d.Published = v.publishedMatches(ht)
		return d
	}
	if t.Class == TargetLoopback {
		return d
	}
	srcNets := map[string]bool{}
	if haveOwner && !owner.C.HostNetwork() {
		for _, n := range owner.C.NetworkNames() {
			if n != NetworkNone {
				srcNets[n] = true
			}
		}
	}
	addr := t.Addr
	if d.HostsEntry != "" {
		a, err := netip.ParseAddr(d.HostsEntry)
		if err != nil {
			return d // host-gateway: the name means the host, not a container
		}
		addr = a.Unmap()
	}
	srcProject := ""
	if src, ok := v.Source(); ok && src.C.Compose != nil {
		srcProject = src.C.Compose.Project
	}
	// A connection to an address goes to the container that holds it,
	// running or paused. Only when none does is it a stopped container's
	// address, its fixed one (or the one Docker shows for a created
	// container), which it would hold if it ran (WR008). Docker hands a
	// stopped container's fixed address to other containers, so one that
	// is up takes precedence; a dynamic address isn't kept at all.
	held := addr.IsValid() && slices.ContainsFunc(v.Containers(), func(c ContainerEv) bool {
		return c.C.Up() && len(holdsAddr(c.C, addr, false)) > 0
	})
	for _, c := range v.Containers() {
		m := Match{Port: t.Port}
		switch {
		case addr.IsValid():
			switch {
			case c.C.Up():
				m.Networks = holdsAddr(c.C, addr, false)
			case !held:
				m.Networks = holdsAddr(c.C, addr, true)
			}
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

// publishedMatches lists the containers that publish the target port on the
// host address ht stands for, in container-name order.
func (v View) publishedMatches(ht HostTarget) []Match {
	port := v.q.To.Port
	var out []Match
	for _, c := range v.Containers() {
		for _, pm := range c.C.PublishedAs(port) {
			if !ht.coveredBy(pm) {
				continue
			}
			out = append(out, Match{ContainerEv: c, Port: pm.ContainerPort, Published: &pm})
			break
		}
	}
	slices.SortFunc(out, func(a, b Match) int {
		return cmp.Or(strings.Compare(a.C.Name, b.C.Name), strings.Compare(a.C.ID, b.C.ID))
	})
	return out
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

// holdsAddr lists the networks where c shows addr as its address, or with
// fixed also as its fixed address.
func holdsAddr(c Container, addr netip.Addr, fixed bool) []string {
	var out []string
	for _, a := range c.Networks {
		if a.IPv4 == addr || a.IPv6 == addr || (fixed && (a.FixedIPv4 == addr || a.FixedIPv6 == addr)) {
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

// HostAddrsEv is a host.addrs observation with its record ID.
type HostAddrsEv struct {
	ID string
	H  HostAddrs
}

// PlatformEv is the platform record with its ID.
type PlatformEv struct {
	ID string
	P  Platform
}

// Platform returns where whyreach and Docker's containers run, when the
// engine recorded it.
func (v View) Platform() (PlatformEv, bool) {
	for _, e := range v.items {
		if p, ok := e.Data.(Platform); ok && e.Kind == KindPlatform && e.OK() {
			return PlatformEv{ID: e.ID, P: p}, true
		}
	}
	return PlatformEv{}, false
}

// HostLabel names whyreach's host-side network namespace in prose: "the
// host", or under WSL2 "the WSL2 VM" (INITIAL.md §3.7).
func (v View) HostLabel() string {
	p, _ := v.Platform()
	return p.P.HostLabel()
}

// HostAddrs returns the observed host interfaces.
func (v View) HostAddrs() (HostAddrsEv, bool) {
	for _, e := range v.items {
		if h, ok := e.Data.(HostAddrs); ok && e.Kind == KindHostAddrs && e.OK() {
			return HostAddrsEv{ID: e.ID, H: h}, true
		}
	}
	return HostAddrsEv{}, false
}

// HostDockerInternal is the name Docker Desktop gives the host. On Docker
// Engine a container has it only through extra_hosts (host-gateway).
const HostDockerInternal = "host.docker.internal"

// IsHostDockerInternal reports the name host.docker.internal.
func IsHostDockerInternal(name string) bool { return NormalizeName(name) == HostDockerInternal }

// How a target can refer to the host's network namespace.
const (
	HostViaLoopback = "loopback"     // localhost, from the host itself or a host-network container
	HostViaAddress  = "address"      // one of the host's own addresses
	HostViaGateway  = "host-gateway" // a name the source's extra_hosts map to Docker's host-gateway
	HostViaName     = "name"         // host.docker.internal without a mapping: the host by convention
)

// HostTarget is how the target refers to the host.
type HostTarget struct {
	Via      string
	Addr     netip.Addr   // the host address the connection goes to, when known
	Resolved []netip.Addr // for a loopback name: what it resolved to in the source, when looked up
	Iface    string       // the host interface holding Addr, when known
	Evidence []string     // the records that show it
}

// Addresses lists the host addresses the target stands for: Addr, or for
// a loopback name what it resolved to ("localhost" is often 127.0.0.1
// alone), or else both loopback addresses. Empty when unknown.
func (h HostTarget) Addresses() []netip.Addr {
	switch {
	case h.Addr.IsValid():
		return []netip.Addr{h.Addr.Unmap()}
	case len(h.Resolved) > 0:
		return h.Resolved
	case h.Via == HostViaLoopback:
		return []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}
	default:
		return nil
	}
}

// coveredBy reports whether a port binding accepts connections to the host
// address the target stands for.
func (h HostTarget) coveredBy(pm PortMap) bool {
	for _, a := range h.Addresses() {
		if pm.Covers(a) {
			return true
		}
	}
	return false
}

// HostSource reports a source that runs in the host's network namespace:
// the host itself, or a container with network_mode host.
func (v View) HostSource() bool {
	if v.q.From.Kind == SourceHost {
		return true
	}
	owner, ok := v.NetnsOwner()
	return ok && owner.C.HostNetwork()
}

// HostTarget reports whether the target is the host's network namespace,
// and how: localhost from the host itself, one of the host's addresses, a
// name that extra_hosts map to host-gateway, host.docker.internal, or a name
// that resolved from the source to a host address.
func (v View) HostTarget() (HostTarget, bool) {
	t := v.q.To
	ha, haveAddrs := v.HostAddrs()
	owned := func(a netip.Addr, ids ...string) (HostTarget, bool) {
		a = a.Unmap()
		if !haveAddrs || a.IsLoopback() {
			return HostTarget{}, false
		}
		if i, ok := ha.H.Owner(a); ok {
			return HostTarget{Via: HostViaAddress, Addr: a, Iface: i.Name, Evidence: append([]string{ha.ID}, ids...)}, true
		}
		return HostTarget{}, false
	}
	if v.HostSource() {
		switch {
		case t.Class == TargetLoopback:
			ht := HostTarget{Via: HostViaLoopback, Addr: t.Addr}
			if d, ok := v.SourceDNS(t.Host); ok && !t.Addr.IsValid() {
				for _, a := range d.P.Answers {
					if a.Unmap().IsLoopback() {
						ht.Resolved = append(ht.Resolved, a.Unmap())
					}
				}
				if len(ht.Resolved) > 0 {
					ht.Evidence = append(ht.Evidence, d.ID)
				}
			}
			return ht, true
		case t.Addr.IsValid():
			return owned(t.Addr)
		}
		// A name: a container name doesn't resolve on the host, so a name
		// that matches a container is about that container.
		for _, c := range v.Containers() {
			if c.C.Matches(t.Host) {
				return HostTarget{}, false
			}
		}
		if d, ok := v.SourceDNS(t.Host); ok {
			for _, a := range d.P.Answers {
				if a.IsLoopback() {
					return HostTarget{Via: HostViaLoopback, Addr: a, Evidence: []string{d.ID}}, true
				}
				if ht, ok := owned(a, d.ID); ok {
					return ht, true
				}
			}
		}
		return HostTarget{}, false
	}
	owner, ok := v.NetnsOwner()
	if !ok {
		return HostTarget{}, false
	}
	switch t.Class {
	case TargetLoopback:
		return HostTarget{}, false
	case TargetIP:
		return owned(t.Addr)
	}
	if entry, ok := owner.C.HostsEntry(t.Host); ok {
		a, err := netip.ParseAddr(entry)
		if err == nil {
			return owned(a, owner.ID)
		}
		if !strings.EqualFold(entry, "host-gateway") {
			return HostTarget{}, false
		}
		ht := HostTarget{Via: HostViaGateway, Evidence: []string{owner.ID}}
		if d, ok := v.SourceDNS(t.Host); ok && len(d.P.Answers) > 0 {
			ht.Addr = d.P.Answers[0]
			ht.Evidence = append(ht.Evidence, d.ID)
		} else if haveAddrs {
			if i, ok := ha.H.Interface(DefaultBridge); ok {
				ht.Addr, _ = i.IPv4()
			}
		}
		if haveAddrs && ht.Addr.IsValid() {
			if i, ok := ha.H.Owner(ht.Addr); ok {
				ht.Iface = i.Name
				ht.Evidence = append(ht.Evidence, ha.ID)
			}
		}
		return ht, true
	}
	if IsHostDockerInternal(t.Host) {
		return HostTarget{Via: HostViaName}, true
	}
	if d, ok := v.SourceDNS(t.Host); ok {
		for _, a := range d.P.Answers {
			if ht, ok := owned(a, d.ID); ok {
				return ht, true
			}
		}
	}
	return HostTarget{}, false
}

// InSource reports whether a check ran in the source's network namespace,
// as recorded under the source's context.
func (v View) InSource(c ContextRef) bool {
	if v.q.From.Kind == SourceHost {
		return c.Kind == ContextHost
	}
	return c.Kind == ContextContainer && c.Container == ShortID(v.q.From.ContainerID)
}

// HostControl returns whyreach's own connect from the host's network
// namespace to addr, made for comparison when a container's connect to that
// host address failed (WR021), if it was made.
func (v View) HostControl(addr netip.AddrPort) (TCPEv, bool) {
	for _, t := range v.TCP() {
		if t.Context.Kind == ContextHost && t.P.Via == ViaControl && t.P.Addr == addr {
			return t, true
		}
	}
	return TCPEv{}, false
}

// HostHolds reports an address of the host's own: on one of its
// interfaces, or, when those weren't read, one the target stands for.
func (v View) HostHolds(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() {
		return false
	}
	if ha, ok := v.HostAddrs(); ok {
		_, owned := ha.H.Owner(a)
		return owned
	}
	if ht, ok := v.HostTarget(); ok {
		return slices.Contains(ht.Addresses(), a)
	}
	return false
}

// SourceTCP returns the TCP connects that ran in the source's netns.
func (v View) SourceTCP() []TCPEv {
	var out []TCPEv
	for _, t := range v.TCP() {
		if v.InSource(t.Context) {
			out = append(out, t)
		}
	}
	return out
}

// SourceDNS returns the source's lookup of name, if one ran.
func (v View) SourceDNS(name string) (DNSEv, bool) {
	for _, d := range v.DNS() {
		if strings.EqualFold(d.P.Name, name) && v.InSource(d.Context) {
			return d, true
		}
	}
	return DNSEv{}, false
}

// Incomplete reports container metadata that could not be read, or that
// whyreach skipped at one of its bounds: claims that no container has some
// name can't be made then.
func (v View) Incomplete() bool {
	for _, e := range v.items {
		if e.Kind == KindContainer && !e.OK() {
			return true
		}
	}
	return false
}
