package evidence

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DockerVersion is the daemon's identity and the negotiated API version.
type DockerVersion struct {
	Version       string `json:"version"`          // "29.9.3"
	APIVersion    string `json:"api_version"`      // the version whyreach talks
	DaemonMaxAPI  string `json:"daemon_api"`       // the newest the daemon supports
	Os            string `json:"os"`               // "linux"
	Arch          string `json:"arch"`             // "amd64"
	PlatformName  string `json:"platform"`         // "Docker Engine - Community"
	Endpoint      string `json:"endpoint"`         // "unix:///var/run/docker.sock"
	LinuxEngine   bool   `json:"linux_engine"`     // daemon and whyreach share a Linux kernel (not Docker Desktop)
	KernelVersion string `json:"kernel,omitempty"` // daemon's kernel
}

// Container states as Docker reports them.
const (
	StateRunning    = "running"
	StateRestarting = "restarting"
	StatePaused     = "paused"
	StateExited     = "exited"
	StateCreated    = "created"
	StateDead       = "dead"
	StateRemoving   = "removing"
)

// Container is the part of `docker inspect` whyreach uses. It never holds
// environment values or file contents (CLAUDE.md non-negotiable 6).
type Container struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"` // without the leading slash
	Image        string          `json:"image"`
	State        string          `json:"state"`            // running, exited, restarting, …
	Health       string          `json:"health,omitempty"` // starting, healthy, unhealthy; empty without a healthcheck
	ExitCode     int             `json:"exit_code"`
	Error        string          `json:"error,omitempty"` // the daemon's State.Error
	Pid          int             `json:"pid,omitempty"`
	StartedAt    time.Time       `json:"started_at"`
	FinishedAt   time.Time       `json:"finished_at"`
	RestartCount int             `json:"restart_count"`
	Compose      *ComposeRef     `json:"compose,omitempty"`
	NetworkMode  string          `json:"network_mode"`       // bridge, host, none, container:<id>, or a network name
	Networks     []NetAttachment `json:"networks,omitempty"` // sorted by network name
	Ports        []PortMap       `json:"ports,omitempty"`
	ExtraHosts   []string        `json:"extra_hosts,omitempty"`
	DNS          []string        `json:"dns,omitempty"`   // resolvers set on the container itself (Compose dns:, --dns)
	Links        []string        `json:"links,omitempty"` // legacy --link entries, which add /etc/hosts names
}

// ComposeRef is the Compose project and service, from the container's labels.
type ComposeRef struct {
	Project string `json:"project"`
	Service string `json:"service"`
}

// NetAttachment is one network a container is configured on. A stopped
// container keeps its attachments but has no addresses.
type NetAttachment struct {
	Network   string     `json:"network"`
	NetworkID string     `json:"network_id,omitempty"`
	IPv4      netip.Addr `json:"ipv4,omitzero"`
	IPv6      netip.Addr `json:"ipv6,omitzero"`
	Gateway   netip.Addr `json:"gateway,omitzero"`
	Names     []string   `json:"names,omitempty"` // names Docker's DNS answers for on this network (aliases and DNSNames), sorted
}

// PortMap is one published port: container port → host address.
type PortMap struct {
	ContainerPort uint16 `json:"container_port"`
	Proto         string `json:"proto"`
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port,omitempty"`
}

// PublishesPort returns the bindings that publish the container's port on
// the host, in the container's order.
func (c Container) PublishesPort(containerPort uint16) []PortMap {
	var out []PortMap
	for _, p := range c.Ports {
		if p.ContainerPort == containerPort && p.Proto == "tcp" && p.HostPort != 0 {
			out = append(out, p)
		}
	}
	return out
}

// PublishedAs returns the bindings that publish some container port as the
// host port hostPort.
func (c Container) PublishedAs(hostPort uint16) []PortMap {
	var out []PortMap
	for _, p := range c.Ports {
		if p.HostPort == hostPort && p.Proto == "tcp" {
			out = append(out, p)
		}
	}
	return out
}

// Covers reports whether a binding accepts connections to the host address
// addr: an empty or unspecified HostIP of the same family covers every
// address, a specific HostIP only itself.
func (p PortMap) Covers(addr netip.Addr) bool {
	addr = addr.Unmap()
	if p.HostIP == "" {
		return true
	}
	h, err := netip.ParseAddr(p.HostIP)
	if err != nil {
		return false
	}
	h = h.Unmap()
	if h.IsUnspecified() {
		return h.Is4() == addr.Is4()
	}
	return h == addr
}

// LoopbackOnly reports a binding on a loopback host address, which only
// the host itself can use.
func (p PortMap) LoopbackOnly() bool {
	h, err := netip.ParseAddr(p.HostIP)
	return err == nil && h.Unmap().IsLoopback()
}

// HostAddr is the binding's host side as host:port, "*" standing for every
// address.
func (p PortMap) HostAddr() string {
	ip := p.HostIP
	if ip == "" || ip == "0.0.0.0" {
		ip = "0.0.0.0"
	}
	if a, err := netip.ParseAddr(ip); err == nil && a.Is6() && !a.Is4In6() {
		return "[" + ip + "]:" + strconv.Itoa(int(p.HostPort))
	}
	return ip + ":" + strconv.Itoa(int(p.HostPort))
}

// DisplayName is the name users know the container by: its Compose service,
// or its container name.
func (c Container) DisplayName() string {
	if c.Compose != nil && c.Compose.Service != "" {
		return c.Compose.Service
	}
	return c.Name
}

// Running reports whether the container's processes run, so it has a
// network namespace that can be read or joined.
func (c Container) Running() bool { return c.State == StateRunning }

// NetnsOwner returns the container ID whose network namespace this container
// uses, for network_mode "container:<id>", and "" otherwise.
func (c Container) NetnsOwner() string {
	id, ok := strings.CutPrefix(c.NetworkMode, "container:")
	if !ok {
		return ""
	}
	return id
}

// HostNetwork reports network_mode "host".
func (c Container) HostNetwork() bool { return c.NetworkMode == "host" }

// Attachment returns the container's attachment to network, if any.
func (c Container) Attachment(network string) (NetAttachment, bool) {
	for _, a := range c.Networks {
		if a.Network == network {
			return a, true
		}
	}
	return NetAttachment{}, false
}

// NetworkNames lists the networks the container is configured on, sorted.
func (c Container) NetworkNames() []string {
	out := make([]string, 0, len(c.Networks))
	for _, a := range c.Networks {
		out = append(out, a.Network)
	}
	slices.Sort(out)
	return out
}

// Addrs lists the container's addresses on all its networks, sorted.
func (c Container) Addrs() []netip.Addr {
	var out []netip.Addr
	for _, a := range c.Networks {
		if a.IPv4.IsValid() {
			out = append(out, a.IPv4)
		}
		if a.IPv6.IsValid() {
			out = append(out, a.IPv6)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// Docker's predefined networks. The default bridge has no embedded DNS, and
// "host" and "none" are network modes rather than networks to share.
const (
	NetworkBridge = "bridge"
	NetworkHost   = "host"
	NetworkNone   = "none"
)

// UserDefined reports a network with Docker's embedded DNS: any network but
// the predefined bridge, host and none.
func UserDefined(network string) bool {
	return network != NetworkBridge && network != NetworkHost && network != NetworkNone
}

// UserDefinedNetworks lists the container's user-defined networks, sorted.
func (c Container) UserDefinedNetworks() []string {
	var out []string
	for _, n := range c.NetworkNames() {
		if UserDefined(n) {
			out = append(out, n)
		}
	}
	return out
}

// Matches reports whether name refers to this container: its container
// name, Compose service, or one of its aliases or DNSNames on any network.
// Matching ignores case and a trailing dot, as DNS does. Whether Docker's DNS
// actually answers the name is AnswersTo's question.
func (c Container) Matches(name string) bool {
	name = normalizeName(name)
	if name == "" {
		return false
	}
	if strings.EqualFold(c.Name, name) || (c.Compose != nil && strings.EqualFold(c.Compose.Service, name)) {
		return true
	}
	for _, a := range c.Networks {
		if slices.ContainsFunc(a.Names, func(n string) bool { return strings.EqualFold(n, name) }) {
			return true
		}
	}
	return false
}

// AnswersTo returns the networks on which Docker's embedded DNS answers name
// with this container: user-defined networks where name is its container
// name, Compose service, an alias or a DNSName. The default bridge network
// answers nothing.
func (c Container) AnswersTo(name string) []string {
	name = normalizeName(name)
	if name == "" {
		return nil
	}
	var out []string
	for _, a := range c.Networks {
		if UserDefined(a.Network) && c.answersOn(a, name) {
			out = append(out, a.Network)
		}
	}
	slices.Sort(out)
	return out
}

func (c Container) answersOn(a NetAttachment, name string) bool {
	if strings.EqualFold(c.Name, name) {
		return true
	}
	if c.Compose != nil && strings.EqualFold(c.Compose.Service, name) {
		return true
	}
	return slices.ContainsFunc(a.Names, func(n string) bool { return strings.EqualFold(n, name) })
}

// HostsEntry returns what the container's extra_hosts map name to, such as
// "192.168.1.50" or "host-gateway". The container's /etc/hosts answers such
// a name before any DNS, so it overrides every container with that name.
func (c Container) HostsEntry(name string) (string, bool) {
	name = normalizeName(name)
	for _, e := range c.ExtraHosts {
		// "host:ip" (an IPv6 ip contains colons too) or, from Docker 25, "host=ip"
		host, value, ok := strings.Cut(e, "=")
		if !ok {
			host, value, ok = strings.Cut(e, ":")
		}
		if ok && strings.EqualFold(strings.TrimSpace(host), name) {
			return strings.Trim(strings.TrimSpace(value), "[]"), true
		}
	}
	return "", false
}

func normalizeName(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }

// Listeners is the set of listening TCP sockets in one network namespace.
type Listeners struct {
	Sockets []Socket `json:"sockets"` // sorted by port, then address
}

// Socket is one listening socket.
type Socket struct {
	Proto string         `json:"proto"` // "tcp" or "tcp6": the /proc/net table it came from
	Local netip.AddrPort `json:"local"`
}

// DockerDNSAddr is where Docker's embedded DNS listens inside every container
// on a user-defined network (on a random TCP port). Listener rules ignore it.
var DockerDNSAddr = netip.AddrFrom4([4]byte{127, 0, 0, 11})

// IsDockerDNS reports Docker's embedded-DNS listener (ADR 0001).
func (s Socket) IsDockerDNS() bool { return s.Local.Addr().Unmap() == DockerDNSAddr }

// IsLoopback reports a socket that only accepts connections from its own
// network namespace: 127.0.0.0/8, ::1, or ::ffff:127.x.
func (s Socket) IsLoopback() bool { return s.Local.Addr().Unmap().IsLoopback() }

// OnPort returns the sockets listening on port, without Docker's DNS listener.
func (l Listeners) OnPort(port uint16) []Socket {
	var out []Socket
	for _, s := range l.Sockets {
		if s.Local.Port() == port && !s.IsDockerDNS() {
			out = append(out, s)
		}
	}
	return out
}

// AcceptsLoopback reports whether something in this netns accepts
// connections to localhost:port (a loopback or wildcard listener).
func (l Listeners) AcceptsLoopback(port uint16) bool {
	for _, s := range l.OnPort(port) {
		a := s.Local.Addr().Unmap()
		if a.IsLoopback() || a.IsUnspecified() {
			return true
		}
	}
	return false
}

// AcceptsRemote reports whether something in this netns accepts connections
// to port from other network namespaces: a listener that is not loopback-only.
func (l Listeners) AcceptsRemote(port uint16) bool {
	for _, s := range l.OnPort(port) {
		if !s.IsLoopback() {
			return true
		}
	}
	return false
}

// SortSockets orders sockets by port, then address, then table.
func SortSockets(s []Socket) {
	slices.SortFunc(s, func(a, b Socket) int {
		if c := int(a.Local.Port()) - int(b.Local.Port()); c != 0 {
			return c
		}
		if c := a.Local.Addr().Compare(b.Local.Addr()); c != 0 {
			return c
		}
		return strings.Compare(a.Proto, b.Proto)
	})
}

// DNS lookup paths and outcomes.
const (
	ViaHosts    = "hosts"    // answered from /etc/hosts
	ViaDNS      = "dns"      // answered by the resolver in resolv.conf
	ViaLiteral  = "literal"  // the target was an IP address
	ViaMetadata = "metadata" // the address came from Docker metadata, not from a lookup

	RcodeTimeout = "TIMEOUT" // no answer from the resolver in time
)

// DNSProbe is a name lookup as the source sees it: /etc/hosts first, then the
// resolver from resolv.conf (nsswitch order "files dns"). Search domains can
// identify the user's organisation, so they are recorded as "<search N>"
// placeholders, never by name.
type DNSProbe struct {
	Name     string       `json:"name"`               // the name asked for
	Answered string       `json:"answered,omitempty"` // the query that produced the answers: "api" or "api.<search 1>"
	Via      string       `json:"via,omitempty"`      // hosts or dns; empty when nothing answered
	Server   string       `json:"server,omitempty"`   // the resolver: "127.0.0.11:53"
	Rcode    string       `json:"rcode,omitempty"`    // of the first query: NOERROR, NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT
	Answers  []netip.Addr `json:"answers,omitempty"`  // unmapped: IPv4 first, then IPv6
	Upstream []string     `json:"upstream,omitempty"` // Docker's "# ExtServers:" comment in resolv.conf
	Attempts []DNSAttempt `json:"attempts,omitempty"` // each query sent, in order
}

// DNSAttempt is one query sent to the resolver.
type DNSAttempt struct {
	Query string `json:"query"` // "api" or "api.<search 1>"
	Type  string `json:"type"`  // A or AAAA
	Rcode string `json:"rcode"`
	N     int    `json:"answers"`
}

// TCP connect outcomes. Refused, timeout and unreachable are different
// results and are never merged (CLAUDE.md).
const (
	OutcomeConnected   = "connected"
	OutcomeRefused     = "refused"
	OutcomeTimeout     = "timeout"
	OutcomeUnreachable = "unreachable"
	OutcomeReset       = "reset"
	// OutcomeClosed is a connection the peer accepted and then closed at
	// once, before sending anything: typical of docker-proxy when the
	// published container's port refuses, and of servers that reject the
	// client right after accept. It does not count as reaching the service.
	OutcomeClosed  = "closed"
	OutcomeBlocked = "blocked" // whyreach's probe policy refused to send it
	OutcomeError   = "error"
)

// TCPProbe is one connect-then-close attempt to one address.
type TCPProbe struct {
	Target  string         `json:"target"`          // as asked: "api:8080"
	Addr    netip.AddrPort `json:"addr"`            // the address dialed
	Via     string         `json:"via"`             // how Addr was obtained: literal, hosts, dns, metadata
	Outcome string         `json:"outcome"`         // connected, refused, timeout, unreachable, reset, blocked, error
	Errno   string         `json:"errno,omitempty"` // ECONNREFUSED, EHOSTUNREACH, …
	Error   string         `json:"error,omitempty"`
	RTT     time.Duration  `json:"rtt_ns"`
}

// HostAddrs is the host's network interfaces that have addresses, as
// whyreach's own network namespace sees them (the host's when whyreach runs
// natively).
type HostAddrs struct {
	Interfaces []Interface `json:"interfaces"` // sorted by name
}

// Interface is one network interface and its addresses.
type Interface struct {
	Name  string         `json:"name"`
	Up    bool           `json:"up"`
	MTU   int            `json:"mtu,omitempty"`
	Addrs []netip.Prefix `json:"addrs"`
}

// DefaultBridge is the interface of Docker's default bridge network, whose
// address Docker's host-gateway stands for unless the daemon sets another.
const DefaultBridge = "docker0"

// Owner returns the interface that holds addr.
func (h HostAddrs) Owner(addr netip.Addr) (Interface, bool) {
	addr = addr.Unmap()
	for _, i := range h.Interfaces {
		for _, p := range i.Addrs {
			if p.Addr().Unmap() == addr {
				return i, true
			}
		}
	}
	return Interface{}, false
}

// Interface returns the interface with a name.
func (h HostAddrs) Interface(name string) (Interface, bool) {
	for _, i := range h.Interfaces {
		if i.Name == name {
			return i, true
		}
	}
	return Interface{}, false
}

// IPv4 is the interface's first IPv4 address.
func (i Interface) IPv4() (netip.Addr, bool) {
	for _, p := range i.Addrs {
		if p.Addr().Unmap().Is4() {
			return p.Addr().Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// ByName reports whether the address came from resolving the target the way
// the app would (or was given literally), as opposed to Docker metadata.
// Only such probes decide whether the problem reproduced.
func (t TCPProbe) ByName() bool { return t.Via != ViaMetadata }
