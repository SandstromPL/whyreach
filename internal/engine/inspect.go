package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/target"
)

// Bounds on what an inspection lists, so its output stays compact.
const (
	maxInspectContainers = 40
	maxInspectListeners  = 40
	maxInspectMembers    = 64
)

// Inspection is a compact set of facts about the host, one container or
// one Docker network (the inspect_environment tool). It holds no raw dumps.
type Inspection struct {
	Scope     string          `json:"scope"`
	Summary   string          `json:"summary"`
	Host      *HostFacts      `json:"host,omitempty"`
	Container *ContainerFacts `json:"container,omitempty"`
	Network   *NetworkFacts   `json:"network,omitempty"`
	Gaps      []Gap           `json:"gaps"`
}

// HostFacts describe the machine whyreach runs on.
type HostFacts struct {
	Docker      *DockerFacts     `json:"docker,omitempty"`
	Permissions *PermissionFacts `json:"permissions,omitempty"` // filled in by the policy package
	Interfaces  []IfaceFacts     `json:"interfaces"`
	Listening   []string         `json:"listening"` // the host's TCP listeners, by port
	Containers  []ContainerBrief `json:"containers"`
	Omitted     int              `json:"omitted,omitempty"` // containers or listeners left out to keep this short
}

// DockerFacts describe the daemon.
type DockerFacts struct {
	Endpoint    string `json:"endpoint"`
	Version     string `json:"version"`
	API         string `json:"api"`
	Platform    string `json:"platform"`
	LinuxEngine bool   `json:"linux_engine"` // containers share whyreach's kernel: /proc reads work
}

// PermissionFacts are the tiers in effect (INITIAL.md §4.9).
type PermissionFacts struct {
	Docker          bool     `json:"docker"`
	ProbeContainers string   `json:"probe_containers"` // "on (config)", "on (approved for this session)" or "off"
	Netns           string   `json:"netns"`            // "on (root)": container checks enter the containers' network namespaces, with no Docker write; or "off"
	Root            bool     `json:"root"`
	Allow           []string `json:"probe_allow,omitempty"`
	RatePerMinute   int      `json:"probes_per_minute"`
	// OutsideNames says which names with a dot that Docker doesn't know are
	// looked up: any (the CLI), or only with the user's approval (MCP),
	// except under the [probe] names domains (INITIAL.md §10 Q11).
	OutsideNames string `json:"outside_names"`
}

// IfaceFacts is one host interface.
type IfaceFacts struct {
	Name    string   `json:"name"`
	Network string   `json:"docker_network,omitempty"` // the Docker network whose bridge this is
	Addrs   []string `json:"addrs"`
	Down    bool     `json:"down,omitempty"`
}

// ContainerBrief is one line of the host's container list.
type ContainerBrief struct {
	Name      string   `json:"name"`
	Service   string   `json:"service,omitempty"` // service@project
	State     string   `json:"state"`
	Networks  []string `json:"networks,omitempty"`
	Published []string `json:"published,omitempty"` // "0.0.0.0:18080->8080"
}

// ContainerFacts describe one container's networking.
type ContainerFacts struct {
	Name         string     `json:"name"`
	ID           string     `json:"id"`
	Service      string     `json:"service,omitempty"`
	Image        string     `json:"image"`
	State        string     `json:"state"`
	Health       string     `json:"health,omitempty"`
	ExitCode     int        `json:"exit_code,omitempty"`
	RestartCount int        `json:"restart_count,omitempty"`
	StartedAt    time.Time  `json:"started_at,omitzero"`
	NetworkMode  string     `json:"network_mode"`
	NetnsOwner   string     `json:"netns_of,omitempty"` // for network_mode container:X
	Networks     []NetFacts `json:"networks,omitempty"`
	Published    []string   `json:"published,omitempty"`
	ExtraHosts   []string   `json:"extra_hosts,omitempty"`
	DNS          []string   `json:"dns,omitempty"`
	Listening    []string   `json:"listening,omitempty"` // in its network namespace; Docker's DNS listener left out
}

// NetFacts is one network attachment.
type NetFacts struct {
	Network string   `json:"network"`
	IPv4    string   `json:"ipv4,omitempty"`
	IPv6    string   `json:"ipv6,omitempty"`
	Names   []string `json:"names,omitempty"` // what Docker's DNS answers for it here
}

// NetworkFacts describe one Docker network.
type NetworkFacts struct {
	Name     string   `json:"name"`
	ID       string   `json:"id"`
	Driver   string   `json:"driver"`
	Internal bool     `json:"internal,omitempty"`
	Compose  string   `json:"compose_project,omitempty"`
	Subnets  []string `json:"subnets,omitempty"`
	Gateways []string `json:"gateways,omitempty"`
	DNS      bool     `json:"name_resolution"` // Docker's embedded DNS answers container names here
	Members  []string `json:"members"`         // "shop-api-1 172.22.0.3"
	Omitted  int      `json:"omitted,omitempty"`
}

// Inspect collects compact facts about a scope. It returns an error only
// for a scope that can't be inspected at all: an unknown container or
// network, or no Docker API for a container or network scope.
func (e *Engine) Inspect(ctx context.Context, scope target.Scope) (*Inspection, error) {
	ctx, cancel := context.WithTimeout(ctx, e.d.Deadline)
	defer cancel()
	in := &Inspection{Scope: scope.String(), Gaps: []Gap{}}
	switch scope.Kind {
	case target.ScopeHost:
		e.inspectHost(ctx, in)
	case target.ScopeNetwork:
		if err := e.inspectNetwork(ctx, scope.Name, in); err != nil {
			return nil, err
		}
	default:
		if err := e.inspectContainer(ctx, scope, in); err != nil {
			return nil, err
		}
	}
	return in, nil
}

func (e *Engine) inspectHost(ctx context.Context, in *Inspection) {
	h := &HostFacts{Interfaces: []IfaceFacts{}, Listening: []string{}, Containers: []ContainerBrief{}}
	in.Host = h
	r := &run{e: e, docker: e.d.Docker, timing: map[string]time.Duration{}}
	bridges := map[string]string{} // interface → network
	if r.docker == nil {
		r.dockerGap(e.d.DockerErr)
	} else if v, err := negotiate(ctx, r.docker); err != nil {
		r.dockerGap(err)
		r.docker = nil
	} else {
		h.Docker = &DockerFacts{
			Endpoint: r.docker.Endpoint(), Version: v.Version, API: r.docker.APIVersion(), Platform: v.Platform.Name,
			LinuxEngine: runtime.GOOS == "linux" && v.Os == "linux" && !v.Desktop(),
		}
		lctx, lcancel := context.WithTimeout(ctx, dockerTimeout)
		nets, err := r.docker.ListNetworks(lctx)
		lcancel()
		if err != nil {
			r.gaps = append(r.gaps, Gap{What: "Docker networks", Why: "failed", Detail: err.Error()})
		}
		for _, n := range nets {
			if n.Driver != "bridge" {
				continue
			}
			if n.Name == evidence.NetworkBridge {
				bridges[evidence.DefaultBridge] = n.Name
			} else {
				bridges["br-"+evidence.ShortID(n.ID)] = n.Name
			}
		}
		cctx, ccancel := context.WithTimeout(ctx, dockerTimeout)
		list, err := r.docker.ListContainers(cctx, true)
		ccancel()
		if err != nil {
			r.gaps = append(r.gaps, Gap{What: "the list of containers", Why: "failed", Detail: err.Error()})
		}
		for i, s := range list {
			if i == maxInspectContainers {
				h.Omitted += len(list) - i
				break
			}
			h.Containers = append(h.Containers, brief(s))
		}
	}
	if e.d.Interfaces == nil {
		r.gaps = append(r.gaps, Gap{What: "host interfaces", Why: "unsupported", Detail: "no interface reader on this platform"})
	} else if addrs, err := e.d.Interfaces(); err != nil {
		r.gaps = append(r.gaps, Gap{What: "host interfaces", Why: "failed", Detail: err.Error()})
	} else {
		for _, i := range addrs.Interfaces {
			f := IfaceFacts{Name: i.Name, Network: bridges[i.Name], Down: !i.Up}
			for _, a := range i.Addrs {
				f.Addrs = append(f.Addrs, a.String())
			}
			h.Interfaces = append(h.Interfaces, f)
		}
	}
	if ev := r.hostListeners(); ev.OK() {
		socks := ev.Data.(evidence.Listeners).Sockets
		for i, s := range socks {
			if i == maxInspectListeners {
				h.Omitted += len(socks) - i
				break
			}
			h.Listening = append(h.Listening, s.Local.String())
		}
	} else {
		r.gaps = append(r.gaps, Gap{What: "the host's listening sockets", Why: string(ev.Status), Detail: ev.Err.Message})
	}
	in.Gaps = append(in.Gaps, r.gaps...)

	running := 0
	for _, c := range h.Containers {
		if c.State == evidence.StateRunning {
			running++
		}
	}
	var parts []string
	if h.Docker != nil {
		kind := "Docker Engine"
		if !h.Docker.LinuxEngine {
			kind = h.Docker.Platform
		}
		parts = append(parts, fmt.Sprintf("%s %s (API %s)", kind, h.Docker.Version, h.Docker.API))
		parts = append(parts, fmt.Sprintf("%d containers listed, %d running", len(h.Containers)+h.Omitted, running))
	} else {
		parts = append(parts, "no Docker API")
	}
	parts = append(parts, fmt.Sprintf("%d interfaces with addresses", len(h.Interfaces)), fmt.Sprintf("%d TCP listeners", len(h.Listening)))
	in.Summary = "Host: " + strings.Join(parts, "; ") + "."
}

func brief(s docker.Summary) ContainerBrief {
	b := ContainerBrief{Name: s.Name(), State: s.State, Networks: s.Networks()}
	if svc := s.Labels[docker.LabelComposeService]; svc != "" {
		b.Service = svc + "@" + s.Labels[docker.LabelComposeProject]
	}
	for _, p := range s.Ports {
		if p.PublicPort == 0 {
			continue
		}
		host := p.IP
		if host == "" {
			host = "0.0.0.0"
		}
		b.Published = append(b.Published, fmt.Sprintf("%s->%d/%s", hostPortString(host, p.PublicPort), p.PrivatePort, cmp.Or(p.Type, "tcp")))
	}
	slices.Sort(b.Published)
	b.Published = slices.Compact(b.Published)
	return b
}

func hostPortString(host string, port uint16) string {
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() && !a.Is4In6() {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

func (e *Engine) inspectContainer(ctx context.Context, scope target.Scope, in *Inspection) error {
	if e.d.Docker == nil {
		return &Error{Code: evidence.CodeDockerUnavailable, Message: "inspecting a container needs the Docker API: " + errText(e.d.DockerErr)}
	}
	r := &run{e: e, docker: e.d.Docker, from: target.From(scope), timing: map[string]time.Duration{}}
	v, err := negotiate(ctx, r.docker)
	if err != nil {
		return &Error{Code: evidence.CodeDockerUnavailable, Message: err.Error()}
	}
	r.version = v
	r.linux = runtime.GOOS == "linux" && v.Os == "linux" && !v.Desktop()
	c, err := r.findSource(ctx)
	if err != nil {
		return err
	}
	f := &ContainerFacts{
		Name: c.Name, ID: evidence.ShortID(c.ID), Image: c.Image, State: c.State, Health: c.Health,
		ExitCode: c.ExitCode, RestartCount: c.RestartCount, StartedAt: c.StartedAt, NetworkMode: c.NetworkMode,
		ExtraHosts: c.ExtraHosts, DNS: c.DNS,
	}
	if c.Compose != nil {
		f.Service = c.Compose.Service + "@" + c.Compose.Project
	}
	for _, a := range c.Networks {
		nf := NetFacts{Network: a.Network, Names: a.Names}
		if a.IPv4.IsValid() {
			nf.IPv4 = a.IPv4.String()
		}
		if a.IPv6.IsValid() {
			nf.IPv6 = a.IPv6.String()
		}
		if !evidence.UserDefined(a.Network) {
			nf.Names = nil // the default bridge answers no names
		}
		f.Networks = append(f.Networks, nf)
	}
	for _, p := range c.Ports {
		if p.HostPort != 0 {
			f.Published = append(f.Published, fmt.Sprintf("%s->%d/%s", p.HostAddr(), p.ContainerPort, p.Proto))
		}
	}
	netns := c
	if owner := c.NetnsOwner(); owner != "" {
		o, _, err := r.inspectEv(ctx, owner)
		if err != nil {
			in.Gaps = append(in.Gaps, Gap{What: "the container whose network namespace it uses", Why: "failed", Detail: err.Error()})
		} else {
			netns = o
			f.NetnsOwner = o.Name
		}
	}
	ev := r.containerListeners(ctx, netns)
	if netns.HostNetwork() {
		ev = r.hostListeners() // its sockets are the host's
	}
	{
		if ev.OK() {
			for _, s := range ev.Data.(evidence.Listeners).Sockets {
				if !s.IsDockerDNS() && len(f.Listening) < maxInspectListeners {
					f.Listening = append(f.Listening, s.Local.String())
				}
			}
		} else if ev.Err != nil && ev.Status != evidence.StatusSkipped {
			in.Gaps = append(in.Gaps, Gap{What: "its listening sockets", Why: string(ev.Status), Detail: ev.Err.Message})
		}
	}
	in.Container = f
	in.Summary = containerSummary(c, f)
	return nil
}

func containerSummary(c evidence.Container, f *ContainerFacts) string {
	state := c.State
	if c.Health != "" {
		state += ", " + c.Health
	}
	where := "no network"
	switch {
	case c.HostNetwork():
		where = "the host's network"
	case f.NetnsOwner != "":
		where = f.NetnsOwner + "'s network namespace"
	case len(c.Networks) > 0:
		where = strings.Join(c.NetworkNames(), ", ")
	}
	s := fmt.Sprintf("%s (%s) is %s, on %s", c.DisplayName(), c.Name, state, where)
	if len(f.Listening) > 0 {
		s += "; listening on " + strings.Join(f.Listening, ", ")
	}
	if len(f.Published) > 0 {
		s += "; publishes " + strings.Join(f.Published, ", ")
	}
	return s + "."
}

func (e *Engine) inspectNetwork(ctx context.Context, name string, in *Inspection) error {
	if e.d.Docker == nil {
		return &Error{Code: evidence.CodeDockerUnavailable, Message: "inspecting a network needs the Docker API: " + errText(e.d.DockerErr)}
	}
	if _, err := negotiate(ctx, e.d.Docker); err != nil {
		return &Error{Code: evidence.CodeDockerUnavailable, Message: err.Error()}
	}
	nctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	n, err := e.d.Docker.InspectNetwork(nctx, name)
	cancel()
	if errors.Is(err, docker.ErrNotFound) {
		return &Error{Code: evidence.CodeNotFound, Message: fmt.Sprintf("no Docker network named %q; list them with inspect_environment scope host", name)}
	}
	if err != nil {
		return &Error{Code: evidence.CodeDockerUnavailable, Message: err.Error()}
	}
	f := &NetworkFacts{
		Name: n.Name, ID: evidence.ShortID(n.ID), Driver: n.Driver, Internal: n.Internal, Compose: n.Compose,
		DNS: evidence.UserDefined(n.Name) && n.Driver != "host" && n.Driver != "null", Members: []string{},
	}
	for _, p := range n.Subnets {
		f.Subnets = append(f.Subnets, p.String())
	}
	for _, g := range n.Gateways {
		f.Gateways = append(f.Gateways, g.String())
	}
	for i, m := range n.Members {
		if i == maxInspectMembers {
			f.Omitted = len(n.Members) - i
			break
		}
		line := m.Name
		if m.IPv4.IsValid() {
			line += " " + m.IPv4.String()
		}
		if m.IPv6.IsValid() {
			line += " " + m.IPv6.String()
		}
		f.Members = append(f.Members, line)
	}
	in.Network = f
	resolution := "Docker's DNS resolves container names on it"
	if !f.DNS {
		resolution = "container names do not resolve on it (Docker's default bridge has no embedded DNS)"
	}
	if n.Internal {
		resolution += "; it is internal: no route to the outside"
	}
	in.Summary = fmt.Sprintf("Network %s (%s driver, %s) has %d containers; %s.", n.Name, n.Driver, orNone(f.Subnets), len(n.Members), resolution)
	return nil
}

func negotiate(ctx context.Context, d Docker) (docker.Version, error) {
	vctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	return d.Negotiate(vctx)
}

func errText(err error) string {
	if err == nil {
		return "Docker access is turned off in the config"
	}
	return err.Error()
}
