package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Compose labels.
const (
	LabelComposeProject = "com.docker.compose.project"
	LabelComposeService = "com.docker.compose.service"
)

// Summary is one entry of GET /containers/json.
type Summary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	State   string            `json:"State"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
}

// Name is the container's name without the leading slash.
func (s Summary) Name() string {
	if len(s.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(s.Names[0], "/")
}

// ListContainers lists containers, stopped ones included when all is set.
// labels filters by "key=value" or "key" (all must match).
func (c *Client) ListContainers(ctx context.Context, all bool, labels ...string) ([]Summary, error) {
	q := url.Values{}
	if all {
		q.Set("all", "1")
	}
	if len(labels) > 0 {
		f, err := json.Marshal(map[string][]string{"label": labels})
		if err != nil {
			return nil, err
		}
		q.Set("filters", string(f))
	}
	var out []Summary
	if err := c.do(ctx, http.MethodGet, "/containers/json", q, nil, "", &out); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b Summary) int { return strings.Compare(a.Name(), b.Name()) })
	return out, nil
}

// containerJSON is the part of GET /containers/{id}/json whyreach decodes.
// It deliberately has no Config.Env: environment values are never read
// (CLAUDE.md non-negotiable 6).
type containerJSON struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status     string `json:"Status"`
		Pid        int    `json:"Pid"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode  string                   `json:"NetworkMode"`
		PortBindings map[string][]portBinding `json:"PortBindings"`
		ExtraHosts   []string                 `json:"ExtraHosts"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID         string   `json:"NetworkID"`
			IPAddress         string   `json:"IPAddress"`
			GlobalIPv6Address string   `json:"GlobalIPv6Address"`
			Gateway           string   `json:"Gateway"`
			Aliases           []string `json:"Aliases"`
			DNSNames          []string `json:"DNSNames"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// InspectContainer returns a container's metadata by ID or name.
func (c *Client) InspectContainer(ctx context.Context, idOrName string) (evidence.Container, error) {
	var raw containerJSON
	if err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(idOrName)+"/json", nil, nil, "", &raw); err != nil {
		return evidence.Container{}, err
	}
	return raw.toEvidence(), nil
}

func (r containerJSON) toEvidence() evidence.Container {
	c := evidence.Container{
		ID:           r.ID,
		Name:         strings.TrimPrefix(r.Name, "/"),
		Image:        r.Config.Image,
		State:        r.State.Status,
		ExitCode:     r.State.ExitCode,
		Error:        r.State.Error,
		Pid:          r.State.Pid,
		StartedAt:    parseTime(r.State.StartedAt),
		FinishedAt:   parseTime(r.State.FinishedAt),
		RestartCount: r.RestartCount,
		NetworkMode:  r.HostConfig.NetworkMode,
		ExtraHosts:   slices.Clone(r.HostConfig.ExtraHosts),
	}
	if r.State.Health != nil && r.State.Health.Status != "none" {
		c.Health = r.State.Health.Status
	}
	if p := r.Config.Labels[LabelComposeProject]; p != "" {
		c.Compose = &evidence.ComposeRef{Project: p, Service: r.Config.Labels[LabelComposeService]}
	}
	for name, n := range r.NetworkSettings.Networks {
		a := evidence.NetAttachment{
			Network:   name,
			NetworkID: n.NetworkID,
			IPv4:      parseAddr(n.IPAddress),
			IPv6:      parseAddr(n.GlobalIPv6Address),
			Gateway:   parseAddr(n.Gateway),
		}
		names := append(slices.Clone(n.Aliases), n.DNSNames...)
		for i := range names {
			names[i] = strings.ToLower(names[i])
		}
		slices.Sort(names)
		a.Names = slices.Compact(names)
		c.Networks = append(c.Networks, a)
	}
	slices.SortFunc(c.Networks, func(a, b evidence.NetAttachment) int { return strings.Compare(a.Network, b.Network) })
	for spec, bindings := range r.HostConfig.PortBindings {
		port, proto := parsePortSpec(spec)
		if port == 0 {
			continue
		}
		if len(bindings) == 0 {
			c.Ports = append(c.Ports, evidence.PortMap{ContainerPort: port, Proto: proto})
		}
		for _, b := range bindings {
			hp, _ := strconv.ParseUint(b.HostPort, 10, 16)
			c.Ports = append(c.Ports, evidence.PortMap{ContainerPort: port, Proto: proto, HostIP: b.HostIP, HostPort: uint16(hp)})
		}
	}
	slices.SortFunc(c.Ports, func(a, b evidence.PortMap) int {
		if a.ContainerPort != b.ContainerPort {
			return int(a.ContainerPort) - int(b.ContainerPort)
		}
		if a.Proto != b.Proto {
			return strings.Compare(a.Proto, b.Proto)
		}
		if a.HostIP != b.HostIP {
			return strings.Compare(a.HostIP, b.HostIP)
		}
		return int(a.HostPort) - int(b.HostPort)
	})
	return c
}

// parsePortSpec splits "8080/tcp".
func parsePortSpec(s string) (uint16, string) {
	p, proto, _ := strings.Cut(s, "/")
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return 0, ""
	}
	if proto == "" {
		proto = "tcp"
	}
	return uint16(n), proto
}

func parseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// parseTime reads Docker's RFC 3339 timestamps; the zero time
// ("0001-01-01T00:00:00Z") stays zero.
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() <= 1 {
		return time.Time{}
	}
	return t.UTC()
}
