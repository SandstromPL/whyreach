package docker

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// Network is the part of a Docker network's metadata whyreach uses. MAC
// addresses and driver options are never kept.
type Network struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Driver   string          `json:"driver"`
	Scope    string          `json:"scope,omitempty"`
	Internal bool            `json:"internal,omitempty"`
	IPv6     bool            `json:"ipv6,omitempty"`
	Subnets  []netip.Prefix  `json:"subnets,omitempty"`
	Gateways []netip.Addr    `json:"gateways,omitempty"`
	Compose  string          `json:"compose_project,omitempty"`
	Members  []NetworkMember `json:"members,omitempty"` // only from InspectNetwork, sorted by name
}

// NetworkMember is a container attached to a network.
type NetworkMember struct {
	ID   string     `json:"id"`
	Name string     `json:"name"`
	IPv4 netip.Addr `json:"ipv4,omitzero"`
	IPv6 netip.Addr `json:"ipv6,omitzero"`
}

type networkJSON struct {
	ID         string `json:"Id"`
	Name       string `json:"Name"`
	Driver     string `json:"Driver"`
	Scope      string `json:"Scope"`
	Internal   bool   `json:"Internal"`
	EnableIPv6 bool   `json:"EnableIPv6"`
	IPAM       struct {
		Config []struct {
			Subnet  string `json:"Subnet"`
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
	Labels     map[string]string `json:"Labels"`
	Containers map[string]struct {
		Name        string `json:"Name"`
		IPv4Address string `json:"IPv4Address"`
		IPv6Address string `json:"IPv6Address"`
	} `json:"Containers"`
}

func (n networkJSON) toNetwork() Network {
	out := Network{
		ID: n.ID, Name: n.Name, Driver: n.Driver, Scope: n.Scope, Internal: n.Internal, IPv6: n.EnableIPv6,
		Compose: n.Labels[LabelComposeProject],
	}
	for _, c := range n.IPAM.Config {
		if p, err := netip.ParsePrefix(c.Subnet); err == nil {
			out.Subnets = append(out.Subnets, p.Masked())
		}
		if a, err := netip.ParseAddr(c.Gateway); err == nil {
			out.Gateways = append(out.Gateways, a.Unmap())
		}
	}
	for id, c := range n.Containers {
		m := NetworkMember{ID: id, Name: c.Name}
		m.IPv4 = prefixAddr(c.IPv4Address)
		m.IPv6 = prefixAddr(c.IPv6Address)
		out.Members = append(out.Members, m)
	}
	slices.SortFunc(out.Members, func(a, b NetworkMember) int {
		return strings.Compare(a.Name+"\x00"+a.ID, b.Name+"\x00"+b.ID)
	})
	return out
}

// prefixAddr reads "172.22.0.3/16" as its address.
func prefixAddr(s string) netip.Addr {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Unmap()
	}
	return parseAddr(s)
}

// ListNetworks lists the daemon's networks, sorted by name. The list has no
// members; InspectNetwork has them.
func (c *Client) ListNetworks(ctx context.Context) ([]Network, error) {
	var raw []networkJSON
	if err := c.do(ctx, http.MethodGet, "/networks", nil, nil, "", &raw); err != nil {
		return nil, err
	}
	out := make([]Network, 0, len(raw))
	for _, n := range raw {
		nw := n.toNetwork()
		nw.Members = nil
		out = append(out, nw)
	}
	slices.SortFunc(out, func(a, b Network) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// InspectNetwork returns a network and the containers attached to it, by
// ID or name.
func (c *Client) InspectNetwork(ctx context.Context, idOrName string) (Network, error) {
	var raw networkJSON
	if err := c.do(ctx, http.MethodGet, "/networks/"+url.PathEscape(idOrName), nil, nil, "", &raw); err != nil {
		return Network{}, err
	}
	return raw.toNetwork(), nil
}
