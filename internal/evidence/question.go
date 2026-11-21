package evidence

import (
	"net/netip"
	"strconv"
	"strings"
)

// Question is what the user asked: can From reach To?
type Question struct {
	From Source `json:"from"`
	To   Target `json:"to"`
}

// Source kinds.
const (
	SourceHost      = "host"
	SourceContainer = "container"
)

// Source is where the connection starts.
type Source struct {
	Kind        string `json:"kind"`                   // host or container
	Ref         string `json:"ref"`                    // as given: "host", "container:worker", "service:worker@shop"
	ContainerID string `json:"container_id,omitempty"` // the container Ref resolved to
}

// Target classes.
const (
	TargetName     = "name"     // a container name, Compose service, alias or DNS name
	TargetIP       = "ip"       // an IP address that is not loopback
	TargetLoopback = "loopback" // localhost, 127.0.0.0/8, ::1: the source's own netns
)

// Target is where the connection should go.
type Target struct {
	Host  string     `json:"host"`          // "api", "10.0.0.5", "::1", "localhost"
	Port  uint16     `json:"port"`          // 1-65535
	Proto string     `json:"proto"`         // "tcp"
	Class string     `json:"class"`         // name, ip or loopback
	Addr  netip.Addr `json:"addr,omitzero"` // set when Host is an IP address
}

// String is the target as host:port, with IPv6 addresses in brackets.
func (t Target) String() string {
	if t.Addr.Is6() && !t.Addr.Is4In6() {
		return "[" + t.Host + "]:" + strconv.Itoa(int(t.Port))
	}
	return t.Host + ":" + strconv.Itoa(int(t.Port))
}

// ClassifyHost decides whether host is a name, a loopback reference or another
// address. The names Docker puts in every container's /etc/hosts for loopback
// count as loopback.
func ClassifyHost(host string) (class string, addr netip.Addr) {
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if a.IsLoopback() || a.IsUnspecified() {
			return TargetLoopback, a
		}
		return TargetIP, a
	}
	h := NormalizeName(host)
	switch {
	case h == "localhost", h == "ip6-localhost", h == "ip6-loopback", strings.HasSuffix(h, ".localhost"):
		return TargetLoopback, netip.Addr{}
	default:
		return TargetName, netip.Addr{}
	}
}
