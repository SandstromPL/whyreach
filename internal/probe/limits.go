package probe

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/SandstromPL/whyreach/internal/target"
)

// Limits narrow where a probe may connect, beyond the block list that
// always applies (target.Blocked), and which names it may send to a
// nameserver. They come from the user's config and the user's answers
// through the policy package, which hands them to the executors with
// WithLimits; tool arguments never set them (INITIAL.md §4.9).
type Limits struct {
	Restricted bool           // an allowlist applies: only Allow may be dialed
	Allow      []netip.Prefix // what the allowlist admits
	// NamesRestricted holds back lookups of outside names (target.OutsideName)
	// that the hosts file doesn't answer: one goes to a nameserver only when
	// Names lists it (INITIAL.md §10 Q11). The policy sets it for MCP
	// clients, and lists the names Docker's metadata knows, the user
	// approved, or [probe] names covers.
	NamesRestricted bool
	Names           []string // outside names that may be looked up, as target.NormalizeName folds them
	// HostResolvers are the host's own resolvers: a nameserver on the block
	// list is asked anyway when it is one of them, for DNS on port 53 only
	// (INITIAL.md §10 Q13). The policy sets them for every client; none
	// when whyreach can't read the host's resolver files.
	HostResolvers []netip.Addr
	// AddrsRestricted holds back connects to private addresses that only the
	// allowlist's rfc1918 class admits (INITIAL.md §10 Q15): one goes out
	// only when Free covers its address or Approved lists its address and
	// port. The policy sets it for MCP clients.
	AddrsRestricted bool
	Private         []netip.Prefix // what the rfc1918 class admits
	Free            []netip.Prefix // Docker's networks, the host's own addresses, explicit allowlist entries
	// Approved lists the addresses and ports the user approved, once per
	// connect the batch may make to each: Run counts them down.
	Approved  []netip.AddrPort
	allowance *allowance
}

// ApprovalBudget is how many lookups of a name, or connects to an address
// and port, one approval of the user's covers in a session (INITIAL.md §10
// Q14, Q15): past them, the MCP server asks again.
const ApprovalBudget = 3

// AddrNotApproved is the message of a connect that was not made because its
// address is private, outside Docker's networks and the host's own
// addresses, and no one approved it: gaps recognise it and say how to allow
// it, and the MCP server asks the user about the address and port.
const AddrNotApproved = "not connected: a private address outside Docker's networks and this machine's own addresses is connected to only with the user's approval ([probe] allow)"

// CheckConnect reports whether a connect to addr may be sent, and why not:
// Check, then the approval a private address outside Docker's networks
// and the host's own addresses needs.
func (l Limits) CheckConnect(addr netip.AddrPort) (reason string, ok bool) {
	a := addr.Addr().Unmap()
	if reason, ok := l.Check(a); !ok {
		return reason, false
	}
	if !l.AddrsRestricted || !inPrefixes(l.Private, a) || inPrefixes(l.Free, a) || slices.Contains(l.Approved, netip.AddrPortFrom(a, addr.Port())) {
		return "", true
	}
	return AddrNotApproved, false
}

// HostResolver reports whether a is one of the host's own resolvers. For an
// IPv6 link-local address the zone counts too, since it names the link: a
// container's own fe80::1%eth0 isn't the host's router at fe80::1%wlan0.
func (l Limits) HostResolver(a netip.Addr) bool {
	a = a.Unmap()
	return slices.ContainsFunc(l.HostResolvers, func(h netip.Addr) bool {
		h = h.Unmap()
		if a.Is6() && a.IsLinkLocalUnicast() {
			return h == a
		}
		return h.WithZone("") == a.WithZone("")
	})
}

// needsApproval reports a private address that only an approval lets
// through (INITIAL.md §10 Q15).
func (l Limits) needsApproval(a netip.Addr) bool {
	a = a.Unmap()
	return l.AddrsRestricted && inPrefixes(l.Private, a) && !inPrefixes(l.Free, a)
}

// allowance counts the connects a batch may still make to each approved
// address and port: each takes one, so a batch never makes more than the
// policy set aside for it (INITIAL.md §10 Q15).
type allowance struct {
	mu   sync.Mutex
	left map[netip.AddrPort]int
}

func newAllowance(approved []netip.AddrPort) *allowance {
	a := &allowance{left: map[netip.AddrPort]int{}}
	for _, ap := range approved {
		a.left[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())]++
	}
	return a
}

// take uses one connect to ap, if one is left.
func (a *allowance) take(ap netip.AddrPort) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.left[ap] == 0 {
		return false
	}
	a.left[ap]--
	return true
}

func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(a) })
}

// AddrsFlags encodes HostResolvers and the private-address limits for
// `whyreach __probe`: flag name → value, only for those that apply.
func (l Limits) AddrsFlags() [][2]string {
	var out [][2]string
	if len(l.HostResolvers) > 0 {
		out = append(out, [2]string{"--host-resolvers", joinStrings(l.HostResolvers)})
	}
	if l.AddrsRestricted {
		out = append(out, [2]string{"--private", joinStrings(l.Private)}, [2]string{"--free", joinStrings(l.Free)}, [2]string{"--approved", joinStrings(l.Approved)})
	}
	return out
}

func joinStrings[T fmt.Stringer](xs []T) string {
	parts := make([]string, 0, len(xs))
	for _, x := range xs {
		parts = append(parts, x.String())
	}
	return strings.Join(parts, ",")
}

// ParseAddrs decodes a comma-separated list of addresses.
func ParseAddrs(s string) ([]netip.Addr, error) {
	return parseList(s, netip.ParseAddr)
}

// ParsePrefixes decodes a comma-separated list of prefixes.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	return parseList(s, func(p string) (netip.Prefix, error) {
		pr, err := netip.ParsePrefix(p)
		return pr.Masked(), err
	})
}

// ParseAddrPorts decodes a comma-separated list of address:port pairs.
func ParseAddrPorts(s string) ([]netip.AddrPort, error) {
	return parseList(s, netip.ParseAddrPort)
}

func parseList[T any](s string, parse func(string) (T, error)) ([]T, error) {
	var out []T
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		v, err := parse(part)
		if err != nil {
			return nil, fmt.Errorf("list entry %q: %w", part, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// NameNotApproved is the message of a lookup that was not sent because its
// name is outside Docker and no one approved it: gaps recognise it and say
// how to allow it, and the MCP server asks the user about the name.
const NameNotApproved = "not looked up: a name outside Docker is sent to a DNS server only with the user's approval ([probe] names)"

// CheckName reports whether a lookup of name may go to a nameserver.
func (l Limits) CheckName(name string) (reason string, ok bool) {
	if !l.NamesRestricted || !target.OutsideName(name) {
		return "", true
	}
	n := target.NormalizeName(name)
	for _, allowed := range l.Names {
		if n == allowed {
			return "", true
		}
	}
	return NameNotApproved, false
}

// NamesFlag encodes Names for `whyreach __probe --names`.
func (l Limits) NamesFlag() string { return strings.Join(l.Names, ",") }

// ParseNames decodes NamesFlag's output into restricted limits on names.
func ParseNames(s string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		n, err := target.ParseName(part)
		if err != nil {
			return nil, fmt.Errorf("names entry: %w", err)
		}
		out = append(out, target.NormalizeName(n))
	}
	return out, nil
}

// Check reports whether a connect to addr may be sent, and why not.
func (l Limits) Check(addr netip.Addr) (reason string, ok bool) {
	addr = addr.Unmap()
	if reason, blocked := target.Blocked(addr); blocked {
		return reason, false
	}
	if !l.Restricted {
		return "", true
	}
	for _, p := range l.Allow {
		if p.Contains(addr) {
			return "", true
		}
	}
	return fmt.Sprintf("%s is outside the probe allowlist ([probe] allow in the config file)", addr), false
}

// Flag encodes the limits for `whyreach __probe --allow`. An unrestricted
// probe gets no flag at all.
func (l Limits) Flag() string {
	parts := make([]string, 0, len(l.Allow))
	for _, p := range l.Allow {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// ParseLimits decodes Flag's output: a restricted allowlist, possibly empty.
func ParseLimits(s string) (Limits, error) {
	l := Limits{Restricted: true}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return Limits{}, fmt.Errorf("allowlist entry %q: %w", part, err)
		}
		l.Allow = append(l.Allow, p.Masked())
	}
	return l, nil
}

type limitsKey struct{}

// WithLimits returns a context whose probes obey l.
func WithLimits(ctx context.Context, l Limits) context.Context {
	return context.WithValue(ctx, limitsKey{}, l)
}

// LimitsFrom returns the limits set with WithLimits, or none.
func LimitsFrom(ctx context.Context) Limits {
	l, _ := ctx.Value(limitsKey{}).(Limits)
	return l
}
