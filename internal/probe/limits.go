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
	if !l.needsApproval(a) || slices.Contains(l.Approved, netip.AddrPortFrom(a, addr.Port())) {
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

// The flags of `whyreach __probe` that carry the limits. Each restriction's
// flag is given only when the restriction applies, so an absent one means
// none: no --allow, no allowlist; no --names, any name; no --private, no
// approval for private addresses.
const (
	FlagAllow         = "allow"          // Restricted: Allow
	FlagNames         = "names"          // NamesRestricted: Names
	FlagHostResolvers = "host-resolvers" // HostResolvers
	FlagPrivate       = "private"        // AddrsRestricted: Private
	FlagFree          = "free"           // Free, with --private
	FlagApproved      = "approved"       // Approved, with --private
)

// ProbeArgs encodes l as arguments of `whyreach __probe`, the flags of the
// limits that apply; LimitsFromFlags decodes them. Unrestricted limits give
// none.
func (l Limits) ProbeArgs() []string {
	var args []string
	if l.Restricted {
		args = append(args, "--"+FlagAllow, joinStrings(l.Allow))
	}
	if l.NamesRestricted {
		args = append(args, "--"+FlagNames, strings.Join(l.Names, ","))
	}
	if len(l.HostResolvers) > 0 {
		args = append(args, "--"+FlagHostResolvers, joinStrings(l.HostResolvers))
	}
	if l.AddrsRestricted {
		args = append(args, "--"+FlagPrivate, joinStrings(l.Private), "--"+FlagFree, joinStrings(l.Free), "--"+FlagApproved, joinStrings(l.Approved))
	}
	return args
}

// LimitsFromFlags decodes ProbeArgs's flags inside the probe container:
// changed reports whether a flag was given, get returns its value. A
// restriction whose flag is absent doesn't apply.
func LimitsFromFlags(changed func(name string) bool, get func(name string) string) (Limits, error) {
	var l Limits
	var err error
	if changed(FlagAllow) {
		l.Restricted = true
		if l.Allow, err = parsePrefixes(get(FlagAllow)); err != nil {
			return Limits{}, fmt.Errorf("--%s: %w", FlagAllow, err)
		}
	}
	if changed(FlagNames) {
		l.NamesRestricted = true
		if l.Names, err = parseNames(get(FlagNames)); err != nil {
			return Limits{}, fmt.Errorf("--%s: %w", FlagNames, err)
		}
	}
	if l.HostResolvers, err = parseList(get(FlagHostResolvers), netip.ParseAddr); err != nil {
		return Limits{}, fmt.Errorf("--%s: %w", FlagHostResolvers, err)
	}
	if changed(FlagPrivate) {
		l.AddrsRestricted = true
		if l.Private, err = parsePrefixes(get(FlagPrivate)); err != nil {
			return Limits{}, fmt.Errorf("--%s: %w", FlagPrivate, err)
		}
		if l.Free, err = parsePrefixes(get(FlagFree)); err != nil {
			return Limits{}, fmt.Errorf("--%s: %w", FlagFree, err)
		}
		if l.Approved, err = parseList(get(FlagApproved), netip.ParseAddrPort); err != nil {
			return Limits{}, fmt.Errorf("--%s: %w", FlagApproved, err)
		}
	}
	return l, nil
}

func joinStrings[T fmt.Stringer](xs []T) string {
	parts := make([]string, 0, len(xs))
	for _, x := range xs {
		parts = append(parts, x.String())
	}
	return strings.Join(parts, ",")
}

// parsePrefixes decodes a comma-separated list of prefixes.
func parsePrefixes(s string) ([]netip.Prefix, error) {
	return parseList(s, func(p string) (netip.Prefix, error) {
		pr, err := netip.ParsePrefix(p)
		return pr.Masked(), err
	})
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

// parseNames decodes the --names list: outside names, as
// target.NormalizeName folds them.
func parseNames(s string) ([]string, error) {
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
