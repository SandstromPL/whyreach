package probe

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

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
