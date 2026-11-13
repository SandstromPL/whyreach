package probe

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/SandstromPL/whyreach/internal/target"
)

// Limits narrow where a probe may connect, beyond the block list that
// always applies (target.Blocked). They come from the user's config through
// the policy package, which hands them to the executors with WithLimits;
// tool arguments never set them (INITIAL.md §4.9).
type Limits struct {
	Restricted bool           // an allowlist applies: only Allow may be dialed
	Allow      []netip.Prefix // what the allowlist admits
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
