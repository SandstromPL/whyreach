package policy

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// guard wraps an executor with the policy: the permission tier, the probe
// allowlist (checked here for literal addresses and, through the context,
// at dial time for every address a name resolves to) and the rate limit.
// Refused checks come back as records with the reason, so they become gaps.
type guard struct {
	p      *Policy
	name   string
	tier2b bool
	inner  func() (executor.Executor, error)
}

func (g *guard) Name() string { return g.name }

func (g *guard) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	if g.tier2b && !g.p.ProbeContainers() {
		return executor.Failed(where, g.name, specs, evidence.StatusPermissionDenied, &evidence.Error{
			Code: evidence.CodePermissionDenied, Message: executor.ProbeContainersOff,
		}), nil
	}
	lim := g.p.limits(ctx)
	var refused []evidence.Evidence
	var send []probe.Spec
	for _, s := range specs {
		if s.Kind == probe.SpecTCP {
			if a, err := netip.ParseAddr(s.Host); err == nil {
				if reason, ok := lim.Check(a); !ok {
					refused = append(refused, deny(where, g.name, s, reason))
					continue
				}
			}
		}
		if s.Kind != probe.SpecListeners && !g.p.limiter.take() {
			refused = append(refused, deny(where, g.name, s, fmt.Sprintf(
				"rate limit: whyreach sends at most %d probes a minute ([probe] rate_per_minute)", g.p.d.Settings.RatePerMinute)))
			continue
		}
		send = append(send, s)
	}
	countsFrom(ctx).add(len(send), len(refused))
	if len(send) == 0 {
		return refused, nil
	}
	ex, err := g.inner()
	if err != nil {
		return append(refused, executor.Failed(where, g.name, send, evidence.StatusFailed, &evidence.Error{
			Code: evidence.CodeDockerUnavailable, Message: err.Error(),
		})...), err
	}
	evs, err := ex.Run(probe.WithLimits(ctx, lim), where, send)
	return append(evs, refused...), err
}

// deny is the record of a check the policy refused to send.
func deny(where evidence.ContextRef, exe string, s probe.Spec, reason string) evidence.Evidence {
	ev := executor.Failed(where, exe, []probe.Spec{s}, evidence.StatusSkipped, &evidence.Error{
		Code: evidence.CodePolicyDenied, Message: reason,
	})[0]
	if s.Kind == probe.SpecTCP {
		if a, err := netip.ParseAddr(s.Host); err == nil {
			via := evidence.ViaLiteral
			if s.Via != "" {
				via = s.Via
			}
			ev.Data = evidence.TCPProbe{Target: ev.Subject, Addr: netip.AddrPortFrom(a, s.Port), Via: via, Outcome: evidence.OutcomeBlocked}
		}
	}
	return ev
}

// counts tallies the probes one call sent and the ones the policy refused,
// for its audit entry.
type counts struct{ sent, denied atomic.Int64 }

type countsKey struct{}

func withCounts(ctx context.Context) (context.Context, *counts) {
	c := &counts{}
	return context.WithValue(ctx, countsKey{}, c), c
}

func countsFrom(ctx context.Context) *counts {
	if c, ok := ctx.Value(countsKey{}).(*counts); ok {
		return c
	}
	return &counts{}
}

func (c *counts) add(sent, denied int) {
	c.sent.Add(int64(sent))
	c.denied.Add(int64(denied))
}

func (c *counts) fill(e *Entry) {
	e.ProbesSent = int(c.sent.Load())
	e.ProbesDenied = int(c.denied.Load())
}
