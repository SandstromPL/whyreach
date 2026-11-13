package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/target"
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
	// fallback runs a batch the inner executor could not run because it
	// couldn't enter the namespace (executor.ErrCannotEnter): probe
	// containers, used only while tier 2b is in effect.
	fallback func() (executor.Executor, error)
}

func (g *guard) Name() string { return g.name }

func (g *guard) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) (evs []evidence.Evidence, err error) {
	if g.tier2b && !g.p.ProbeContainers() {
		countsFrom(ctx).add(0, len(specs)) // withheld: the audit counts them as denied
		return executor.Failed(where, g.name, specs, evidence.StatusPermissionDenied, &evidence.Error{
			Code: evidence.CodePermissionDenied, Message: executor.ProbeContainersOff,
		}), nil
	}
	lim := g.p.limits(ctx)
	// Connects to approved private addresses are set aside for the batch
	// before anything is sent, and lookups of approved names once the names
	// are known; what goes unused returns afterwards (§10 Q14, Q15).
	var leasedNames []string
	if lim.AddrsRestricted {
		lim.Approved = g.p.leaseAddrs(specs)
	}
	defer func() { g.p.settle(leasedNames, lim.Approved, evs) }()
	var refused []evidence.Evidence
	var send []probe.Spec
	for _, s := range specs {
		if s.Kind == probe.SpecTCP {
			if a, err := netip.ParseAddr(s.Host); err == nil {
				if reason, ok := lim.CheckConnect(netip.AddrPortFrom(a, s.Port)); !ok {
					refused = append(refused, deny(where, g.name, s, reason))
					continue
				}
			}
		}
		// Listener reads through /proc are free; in a probe container
		// (Docker Desktop) every check is a container run, so it counts.
		if (s.Kind != probe.SpecListeners || g.tier2b) && !g.p.limiter.take() {
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
	lim.NamesRestricted, lim.Names, leasedNames = g.p.names(ctx, send)
	ex, err := g.inner()
	if err != nil {
		return append(refused, executor.Failed(where, g.name, send, evidence.StatusFailed, &evidence.Error{
			Code: evidence.CodeDockerUnavailable, Message: err.Error(),
		})...), err
	}
	evs, err = ex.Run(probe.WithLimits(ctx, lim), where, send)
	if err != nil && g.fallback != nil && errors.Is(err, executor.ErrCannotEnter) && g.p.ProbeContainers() {
		if pex, perr := g.fallback(); perr == nil {
			why := err.Error()
			g.p.d.Logger.Warn("using a probe container instead", "container", where.String(), "err", err)
			evs, err = pex.Run(probe.WithLimits(ctx, lim), where, send)
			for i := range evs {
				evs[i].Limitations = append(evs[i].Limitations, "ran in a probe container: "+why)
			}
		}
	}
	// A check whose lookup the probe refused before sending anything (a
	// name held back, or the first nameserver on the block list) counts as
	// denied; one refused after its queries went out (the next nameserver
	// on the block list) stays sent. Counted per check, since a connect to
	// a name reports its lookup too.
	refusedLookups := map[string]bool{}
	for _, e := range evs {
		if e.Kind == evidence.KindDNS && e.Status == evidence.StatusSkipped && e.Err != nil && e.Err.Code == evidence.CodePolicyDenied && !queried(e) {
			refusedLookups[target.NormalizeName(e.Subject)] = true
		}
	}
	n := 0
	for _, s := range send {
		if (s.Kind == probe.SpecDNS || s.Kind == probe.SpecTCP) && refusedLookups[target.NormalizeName(s.Host)] {
			n++
		}
	}
	countsFrom(ctx).add(-n, n)
	return append(evs, refused...), err
}

// queried reports a lookup that sent queries.
func queried(e evidence.Evidence) bool {
	p, ok := e.Data.(evidence.DNSProbe)
	return ok && len(p.Attempts) > 0
}

// names says whether a batch's lookups of outside names are held back, and
// which outside names among its checks may go to a nameserver anyway: those
// [probe] names covers, those Docker's metadata knows, and those the user
// approved this session while the approval has lookups left (INITIAL.md
// §10 Q11, Q14). An approved name takes one lookup for the batch: leased.
func (p *Policy) names(ctx context.Context, specs []probe.Spec) (restricted bool, allowed, leased []string) {
	if !p.NamesNeedApproval() {
		return false, nil, nil
	}
	known := executor.KnownNamesFrom(ctx)
	for _, s := range specs {
		if s.Kind == probe.SpecListeners || !target.OutsideName(s.Host) {
			continue
		}
		n := target.NormalizeName(s.Host)
		if slices.Contains(allowed, n) {
			continue
		}
		switch {
		case target.CoveredBy(n, p.d.Settings.Names), known(ctx, n):
			allowed = append(allowed, n)
		case p.leaseName(n):
			allowed, leased = append(allowed, n), append(leased, n)
		}
	}
	return true, allowed, leased
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
