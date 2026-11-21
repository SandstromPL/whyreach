package engine

import (
	"context"
	"net/netip"
	"slices"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// maxControls bounds the host addresses whose own connect is made for
// comparison (WR021).
const maxControls = 2

// hostControl makes the host's own connect for comparison (WR021). When a
// container's connect to one of the host's addresses was rejected ("no
// route to host"), timed out, or was refused although a listener of the
// host's takes that address, whyreach connects to the same address and port
// from its own network namespace, the host's. Host firewalls let the host's
// own traffic in (it arrives through the loopback interface), so an answer
// there and none, or a refusal, for the container points at a firewall that
// filters what comes in from Docker's networks. Measured in M6 (ADR 0002).
//
// It is one connect to the address the source's own connect went to, through
// the host executor and so through the policy, like every probe: the
// allowlist (it admitted the source's connect to that address), Q15's free
// list (the host's own addresses need no approval through MCP), a token of
// the rate limit and the audit's count. Only where Docker Engine runs on
// this machine: on Docker Desktop the host the containers reach is Windows
// or macOS, behind Docker Desktop's own network stack, and a connect from
// here says nothing about it.
func (r *run) hostControl(ctx context.Context) error {
	if ctx.Err() != nil || r.q.From.Kind != evidence.SourceContainer || !r.engineHere || r.e.d.Host == nil {
		return nil
	}
	view := r.view()
	if view.HostSource() {
		return nil // a host-network container's connect was the host's own
	}
	addrs := controlAddrs(view)
	if len(addrs) == 0 {
		return nil
	}
	specs := make([]probe.Spec, 0, len(addrs))
	for _, a := range addrs {
		specs = append(specs, probe.Spec{Kind: probe.SpecTCP, Host: a.Addr().String(), Port: a.Port(), Via: evidence.ViaControl})
	}
	where := r.host()
	evs, err := r.e.d.Host.Run(ctx, where, specs)
	if err != nil {
		r.e.d.Logger.Warn("the host's own connect failed to run", "err", err)
	}
	r.store.Add(restamp(evs, where)...)
	return nil
}

// controlAddrs lists the host addresses and ports the source's connects
// through the target's name (or literal address) failed at in a way a host
// firewall explains: rejected with EHOSTUNREACH, timed out, or refused while
// a listener of the host's takes the address. None when one of them
// connected, or when the target isn't the host's own service (a port a
// container publishes there goes through Docker's NAT).
func controlAddrs(v evidence.View) []netip.AddrPort {
	d := v.Destinations()
	if d.Host == nil || d.Host.Via == evidence.HostViaLoopback || len(d.Published) > 0 {
		return nil
	}
	hl, read := v.HostListeners()
	var out []netip.AddrPort
	for _, t := range v.SourceTCP() {
		if !t.P.ByName() {
			continue
		}
		a := netip.AddrPortFrom(t.P.Addr.Addr().Unmap(), t.P.Addr.Port())
		switch {
		case t.P.Outcome == evidence.OutcomeConnected:
			return nil // it works: nothing to compare
		case !v.HostHolds(a.Addr()), slices.Contains(out, a), len(out) == maxControls:
			continue
		case t.P.Outcome == evidence.OutcomeTimeout,
			t.P.Outcome == evidence.OutcomeUnreachable && t.P.Errno == "EHOSTUNREACH",
			t.P.Outcome == evidence.OutcomeRefused && read && slices.ContainsFunc(hl.L.OnPort(a.Port()), func(s evidence.Socket) bool { return s.Accepts(a.Addr()) }):
			out = append(out, a)
		}
	}
	return out
}
