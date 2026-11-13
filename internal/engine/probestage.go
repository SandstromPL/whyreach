package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// probe runs DNS and TCP checks from the source's network namespace, after
// the gate: no probe runs from a stopped source or towards a destination
// that isn't running (WR008 is checked first).
func (r *run) probe(ctx context.Context) error {
	view := evidence.NewView(r.q, r.store.Snapshot())
	specs := r.specs(view)
	if len(specs) == 0 {
		return nil
	}

	var ex executor.Executor
	var where, stamp evidence.ContextRef
	switch r.q.From.Kind {
	case evidence.SourceHost:
		ex, where, stamp = r.e.d.Host, evidence.Host(), evidence.Host()
	default:
		src, ok := view.Source()
		if !ok {
			return nil // resolve already recorded why
		}
		stamp = evidence.InContainer(src.C)
		owner, ok := view.NetnsOwner()
		if !ok {
			r.store.Add(executor.Failed(stamp, "", specs, evidence.StatusFailed, &evidence.Error{
				Code: evidence.CodeNotFound,
				Message: fmt.Sprintf("%s uses the network namespace of %s, whose metadata could not be read",
					src.C.DisplayName(), strings.TrimPrefix(src.C.NetworkMode, "container:")),
			})...)
			return nil
		}
		// The probe joins the netns owner directly; the evidence is reported
		// in the source's context, which shares that netns.
		where = evidence.InContainer(owner.C)
		if !owner.C.Running() {
			r.store.Add(executor.Failed(stamp, "", specs, evidence.StatusFailed, &evidence.Error{
				Code:    evidence.CodeNotFound,
				Message: fmt.Sprintf("%s is %s, so nothing can be tested from its network namespace; start it first", owner.C.DisplayName(), owner.C.State),
			})...)
			return nil
		}
		ex = r.e.d.Probe
	}

	// The gate comes before the tier-2b check: probes that would be skipped
	// anyway must not ask for probe containers.
	if down := r.destinationDown(view); down != "" {
		r.store.Add(executor.Failed(stamp, "", specs, evidence.StatusSkipped, &evidence.Error{
			Code: evidence.CodeNotFound, Message: down,
		})...)
		return nil
	}
	if ex == nil {
		r.store.Add(executor.Failed(stamp, evidence.ExecutorProbeContainer, specs, evidence.StatusPermissionDenied, &evidence.Error{
			Code: evidence.CodePermissionDenied, Message: executor.ProbeContainersOff,
		})...)
		return nil
	}

	evs, err := ex.Run(ctx, where, specs)
	if err != nil {
		r.e.d.Logger.Warn("probe batch failed", "executor", ex.Name(), "err", err)
	}
	for i := range evs {
		netns, exe := evs[i].Context.NetnsID, evs[i].Context.Executor
		evs[i].Context = stamp
		evs[i].Context.NetnsID, evs[i].Context.Executor = netns, exe
		if evs[i].ObservedAt.IsZero() {
			evs[i].ObservedAt = time.Now()
		}
	}
	r.store.Add(evs...)
	return nil
}

// specs lists the checks for the question: look the name up and connect to
// it as the app would, plus (for a destination on another network) its
// metadata addresses, to show the path is blocked too.
func (r *run) specs(view evidence.View) []probe.Spec {
	to := r.q.To
	var specs []probe.Spec
	switch {
	case to.Class == evidence.TargetName:
		specs = append(specs, probe.Spec{Kind: probe.SpecDNS, Host: to.Host}, probe.Spec{Kind: probe.SpecTCP, Host: to.Host, Port: to.Port})
	case to.Addr.IsValid():
		specs = append(specs, probe.Spec{Kind: probe.SpecTCP, Host: to.Addr.String(), Port: to.Port})
	default: // a loopback name such as localhost: the probe resolves it through /etc/hosts
		specs = append(specs, probe.Spec{Kind: probe.SpecTCP, Host: to.Host, Port: to.Port})
	}
	if to.Class != evidence.TargetName {
		return specs
	}
	n := 0
	for _, m := range view.Destinations().Elsewhere {
		for _, a := range m.C.Addrs() {
			if n == maxMetadataIPs {
				return specs
			}
			specs = append(specs, probe.Spec{Kind: probe.SpecTCP, Host: a.String(), Port: to.Port, Via: evidence.ViaMetadata})
			n++
		}
	}
	return specs
}

// destinationDown says why probing is pointless: every container the name
// refers to on the source's networks is stopped (WR008's case). A stopped
// match elsewhere doesn't stop the probes: the name may well mean something
// else, and the probes show what. It returns "" when probing makes sense.
func (r *run) destinationDown(view evidence.View) string {
	dests := view.Destinations().OnSourceNets
	if len(dests) == 0 {
		return ""
	}
	var states []string
	for _, m := range dests {
		if m.C.Running() {
			return ""
		}
		states = append(states, fmt.Sprintf("%s is %s", m.C.DisplayName(), m.C.State))
	}
	return strings.Join(states, ", ") + ": there is no address to connect to"
}
