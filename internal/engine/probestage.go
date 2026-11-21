package engine

import (
	"context"
	"fmt"
	"slices"
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
		ex, where, stamp = r.e.d.Host, r.host(), r.host()
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
		ex = r.containerExecutor()
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

	// Names Docker's metadata knows carry nothing an agent chose: the
	// policy lets their lookups through without asking (INITIAL.md §10 Q11).
	ctx = executor.WithKnownNames(ctx, func(_ context.Context, name string) bool { return dockerKnows(view.Containers(), name) })
	evs, err := ex.Run(ctx, where, specs)
	if err != nil {
		r.e.d.Logger.Warn("probe batch failed", "executor", ex.Name(), "err", err)
	}
	r.store.Add(restamp(evs, stamp)...)
	return nil
}

// restamp files the records an executor returned under the context to (the
// source's, which may share the netns the checks ran in, or the host's),
// keeping the network namespace and the executor the executor stamped, and
// fills in a missing observation time.
func restamp(evs []evidence.Evidence, to evidence.ContextRef) []evidence.Evidence {
	for i := range evs {
		netns, exe := evs[i].Context.NetnsID, evs[i].Context.Executor
		evs[i].Context = to
		evs[i].Context.NetnsID, evs[i].Context.Executor = netns, exe
		if evs[i].ObservedAt.IsZero() {
			evs[i].ObservedAt = time.Now()
		}
	}
	return evs
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
	dests := view.Destinations()
	if len(dests.All()) == 0 && dests.Host == nil && dests.HostsEntry == "" {
		// The name matches no container. A lookup of a name Docker's DNS
		// certainly knows, the source's own, shows whether internal names
		// resolve (WR005, WR020); it never leaves the host.
		if owner, ok := view.NetnsOwner(); ok && len(owner.C.UserDefinedNetworks()) > 0 && !strings.EqualFold(owner.C.Name, to.Host) {
			specs = append(specs, probe.Spec{Kind: probe.SpecDNS, Host: owner.C.Name})
		}
	}
	n := 0
	for _, m := range dests.Elsewhere {
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

// dockerKnows reports whether one of cs answers to name in Docker's
// metadata: its container name, Compose service, an alias or a DNS name,
// or one of those qualified with a network it is on (api.shop_default),
// which Docker's DNS answers too.
func dockerKnows(cs []evidence.ContainerEv, name string) bool {
	for _, c := range cs {
		if c.C.Matches(name) || answersQualified(c.C, name) {
			return true
		}
	}
	return false
}

// answersQualified reports a name of the form <name>.<network> that c
// answers to on that network.
func answersQualified(c evidence.Container, name string) bool {
	for _, a := range c.Networks {
		if prefix, ok := cutNetwork(name, a.Network); ok && slices.Contains(c.AnswersTo(prefix), a.Network) {
			return true
		}
	}
	return false
}

// cutNetwork splits <name>.<network> into name, ignoring case and a
// trailing dot.
func cutNetwork(qualified, network string) (string, bool) {
	q := strings.TrimSuffix(strings.ToLower(qualified), ".")
	prefix, ok := strings.CutSuffix(q, "."+strings.ToLower(network))
	return prefix, ok && prefix != ""
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
