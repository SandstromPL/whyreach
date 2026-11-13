package engine

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/target"
)

// ProbeResult is one check run on its own (the run_probe tool): the
// evidence it produced, usually one record, or a lookup and the connects
// that used it.
type ProbeResult struct {
	Kind        string              `json:"kind"`
	From        string              `json:"from"`
	Target      string              `json:"target,omitempty"`
	Evidence    []evidence.Evidence `json:"evidence"`
	SideEffects []string            `json:"side_effects"`
	ChangesMade bool                `json:"changes_made"` // always false
}

// Probe runs one check from the source's network namespace: in-process for
// the host, through the probe executor (tier 2b) for a container's DNS and
// TCP, and through /proc for a container's listeners on Linux Docker
// Engine. A source that can't be found is an error; a check that can't run
// is a record with that status.
func (e *Engine) Probe(ctx context.Context, from target.From, spec probe.Spec) (*ProbeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, e.d.Deadline)
	defer cancel()
	ctx, effects := executor.WithSideEffects(ctx)
	res := &ProbeResult{Kind: spec.Kind, From: from.String(), Target: specTarget(spec)}

	var evs []evidence.Evidence
	if from.Kind == target.FromHost {
		ex := e.d.Host
		if spec.Kind == probe.SpecListeners {
			r := &run{e: e}
			evs = []evidence.Evidence{r.hostListeners()}
		} else {
			ctx := executor.WithKnownNames(ctx, func(ctx context.Context, name string) bool { return e.knownName(ctx, nil, name) })
			out, err := ex.Run(ctx, evidence.Host(), []probe.Spec{spec})
			if err != nil {
				e.d.Logger.Warn("probe failed", "executor", ex.Name(), "err", err)
			}
			evs = out
		}
	} else {
		var err error
		if evs, err = e.probeContainer(ctx, from, spec); err != nil {
			return nil, err
		}
	}
	var s evidence.Store
	for i := range evs {
		if evs[i].ObservedAt.IsZero() {
			evs[i].ObservedAt = time.Now()
		}
	}
	s.Add(evs...)
	res.Evidence = s.Finalize()
	res.SideEffects = effects.List()
	if res.SideEffects == nil {
		res.SideEffects = []string{}
	}
	return res, nil
}

func (e *Engine) probeContainer(ctx context.Context, from target.From, spec probe.Spec) ([]evidence.Evidence, error) {
	if e.d.Docker == nil {
		return nil, &Error{Code: evidence.CodeDockerUnavailable, Message: "checks from a container need the Docker API: " + errText(e.d.DockerErr)}
	}
	r := &run{e: e, docker: e.d.Docker, from: from, timing: map[string]time.Duration{}}
	v, err := negotiate(ctx, r.docker)
	if err != nil {
		return nil, &Error{Code: evidence.CodeDockerUnavailable, Message: err.Error()}
	}
	r.version = v
	r.linux = runtime.GOOS == "linux" && v.Os == "linux" && !v.Desktop()
	src, err := r.findSource(ctx)
	if err != nil {
		return nil, err
	}
	stamp := evidence.InContainer(src)
	owner := src
	if ref := src.NetnsOwner(); ref != "" {
		if owner, _, err = r.inspectEv(ctx, ref); err != nil {
			return executor.Failed(stamp, "", []probe.Spec{spec}, evidence.StatusFailed, &evidence.Error{
				Code: evidence.CodeNotFound, Message: fmt.Sprintf("%s uses the network namespace of %s, whose metadata could not be read: %v", src.DisplayName(), evidence.ShortID(ref), err),
			}), nil
		}
	}
	restamp := func(evs []evidence.Evidence) []evidence.Evidence {
		for i := range evs {
			netns, exe := evs[i].Context.NetnsID, evs[i].Context.Executor
			evs[i].Context = stamp
			evs[i].Context.NetnsID, evs[i].Context.Executor = netns, exe
		}
		return evs
	}
	if spec.Kind == probe.SpecListeners && r.linux {
		ev := r.containerListeners(ctx, owner)
		if owner.HostNetwork() {
			ev = r.hostListeners()
		}
		return restamp([]evidence.Evidence{ev}), nil
	}
	if !owner.Running() {
		return executor.Failed(stamp, "", []probe.Spec{spec}, evidence.StatusFailed, &evidence.Error{
			Code: evidence.CodeNotFound, Message: fmt.Sprintf("%s is %s, so nothing can be tested from its network namespace; start it first", owner.DisplayName(), owner.State),
		}), nil
	}
	// The same executor as a diagnosis's probe stage. A host-network
	// container shares the host's network namespace, but its /etc/hosts and
	// /etc/resolv.conf are its own (extra_hosts, dns), so its lookups are
	// made from inside it too, not with whyreach's files.
	ex := r.containerExecutor()
	if ex == nil {
		return executor.Failed(stamp, evidence.ExecutorProbeContainer, []probe.Spec{spec}, evidence.StatusPermissionDenied, &evidence.Error{
			Code: evidence.CodePermissionDenied, Message: executor.ProbeContainersOff,
		}), nil
	}
	ctx = executor.WithKnownNames(ctx, func(ctx context.Context, name string) bool { return e.knownName(ctx, &owner, name) })
	evs, err := ex.Run(ctx, evidence.InContainer(owner), []probe.Spec{spec})
	if err != nil {
		e.d.Logger.Warn("probe failed", "executor", ex.Name(), "err", err)
	}
	return restamp(evs), nil
}

// knownName reports whether Docker's metadata knows name, for a check run
// on its own (INITIAL.md §10 Q11): a container name or Compose service in
// the container list, or an alias or DNS name of a container on owner's
// networks (only an inspect shows those; at most maxPeers are read). The
// policy asks only about outside names it would otherwise hold back, so a
// check that needs no answer reads nothing.
func (e *Engine) knownName(ctx context.Context, owner *evidence.Container, name string) bool {
	if e.d.Docker == nil {
		return false
	}
	lctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	list, err := e.d.Docker.ListContainers(lctx, true)
	cancel()
	if err != nil {
		e.d.Logger.Warn("could not list containers to look for a name", "err", err)
		return false
	}
	var srcNets []string
	if owner != nil && !owner.HostNetwork() {
		srcNets = owner.NetworkNames()
	}
	var peers []docker.Summary
	for _, s := range list {
		if nameMatches(s, name) {
			return true
		}
		for _, n := range s.Networks() {
			if prefix, ok := cutNetwork(name, n); ok && evidence.UserDefined(n) && nameMatches(s, prefix) {
				return true // <container>.<network>, which Docker's DNS answers too
			}
		}
		if shares(s.Networks(), srcNets) && len(peers) < maxPeers {
			peers = append(peers, s)
		}
	}
	for _, s := range peers {
		if ctx.Err() != nil {
			return false
		}
		ictx, cancel := context.WithTimeout(ctx, dockerTimeout)
		c, err := e.d.Docker.InspectContainer(ictx, s.ID)
		cancel()
		if err == nil && (c.Matches(name) || answersQualified(c, name)) {
			return true
		}
	}
	return false
}

func specTarget(s probe.Spec) string {
	switch s.Kind {
	case probe.SpecListeners:
		return ""
	case probe.SpecDNS:
		return s.Host
	default:
		return specSubject(s)
	}
}

// specSubject is the spec's target as host:port.
func specSubject(s probe.Spec) string {
	t := evidence.Target{Host: s.Host, Port: s.Port}
	_, t.Addr = evidence.ClassifyHost(s.Host)
	return t.String()
}
