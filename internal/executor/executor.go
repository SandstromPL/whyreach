// Package executor runs probes inside a network namespace (INITIAL.md §4.7).
// It decides where a probe runs, never what its result means.
//
//   - Host runs probes in-process, in whyreach's own network namespace.
//   - ProbeContainer runs them in a short-lived hardened container that joins
//     the target container's network namespace (tier 2b, off by default).
//
// Neither ever uses docker exec.
package executor

import (
	"context"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// Executor runs a batch of probe specs inside where's network namespace.
// It always returns one record per check it was asked for; when it could not
// run the batch at all, those records carry the failure status and err says
// why.
type Executor interface {
	Name() string
	Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error)
}

// Host runs probes in whyreach's own network namespace.
type Host struct {
	Env probe.Env
}

// NewHost returns a host executor that reads the host's resolver files.
func NewHost() *Host { return &Host{Env: probe.DefaultEnv()} }

// Name is "host".
func (h *Host) Name() string { return evidence.ExecutorHost }

// Run executes specs in-process.
func (h *Host) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	evs := probe.Run(ctx, h.Env, specs)
	netns := probe.SelfNetnsID()
	for i := range evs {
		evs[i].Context = where
		evs[i].Context.Executor = evidence.ExecutorHost
		evs[i].Context.NetnsID = netns
	}
	return evs, nil
}

// Failed returns one record per spec that says the batch could not run.
func Failed(where evidence.ContextRef, executor string, specs []probe.Spec, status evidence.Status, e *evidence.Error) []evidence.Evidence {
	ctx := where
	ctx.Executor = executor
	out := make([]evidence.Evidence, 0, len(specs))
	for _, s := range specs {
		out = append(out, evidence.Evidence{
			Kind: specKind(s), Context: ctx, Subject: specSubject(s), Status: status,
			ObservedAt: time.Now(), Err: e,
		})
	}
	return out
}

func specKind(s probe.Spec) evidence.Kind {
	switch s.Kind {
	case probe.SpecDNS:
		return evidence.KindDNS
	case probe.SpecListeners:
		return evidence.KindListeners
	default:
		return evidence.KindTCP
	}
}

func specSubject(s probe.Spec) string {
	switch s.Kind {
	case probe.SpecDNS:
		return s.Host
	case probe.SpecListeners:
		return "listeners"
	default:
		t := evidence.Target{Host: s.Host, Port: s.Port}
		_, t.Addr = evidence.ClassifyHost(s.Host)
		return t.String()
	}
}
