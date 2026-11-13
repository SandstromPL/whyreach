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
	"slices"
	"sync"
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

// Run executes specs in-process, within the limits in ctx (probe.WithLimits).
func (h *Host) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	env := h.Env
	env.Limits = probe.LimitsFrom(ctx)
	evs := probe.Run(ctx, env, specs)
	netns := probe.SelfNetnsID()
	for i := range evs {
		evs[i].Context = where
		evs[i].Context.Executor = evidence.ExecutorHost
		evs[i].Context.NetnsID = netns
	}
	return evs, nil
}

// HostHidden is the message of host-side records whyreach can't make
// because it runs in a container without the host's network namespace
// (no --network host): its own namespace would pass for the host's.
const HostHidden = "whyreach runs in a container without the host's network namespace (docker run --network host), so the host's interfaces, listening sockets and connections can't be seen from here"

// HostHiddenAdvice says how to let whyreach's image see the host. It gives
// whyreach the host's network and processes, so it is the user's to do.
const HostHiddenAdvice = "Letting whyreach's image see the host is the user's decision, not an agent's: run it with --network host, and --pid host for containers' listening sockets (docker run --rm -i --network host --pid host -v /var/run/docker.sock:/var/run/docker.sock IMAGE …)"

// PIDsHidden is the message of a container's listeners whyreach can't
// read because it runs in a container without the host's PIDs (no --pid
// host): Docker's PID for the container isn't one it can see.
const PIDsHidden = "whyreach runs in a container without the host's PIDs (docker run --pid host), so it can't read containers' listening sockets through /proc/<pid>/net"

// PIDsHiddenAdvice says how to let whyreach's image read containers'
// listening sockets. It shows whyreach the host's processes, so it is the
// user's to do.
const PIDsHiddenAdvice = "Letting whyreach's image see containers' processes is the user's decision, not an agent's: run it with --pid host, and --network host for the host's side (docker run --rm -i --network host --pid host -v /var/run/docker.sock:/var/run/docker.sock IMAGE …)"

// Unsupported answers every check with an unsupported record that says
// why: an executor for a place whyreach can't reach.
type Unsupported struct {
	Executor string // the name it stands in for
	Reason   string
}

// Name is the executor it stands in for.
func (u Unsupported) Name() string { return u.Executor }

// Run returns one unsupported record per spec.
func (u Unsupported) Run(_ context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	return Failed(where, u.Executor, specs, evidence.StatusUnsupported, &evidence.Error{Code: evidence.CodeUnsupported, Message: u.Reason}), nil
}

// ProbeContainersOff is the message of probe records that could not run
// because probe containers (tier 2b) are off; gaps recognise it and say how
// to turn them on.
const ProbeContainersOff = "probe containers are off (tier 2b)"

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

// KnownNames reports whether Docker's own metadata knows name: a container
// name, Compose service, network alias or DNS name. A lookup of such a
// name carries nothing an agent chose, so it needs no approval (INITIAL.md
// §10 Q11). The engine puts one in the context of each batch, from the
// metadata it has; the policy asks it only about outside names it would
// otherwise hold back.
type KnownNames func(ctx context.Context, name string) bool

type knownNamesKey struct{}

// WithKnownNames returns a context whose batches use k.
func WithKnownNames(ctx context.Context, k KnownNames) context.Context {
	return context.WithValue(ctx, knownNamesKey{}, k)
}

// KnownNamesFrom returns the KnownNames set with WithKnownNames; without
// one, Docker knows no name.
func KnownNamesFrom(ctx context.Context) KnownNames {
	if k, ok := ctx.Value(knownNamesKey{}).(KnownNames); ok && k != nil {
		return k
	}
	return func(context.Context, string) bool { return false }
}

// SideEffects collects the Docker writes made for one diagnosis
// (INITIAL.md §3.3). The engine puts one in the context of each diagnosis,
// so a long-lived process never mixes up the writes of different ones.
type SideEffects struct {
	mu   sync.Mutex
	list []string
}

// List returns the writes in the order they happened.
func (s *SideEffects) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.list)
}

type sideEffectsKey struct{}

// WithSideEffects returns a context that collects the side effects of the
// work done under it.
func WithSideEffects(ctx context.Context) (context.Context, *SideEffects) {
	s := &SideEffects{}
	return context.WithValue(ctx, sideEffectsKey{}, s), s
}

// RecordSideEffect notes a Docker write in the diagnosis that ctx belongs to.
func RecordSideEffect(ctx context.Context, effect string) {
	if s, ok := ctx.Value(sideEffectsKey{}).(*SideEffects); ok {
		s.mu.Lock()
		s.list = append(s.list, effect)
		s.mu.Unlock()
	}
}
