// Package engine runs a diagnosis as a staged pipeline (INITIAL.md §4.4):
//
//	resolve → collect → gate → probe → evaluate → compose
//
// It is the only package that orchestrates I/O. It parses nothing raw: the
// Docker client, the listener reader and the executors hand it typed
// evidence, and the rules turn that evidence into findings.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/rules"
	"github.com/SandstromPL/whyreach/internal/target"
)

// Timeouts (INITIAL.md §4.4).
const (
	DefaultDeadline = 15 * time.Second // whole diagnosis
	dockerTimeout   = 3 * time.Second  // one Docker API call
	collectParallel = 4                // concurrent collectors
)

// Bounds on what one diagnosis reads.
const (
	maxPeers        = 64 // other containers on the source's networks inspected for aliases and listeners
	maxMatches      = 16 // containers that match the target by name or address
	maxDestinations = 4  // destination containers whose listeners are read
	maxMetadataIPs  = 2  // destination addresses from metadata that are also probed
)

// Docker is the metadata client the engine needs.
type Docker interface {
	Negotiate(ctx context.Context) (docker.Version, error)
	ListContainers(ctx context.Context, all bool, labels ...string) ([]docker.Summary, error)
	InspectContainer(ctx context.Context, idOrName string) (evidence.Container, error)
	ListNetworks(ctx context.Context) ([]docker.Network, error)
	InspectNetwork(ctx context.Context, idOrName string) (docker.Network, error)
	Endpoint() string
	APIVersion() string
}

// Listeners reads listening sockets from the host side (ADR 0001).
type Listeners interface {
	Host() ([]evidence.Socket, error)
	Container(pid int, id string) ([]evidence.Socket, error)
}

// Deps are the engine's collaborators. Docker is nil when the Docker API is
// unavailable or turned off (DockerErr says why). Probe runs checks inside
// containers; the policy package hands the engine a guarded one that
// answers with permission-denied records while tier 2b is off, and nil
// means the same. Interfaces reads the host's addresses; nil means
// unsupported.
type Deps struct {
	Docker     Docker
	DockerErr  error
	Host       executor.Executor
	Probe      executor.Executor
	Listeners  Listeners
	Interfaces func() (evidence.HostAddrs, error)
	ConfigPath string // named in the advice for enabling tier 2b
	Deadline   time.Duration
	Logger     *slog.Logger
}

// Engine diagnoses connections.
type Engine struct {
	d Deps
}

// New returns an engine.
func New(d Deps) *Engine {
	if d.Deadline <= 0 {
		d.Deadline = DefaultDeadline
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	return &Engine{d: d}
}

// Error is a diagnosis that could not start: the question itself is wrong.
type Error struct {
	Code    string // evidence.Code*: invalid_argument, not_found, policy_denied, internal
	Message string
}

func (e *Error) Error() string { return e.Message }

// IsUsage reports an error the user can fix by changing the arguments.
func IsUsage(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case evidence.CodeInvalidArgument, evidence.CodeNotFound, evidence.CodePolicyDenied:
			return true
		}
	}
	var te *target.Error
	return errors.As(err, &te)
}

// run is the state of one diagnosis.
type run struct {
	e       *Engine
	docker  Docker // nil once Docker turns out to be unreachable
	store   evidence.Store
	q       evidence.Question
	from    target.From
	version docker.Version
	linux   bool // the daemon is Linux Docker Engine on this host: /proc/<pid> works
	gaps    []Gap
	timing  map[string]time.Duration
	// metadataIncomplete is set when some containers' metadata could not be
	// read or was skipped: "no container has that name" can't be claimed then.
	metadataIncomplete bool
}

// Diagnose answers "why can't from reach to?". It returns an error only for
// a question that can't be asked (an unknown source container, an invalid
// target); everything else, missing evidence included, is part of the
// diagnosis.
func (e *Engine) Diagnose(ctx context.Context, from target.From, to evidence.Target) (*Diagnosis, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, e.d.Deadline)
	defer cancel()
	ctx, effects := executor.WithSideEffects(ctx)

	r := &run{e: e, docker: e.d.Docker, from: from, timing: map[string]time.Duration{}}
	r.q = evidence.Question{From: evidence.Source{Kind: evidence.SourceHost, Ref: from.String()}, To: to}
	if from.Kind != target.FromHost {
		r.q.From.Kind = evidence.SourceContainer
	}

	stage := func(name string, f func(context.Context) error) error {
		t := time.Now()
		err := f(ctx)
		r.timing[name] = time.Since(t)
		return err
	}
	if err := stage("resolve", r.resolve); err != nil {
		return nil, err
	}
	_ = stage("collect", r.collect)
	_ = stage("probe", r.probe)

	t := time.Now()
	items := r.store.Finalize()
	view := evidence.NewView(r.q, items)
	var findings []rules.Finding
	for _, rule := range rules.All() {
		if len(rules.Missing(rule, view)) > 0 {
			continue // gaps come from the missing evidence's own records
		}
		findings = append(findings, rule.Evaluate(view)...)
	}
	ranked := rules.Rank(findings)
	r.timing["evaluate"] = time.Since(t)

	d := r.compose(view, ranked, effects.List())
	d.ID = newID(start)
	d.Timing = Timing{StartedAt: start.UTC(), TotalMS: evidence.Millis(time.Since(start)), Stages: map[string]float64{}}
	for k, v := range r.timing {
		d.Timing.Stages[k] = evidence.Millis(v)
	}
	if ctx.Err() != nil {
		d.Timing.DeadlineHit = true
	}
	return d, nil
}

func newID(t time.Time) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return "dg-" + t.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}
