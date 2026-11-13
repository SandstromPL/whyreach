package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// TestNetnsExecutorIsGuarded: as root, container checks go through the
// netns executor, under the same allowlist and rate limit, with no Docker
// write, no tier 2b and so no request for probe containers.
func TestNetnsExecutorIsGuarded(t *testing.T) {
	netns, probes, host := &recorder{}, &recorder{}, &recorder{}
	p, err := New(Deps{
		Settings: Settings{Docker: true, Allow: []string{"loopback", "docker"}, RatePerMinute: 30},
		Docker:   fakeDocker{}, Listeners: fakeDocker{}, Host: host,
		NewProbe: func() (executor.Executor, error) { return probes, nil },
		Netns:    netns,
		Audit:    NewAudit(filepath.Join(t.TempDir(), "audit.jsonl")),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	d, err := p.Diagnose(ctx, DiagnoseArgs{From: "container:shop-worker-1", To: "api:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if netns.count() != 1 || probes.count() != 0 {
		t.Fatalf("netns ran %d batches, probe containers %d; want the netns executor alone", netns.count(), probes.count())
	}
	if d.Verdict != "no_problem_reproduced" || len(d.SideEffects) != 0 || NeedsProbeContainers(d.Evidence) {
		t.Errorf("verdict %s, side effects %v, needs probe containers %v", d.Verdict, d.SideEffects, NeedsProbeContainers(d.Evidence))
	}
	if w := netns.where[0]; w.Kind != evidence.ContextContainer || w.Container != evidence.ShortID(workerID) {
		t.Errorf("entered %+v, want worker's namespace", w)
	}
	if lim := netns.lims[0]; !lim.Restricted {
		t.Error("the netns executor must get the allowlist for dial time")
	}

	// A literal outside the allowlist is refused before the executor runs.
	res, err := p.Probe(ctx, ProbeArgs{Kind: "tcp", Target: "192.168.1.50:5432", From: "container:shop-worker-1"})
	if err != nil {
		t.Fatal(err)
	}
	ev := res.Evidence[0]
	if netns.count() != 1 || ev.Status != evidence.StatusSkipped || !strings.Contains(ev.Err.Message, "allowlist") ||
		ev.Context.Executor != evidence.ExecutorNetns {
		t.Errorf("want a refusal by the policy, stamped netns: %d runs, %+v", netns.count(), ev)
	}

	in, err := p.Inspect(ctx, "host")
	if err != nil {
		t.Fatal(err)
	}
	if got := in.Host.Permissions.Netns; got != "on (root)" {
		t.Errorf("permissions netns = %q, want on (root)", got)
	}
}

// TestNetnsExecutorNeedsDocker: it finds containers through the Docker API,
// so with Docker off there is none.
func TestNetnsExecutorNeedsDocker(t *testing.T) {
	p, err := New(Deps{Settings: Settings{Docker: false}, Docker: fakeDocker{}, Listeners: fakeDocker{}, Netns: &recorder{}})
	if err != nil {
		t.Fatal(err)
	}
	if p.d.Netns != nil {
		t.Error("with Docker off, the netns executor must be dropped")
	}
	in, err := p.Inspect(context.Background(), "host")
	if err != nil {
		t.Fatal(err)
	}
	if got := in.Host.Permissions.Netns; got != "off" {
		t.Errorf("permissions netns = %q, want off", got)
	}
}

// cannotEnter is a netns executor that can't get into any namespace, as
// when Docker's PIDs aren't this machine's.
type cannotEnter struct{ runs int }

func (c *cannotEnter) Name() string { return evidence.ExecutorNetns }

func (c *cannotEnter) Run(_ context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	c.runs++
	err := fmt.Errorf("%w: /proc/42/cgroup does not name container %s", executor.ErrCannotEnter, where.Container)
	return executor.Failed(where, c.Name(), specs, evidence.StatusFailed, &evidence.Error{Code: evidence.CodeNotFound, Message: err.Error()}), err
}

// TestNetnsFallsBackToProbeContainersOnlyWhenAllowed: when the netns
// executor can't enter, a probe container runs the checks if the user
// allows them, and says so; otherwise the records say why and become a gap
// with advice.
func TestNetnsFallsBackToProbeContainersOnlyWhenAllowed(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		netns, probes := &cannotEnter{}, &recorder{}
		p, err := New(Deps{
			Settings: Settings{Docker: true, ProbeContainers: allowed, RatePerMinute: 30, ConfigPath: "/cfg/config.toml"},
			Docker:   fakeDocker{}, Listeners: fakeDocker{}, Host: &recorder{},
			NewProbe: func() (executor.Executor, error) { return probes, nil },
			Netns:    netns,
		})
		if err != nil {
			t.Fatal(err)
		}
		d, err := p.Diagnose(context.Background(), DiagnoseArgs{From: "container:shop-worker-1", To: "api:8080"})
		if err != nil {
			t.Fatal(err)
		}
		if netns.runs != 1 {
			t.Fatalf("allowed %v: the netns executor ran %d times, want 1", allowed, netns.runs)
		}
		if !allowed {
			if probes.count() != 0 {
				t.Error("without tier 2b no probe container may run")
			}
			if len(d.Gaps) == 0 || !strings.Contains(d.Gaps[0].HowToEnable, "probe_containers = true") {
				t.Errorf("want a gap that says how to let a probe container run them: %+v", d.Gaps)
			}
			if !NeedsProbeContainers(d.Evidence) {
				t.Error("a probe container would change the answer, so the MCP server must be able to ask for one")
			}
			continue
		}
		if NeedsProbeContainers(d.Evidence) {
			t.Error("a probe container already ran: nothing to ask for")
		}
		if probes.count() != 1 || d.Verdict != "no_problem_reproduced" {
			t.Fatalf("with tier 2b a probe container must run the checks: %d runs, verdict %s", probes.count(), d.Verdict)
		}
		for _, ev := range d.Evidence {
			if ev.Kind == evidence.KindTCP && !slices.ContainsFunc(ev.Limitations, func(l string) bool { return strings.Contains(l, "probe container") }) {
				t.Errorf("the record must say a probe container ran it: %+v", ev.Limitations)
			}
		}
	}
}

// TestNetnsOffInTheConfig: netns = false keeps tier 3 off even as root, and
// the audit log records whether it was on.
func TestNetnsOffInTheConfig(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, off := range []bool{false, true} {
		netns := &recorder{}
		p, err := New(Deps{
			Settings: Settings{Docker: true, NetnsOff: off, RatePerMinute: 30},
			Docker:   fakeDocker{}, Listeners: fakeDocker{}, Host: &recorder{}, Netns: netns, Audit: NewAudit(audit),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Diagnose(context.Background(), DiagnoseArgs{From: "container:shop-worker-1", To: "api:8080"}); err != nil {
			t.Fatal(err)
		}
		if ran := netns.count() == 1; ran == off {
			t.Errorf("netns off %v: the netns executor ran %v", off, ran)
		}
	}
	es := entries(t, audit)
	if len(es) != 2 || !es[0].Netns || es[1].Netns {
		t.Errorf("audit netns = %v, %v; want true, then false", es[0].Netns, es[1].Netns)
	}
}
