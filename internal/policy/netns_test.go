package policy

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
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
