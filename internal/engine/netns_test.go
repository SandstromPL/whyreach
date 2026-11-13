package engine

import (
	"context"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/target"
)

// TestNetnsExecutorReplacesProbeContainers: with the netns executor (root),
// container checks enter the namespace on a Linux Docker Engine, whatever
// tier 2b says; on Docker Desktop, whose PIDs live in a VM, they don't.
func TestNetnsExecutorReplacesProbeContainers(t *testing.T) {
	tests := []struct {
		name      string
		desktop   bool
		probes    bool
		wantNetns bool
	}{
		{name: "Linux engine, probe containers off", wantNetns: true},
		{name: "Linux engine, probe containers on", probes: true, wantNetns: true},
		{name: "Docker Desktop", desktop: true, probes: true},
	}
	from, err := target.ParseFrom("container:shop-worker-1")
	if err != nil {
		t.Fatal(err)
	}
	to, err := target.ParseTo("api:8080")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := shopWorld()
			w.desktop = tt.desktop
			netns := &scripted{w: w, name: evidence.ExecutorNetns}
			pc := &scripted{w: w, name: evidence.ExecutorProbeContainer, effect: []string{"ephemeral probe container wr-probe-test (removed)"}}
			deps := Deps{Docker: w, Listeners: w, Host: &scripted{w: w, name: evidence.ExecutorHost}, Netns: netns}
			if tt.probes {
				deps.Probe = pc
			}
			e := New(deps)
			d, err := e.Diagnose(context.Background(), from, to)
			if err != nil {
				t.Fatal(err)
			}
			res, err := e.Probe(context.Background(), from, probe.Spec{Kind: probe.SpecDNS, Host: "api"})
			if err != nil {
				t.Fatal(err)
			}
			want, other := netns, pc
			if !tt.wantNetns {
				want, other = pc, netns
			}
			if len(want.ran) != 2 || len(other.ran) != 0 {
				t.Fatalf("%s ran %d batches and %s %d; want 2 and 0", want.name, len(want.ran), other.name, len(other.ran))
			}
			if tt.wantNetns {
				if len(d.SideEffects) != 0 || len(res.SideEffects) != 0 {
					t.Errorf("the netns executor writes nothing to Docker: %v %v", d.SideEffects, res.SideEffects)
				}
				if d.Verdict != VerdictNoProblem {
					t.Errorf("verdict %s, want %s", d.Verdict, VerdictNoProblem)
				}
			}
			for _, where := range want.where {
				if where.Container != evidence.ShortID(w.containers[0].ID) || where.Name != "worker" {
					t.Errorf("entered %+v, want worker's namespace", where)
				}
			}
			for _, ev := range append(d.Evidence, res.Evidence...) {
				if ev.Kind != evidence.KindDNS && ev.Kind != evidence.KindTCP {
					continue
				}
				if ev.Context.Executor != want.name || ev.Context.Name != "worker" {
					t.Errorf("%s %s: context %+v, want %s in worker", ev.Kind, ev.Subject, ev.Context, want.name)
				}
			}
		})
	}
}
