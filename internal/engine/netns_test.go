package engine

import (
	"context"
	"slices"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/target"
)

// TestNetnsExecutorReplacesProbeContainers: with the netns executor (root),
// container checks enter the namespace on a Linux Docker Engine, whatever
// tier 2b says; on Docker Desktop, whose PIDs live in a VM, they don't, and
// the destination's listeners are read in a probe container too.
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
			// Listener batches: on Docker Desktop, api's sockets are read in
			// a probe container joined to api; elsewhere through /proc.
			var probes, listeners [][]probe.Spec
			var listenWhere []evidence.ContextRef
			for i, b := range want.ran {
				if len(b) == 1 && b[0].Kind == probe.SpecListeners {
					listeners = append(listeners, b)
					listenWhere = append(listenWhere, want.where[i])
					continue
				}
				probes = append(probes, b)
			}
			wantListeners := 0
			if tt.desktop {
				wantListeners = 1
			}
			if len(probes) != 2 || len(listeners) != wantListeners || len(other.ran) != 0 {
				t.Fatalf("%s ran %d probe and %d listener batches, %s %d; want 2, %d and 0", want.name, len(probes), len(listeners), other.name, len(other.ran), wantListeners)
			}
			for _, where := range listenWhere {
				if where.Container != evidence.ShortID(w.containers[1].ID) {
					t.Errorf("listeners read in %+v, want api's namespace", where)
				}
			}
			want.where = slices.DeleteFunc(slices.Clone(want.where), func(c evidence.ContextRef) bool { return slices.Contains(listenWhere, c) })
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

// TestHostNetworkSourceUsesTheContainerExecutor: a host-network container
// shares the host's namespace but has its own /etc/hosts and resolv.conf,
// so run_probe checks from it the way a diagnosis does, never with
// whyreach's own files through the host executor.
func TestHostNetworkSourceUsesTheContainerExecutor(t *testing.T) {
	from, err := target.ParseFrom("container:shop-hostnet-1")
	if err != nil {
		t.Fatal(err)
	}
	to, err := target.ParseTo("api:8080")
	if err != nil {
		t.Fatal(err)
	}
	for _, withNetns := range []bool{true, false} {
		w := shopWorld()
		hn := ctr("h", "shop-hostnet-1", "shop", "hostnet", "host", "172.22.0.9", 300)
		hn.NetworkMode, hn.Networks = "host", nil
		w.containers = append(w.containers, hn)
		netns := &scripted{w: w, name: evidence.ExecutorNetns}
		pc := &scripted{w: w, name: evidence.ExecutorProbeContainer}
		host := &scripted{w: w, name: evidence.ExecutorHost}
		deps := Deps{Docker: w, Listeners: w, Host: host, Probe: pc}
		want := pc
		if withNetns {
			deps.Netns, want = netns, netns
		}
		e := New(deps)
		if _, err := e.Probe(context.Background(), from, probe.Spec{Kind: probe.SpecDNS, Host: "api"}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Diagnose(context.Background(), from, to); err != nil {
			t.Fatal(err)
		}
		if len(want.ran) != 2 || len(host.ran) != 0 {
			t.Errorf("netns %v: %s ran %d batches (want 2: run_probe and the diagnosis), the host executor %d (want 0)",
				withNetns, want.name, len(want.ran), len(host.ran))
		}
	}
}
