package engine

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/platform"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/target"
)

// watchedPIDs is a listener reader that records every /proc/<pid> read: on
// Docker Desktop's WSL integration, Docker's PIDs belong to Docker
// Desktop's VM, and a read would describe an unrelated process in the
// distro, so the engine must make none.
type watchedPIDs struct {
	*world
	mu   sync.Mutex
	pids []int
}

func (w *watchedPIDs) Container(pid int, id string) ([]evidence.Socket, error) {
	w.mu.Lock()
	w.pids = append(w.pids, pid)
	w.mu.Unlock()
	return w.world.Container(pid, id)
}

// Where whyreach runs, as platform.Detect would see it.
var (
	wslRoot   = platform.Info{OS: "linux", Arch: "amd64", WSL: true, Root: true, Netns: true, Openat2: true}
	linuxHost = platform.Info{OS: "linux", Arch: "amd64"}
)

type platformRun struct {
	d      *Diagnosis
	pids   *watchedPIDs
	probes *scripted
	netns  *scripted
}

// diagnoseOn runs a diagnosis with whyreach at info and the world's daemon,
// with the netns executor always offered (root) and probe containers when
// probes is set.
func diagnoseOn(t *testing.T, w *world, info platform.Info, probes bool, from, to string) platformRun {
	t.Helper()
	f, err := target.ParseFrom(from)
	if err != nil {
		t.Fatal(err)
	}
	tt, err := target.ParseTo(to)
	if err != nil {
		t.Fatal(err)
	}
	r := platformRun{
		pids:   &watchedPIDs{world: w},
		probes: &scripted{w: w, name: evidence.ExecutorProbeContainer, effect: []string{"ephemeral probe container wr-probe-test (removed)"}},
		netns:  &scripted{w: w, name: evidence.ExecutorNetns},
	}
	deps := Deps{Docker: w, Listeners: r.pids, Host: &scripted{w: w, name: evidence.ExecutorHost}, Netns: r.netns, Platform: info,
		ConfigPath: "/home/u/.config/whyreach/config.toml"}
	if probes {
		deps.Probe = r.probes
	}
	r.d, err = New(deps).Diagnose(context.Background(), f, tt)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func platformOf(t *testing.T, d *Diagnosis) evidence.Platform {
	t.Helper()
	p, ok := evidence.NewView(d.Question, d.Evidence).Platform()
	if !ok {
		t.Fatalf("no platform record in %+v", d.Evidence)
	}
	return p.P
}

// TestPlatformRecorded: every diagnosis records where whyreach and the
// containers run (INITIAL.md §3.7), classified from where whyreach runs and
// the daemon's answer.
func TestPlatformRecorded(t *testing.T) {
	tests := []struct {
		name    string
		info    platform.Info
		desktop bool
		want    evidence.Platform
	}{
		{"Docker Engine on a Linux host", linuxHost, false, evidence.Platform{Name: platform.LinuxEngine}},
		{"Docker Engine in a WSL2 distro", wslRoot, false, evidence.Platform{Name: platform.WSL2Engine, WSL: true}},
		{"Docker Desktop's WSL integration", wslRoot, true, evidence.Platform{Name: platform.WSL2Desktop, WSL: true, Desktop: true}},
		{"Docker Desktop for Linux", linuxHost, true, evidence.Platform{Name: platform.LinuxDesktop, Desktop: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := shopWorld()
			w.desktop = tt.desktop
			r := diagnoseOn(t, w, tt.info, true, "container:shop-worker-1", "api:8080")
			if got := platformOf(t, r.d); got != tt.want {
				t.Errorf("platform = %+v, want %+v", got, tt.want)
			}
		})
	}
	t.Run("without Docker", func(t *testing.T) {
		f, _ := target.ParseFrom("host")
		to, _ := target.ParseTo("localhost:8080")
		w := shopWorld()
		d, err := New(Deps{Listeners: w, Host: &scripted{w: w, name: evidence.ExecutorHost}, Platform: wslRoot}).Diagnose(context.Background(), f, to)
		if err != nil {
			t.Fatal(err)
		}
		if got := platformOf(t, d); got.Name != platform.Other || !got.WSL {
			t.Errorf("platform = %+v, want other, in WSL2", got)
		}
	})
}

// TestWSL2DesktopEntersNoLocalPID is the main correctness risk of Docker
// Desktop's WSL integration: Docker's PIDs belong to Docker Desktop's VM,
// so a /proc/<pid> read or a setns would reach an unrelated process in the
// distro. Neither happens, even as root: the listeners are read inside
// probe containers, and the DNS and TCP checks run in one, never through
// the netns executor.
func TestWSL2DesktopEntersNoLocalPID(t *testing.T) {
	w := shopWorld()
	w.desktop = true
	w.sockets[200] = []string{"127.0.0.1:8080", "127.0.0.11:40001"} // api listens on loopback only: WR002
	w.tcp["172.22.0.3:8080"] = evidence.OutcomeRefused
	r := diagnoseOn(t, w, wslRoot, true, "container:shop-worker-1", "api:8080")
	if len(r.pids.pids) != 0 {
		t.Errorf("read /proc/<pid> for PIDs %v: Docker Desktop's PIDs aren't this distro's", r.pids.pids)
	}
	if len(r.netns.ran) != 0 {
		t.Errorf("the netns executor ran %v: setns would enter an unrelated local process", r.netns.ran)
	}
	l, ok := evidence.NewView(r.d.Question, r.d.Evidence).ListenersIn(w.containers[1].ID)
	if !ok || l.Context.Executor != evidence.ExecutorProbeContainer {
		t.Fatalf("api's listeners = %+v, %v; want them read in a probe container", l, ok)
	}
	if p := r.d.Primary(); p == nil || p.RuleID != "WR002" || p.Confidence != "high" {
		t.Errorf("primary = %+v, want WR002 (high) from the probe container's listeners", p)
	}
}

// TestWSL2DesktopWithoutProbeContainers: with probe containers off, a
// container's listeners can't be read at all on Docker Desktop. The record
// says so, unsupported, and the gap says how to allow probe containers.
func TestWSL2DesktopWithoutProbeContainers(t *testing.T) {
	w := shopWorld()
	w.desktop = true
	r := diagnoseOn(t, w, wslRoot, false, "container:shop-worker-1", "api:8080")
	if len(r.pids.pids) != 0 || len(r.netns.ran) != 0 {
		t.Errorf("read PIDs %v, entered %v: Docker Desktop's PIDs aren't this distro's", r.pids.pids, r.netns.ran)
	}
	found := false
	for _, ev := range r.d.Evidence {
		if ev.Kind == evidence.KindListeners && ev.Context.Kind == evidence.ContextContainer {
			if ev.Status != evidence.StatusUnsupported || ev.Err == nil || ev.Err.Message != executor.PIDsElsewhere {
				t.Errorf("listeners record %+v, want unsupported with %q", ev, executor.PIDsElsewhere)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no listeners record for api")
	}
	gap := false
	for _, g := range r.d.Gaps {
		if g.Detail == executor.PIDsElsewhere {
			gap = strings.Contains(g.HowToEnable, "probe_containers = true") && strings.Contains(g.HowToEnable, "/home/u/.config/whyreach/config.toml")
		}
	}
	if !gap {
		t.Errorf("want a gap that says how to allow probe containers, got %+v", r.d.Gaps)
	}
}

// TestWSL2DesktopHostIsWindows: on Docker Desktop's WSL integration, a
// container reaching host.docker.internal reaches Windows, not the WSL2
// distro. whyreach's own listeners describe the WSL2 VM, so they aren't
// passed off as the host's: the record is unsupported, WR012 stays quiet,
// and the gap says so.
func TestWSL2DesktopHostIsWindows(t *testing.T) {
	w := shopWorld()
	w.desktop = true
	w.host = []string{"127.0.0.1:5432"} // the WSL2 VM's own loopback listener
	r := diagnoseOn(t, w, wslRoot, true, "container:shop-worker-1", "host.docker.internal:5432")
	for _, f := range r.d.Findings {
		if f.RuleID == "WR012" || f.RuleID == "WR011" {
			t.Errorf("%s fired on Docker Desktop's WSL integration: %s", f.RuleID, f.Title)
		}
	}
	var hostL []evidence.Evidence
	for _, ev := range r.d.Evidence {
		if ev.Kind == evidence.KindListeners && ev.Context.Kind == evidence.ContextHost {
			hostL = append(hostL, ev)
		}
	}
	if len(hostL) != 1 || hostL[0].Status != evidence.StatusUnsupported || hostL[0].Err.Message != executor.HostNotHere {
		t.Fatalf("host listeners = %+v, want one unsupported record (%q)", hostL, executor.HostNotHere)
	}
	if !slices.ContainsFunc(r.d.Gaps, func(g Gap) bool {
		return g.Detail == executor.HostNotHere && g.HowToEnable == executor.HostNotHereAdvice+"."
	}) {
		t.Errorf("want the Windows-host gap, got %+v", r.d.Gaps)
	}
	// From the WSL2 VM itself, its own listeners are the source's: read.
	r = diagnoseOn(t, w, wslRoot, true, "host", "localhost:5432")
	if l, ok := evidence.NewView(r.d.Question, r.d.Evidence).HostListeners(); !ok || l.Context.Name != evidence.HostWSL {
		t.Errorf("from the WSL2 VM, its listeners = %+v, %v; want them read and named %q", l, ok, evidence.HostWSL)
	}
}

// TestWSL2EngineReadsPIDs: Docker Engine installed in the WSL2 distro runs
// its containers in the distro, so /proc/<pid> and setns work as on a
// Linux host. Host-side evidence is named the WSL2 VM.
func TestWSL2EngineReadsPIDs(t *testing.T) {
	w := shopWorld()
	w.host = []string{"127.0.0.1:5432"}
	r := diagnoseOn(t, w, wslRoot, false, "container:shop-worker-1", "api:8080")
	if len(r.pids.pids) == 0 {
		t.Error("no /proc/<pid> read: on wsl2-engine Docker's PIDs are the distro's")
	}
	if len(r.netns.ran) == 0 {
		t.Error("the netns executor didn't run as root on wsl2-engine")
	}
	r = diagnoseOn(t, w, wslRoot, false, "host", "localhost:5432")
	for _, ev := range r.d.Evidence {
		if ev.Context.Kind == evidence.ContextHost && ev.Context.Name != evidence.HostWSL {
			t.Errorf("%s %s: host context %+v, want it named %q", ev.Kind, ev.Subject, ev.Context, evidence.HostWSL)
		}
	}
	if !strings.Contains(factTexts(r.d), "the host's side here is the WSL2 VM, not Windows") {
		t.Errorf("no WSL2 fact in:\n%s", factTexts(r.d))
	}
	if !strings.Contains(factTexts(r.d), "in the WSL2 VM") {
		t.Errorf("listener facts don't name the WSL2 VM:\n%s", factTexts(r.d))
	}
}

// TestProbeListenersBounded: where each container's listeners take a probe
// container, a diagnosis reads at most maxProbeListeners, source and
// destinations first, and says what it skipped.
func TestProbeListenersBounded(t *testing.T) {
	w := shopWorld()
	w.desktop = true
	for i := range 8 {
		id := string(rune('c' + i))
		c := ctr(id, "shop-svc"+id+"-1", "shop", "svc"+id, "shop_default", "172.22.0."+strconv.Itoa(4+i), 300+i)
		w.containers = append(w.containers, c)
		w.sockets[300+i] = []string{"0.0.0.0:9000"}
	}
	r := diagnoseOn(t, w, wslRoot, true, "container:shop-worker-1", "localhost:8080")
	var reads int
	for _, b := range r.probes.ran {
		if len(b) == 1 && b[0].Kind == probe.SpecListeners {
			reads++
		}
	}
	if reads != maxProbeListeners {
		t.Errorf("%d probe-container listener reads, want %d", reads, maxProbeListeners)
	}
	if _, ok := evidence.NewView(r.d.Question, r.d.Evidence).ListenersIn(w.containers[0].ID); !ok {
		t.Error("the source's own listeners weren't among those read")
	}
	if !slices.ContainsFunc(r.d.Gaps, func(g Gap) bool { return g.Why == "skipped" && strings.Contains(g.What, "listening sockets in") }) {
		t.Errorf("no gap names the containers left unread: %+v", r.d.Gaps)
	}
}
