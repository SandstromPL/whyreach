package engine

import (
	"context"
	"errors"
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

// TestDoctorPlatform: doctor names the setup it found, and on wsl2-engine
// warns that WSL stops idle distros, and dockerd with them.
func TestDoctorPlatform(t *testing.T) {
	tests := []struct {
		name     string
		info     platform.Info
		desktop  bool
		docker   bool
		want     string // in the platform line
		idleWarn bool
	}{
		{"linux-engine", linuxHost, false, true, "linux-engine: Docker Engine on this Linux machine", false},
		{"wsl2-engine", wslRoot, false, true, "wsl2-engine: Docker Engine in this WSL2 distro", true},
		{"wsl2-desktop", wslRoot, true, true, "wsl2-desktop: Docker Desktop's WSL integration", false},
		{"WSL2 without Docker", wslRoot, false, false, "whyreach runs in WSL2", false},
		{"Linux without Docker", linuxHost, false, false, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := shopWorld()
			w.desktop = tt.desktop
			deps := Deps{Listeners: w, Platform: tt.info, Interfaces: func() (evidence.HostAddrs, error) { return evidence.HostAddrs{}, nil }}
			if tt.docker {
				deps.Docker = w
			} else {
				deps.DockerErr = errors.New("no Docker here")
			}
			var line, idle *Check
			checks := New(deps).SelfCheck(context.Background())
			for i, c := range checks {
				switch c.Name {
				case "platform":
					line = &checks[i]
				case "wsl idle shutdown":
					idle = &checks[i]
				}
			}
			switch {
			case tt.want == "" && line != nil:
				t.Errorf("platform line %+v, want none", line)
			case tt.want != "" && (line == nil || !strings.Contains(line.Detail, tt.want)):
				t.Errorf("platform line %+v, want %q", line, tt.want)
			}
			if (idle != nil) != tt.idleWarn {
				t.Errorf("idle-shutdown line %+v, want one: %v", idle, tt.idleWarn)
			}
			if idle != nil && (idle.Status != CheckWarn || !strings.Contains(idle.Detail, "dockerd") || !strings.Contains(idle.Fix, "instanceIdleTimeout")) {
				t.Errorf("idle-shutdown line %+v", idle)
			}
			for _, c := range checks {
				if c.Name == "container listeners" && tt.desktop && !strings.Contains(c.Detail, "inside probe containers") {
					t.Errorf("container listeners on Docker Desktop: %+v", c)
				}
			}
		})
	}
}

// TestUnpublishedServerOnDesktop: from the host, nothing answers a port
// that a container serves without publishing it (WR019). On Docker Desktop
// the containers' sockets are read in probe containers; without them the
// search can't look inside, which is a gap, and "nothing on the host
// listens" (WR001) is only likely, never settled.
func TestUnpublishedServerOnDesktop(t *testing.T) {
	w := shopWorld()
	w.desktop = true
	w.tcp["127.0.0.1:8080"] = evidence.OutcomeRefused
	r := diagnoseOn(t, w, wslRoot, true, "host", "localhost:8080")
	if p := r.d.Primary(); p == nil || p.RuleID != "WR019" || p.Confidence != "high" {
		t.Errorf("with probe containers: primary %+v, want WR019 (high)", p)
	}
	if len(r.pids.pids) != 0 {
		t.Errorf("read /proc/<pid> for %v", r.pids.pids)
	}
	r = diagnoseOn(t, w, wslRoot, false, "host", "localhost:8080")
	if p := r.d.Primary(); p == nil || p.RuleID != "WR001" || p.Confidence != "medium" {
		t.Errorf("without probe containers: primary %+v, want WR001 (medium)", p)
	}
	if !slices.ContainsFunc(r.d.Gaps, func(g Gap) bool {
		return strings.Contains(g.What, "running containers") && strings.Contains(g.HowToEnable, "probe_containers = true")
	}) {
		t.Errorf("no gap for the containers whose sockets went unread: %+v", r.d.Gaps)
	}
}

// TestInspectWritesNothingOnDesktop: inspect_environment's tool says
// read-only, so on Docker Desktop, where a container's listening sockets
// take a probe container, an inspection doesn't read them (run_probe can).
func TestInspectWritesNothingOnDesktop(t *testing.T) {
	w := shopWorld()
	w.desktop = true
	pids := &watchedPIDs{world: w}
	probes := &scripted{w: w, name: evidence.ExecutorProbeContainer}
	e := New(Deps{Docker: w, Listeners: pids, Probe: probes, Platform: wslRoot})
	scope, err := target.ParseScope("container:shop-api-1")
	if err != nil {
		t.Fatal(err)
	}
	in, err := e.Inspect(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(probes.ran) != 0 || len(pids.pids) != 0 {
		t.Errorf("an inspection ran probe containers %v and read PIDs %v", probes.ran, pids.pids)
	}
	if !slices.ContainsFunc(in.Gaps, func(g Gap) bool { return g.Detail == InspectNoProbe && strings.Contains(g.HowToEnable, "run_probe") }) {
		t.Errorf("gaps %+v, want one that points at run_probe", in.Gaps)
	}
}

// TestDesktopListenerGapsMerge: on Docker Desktop without probe
// containers, every container's sockets are out of reach for the same
// reason, so one gap names them all instead of one gap each.
func TestDesktopListenerGapsMerge(t *testing.T) {
	w := shopWorld()
	w.desktop = true
	r := diagnoseOn(t, w, wslRoot, false, "container:shop-worker-1", "localhost:8080")
	var merged []Gap
	for _, g := range r.d.Gaps {
		if g.Detail == executor.PIDsElsewhere {
			merged = append(merged, g)
		}
	}
	if len(merged) != 1 || merged[0].What != "listening sockets in api and worker" || len(merged[0].Evidence) != 2 {
		t.Errorf("gaps %+v, want one for api and worker", merged)
	}
}
