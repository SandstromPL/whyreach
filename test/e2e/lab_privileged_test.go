//go:build lab && privileged

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/platform"
)

// TestLabNetns is M3's exit criterion (INITIAL.md §7): every lab scenario,
// run as root, where whyreach enters the containers' network namespaces
// itself (the netns executor). Each must reach the diagnosis the scenario
// expects with probe containers on, since entering the namespace gives the
// same evidence, while writing nothing to Docker: no probe image import, no
// probe container, empty side_effects. Each diagnosis runs with probe
// containers off (the default) and on: the netns executor wins either way.
// From a container, `whyreach probe tcp` (run_probe) must go the same way.
//
// make lab-root runs it, with binaries built as the user.
func TestLabNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: run make lab-root")
	}
	if !platform.EngineHere(l.platform) {
		// Docker's PIDs aren't this machine's (Docker Desktop): whyreach
		// never enters them, by design (ADR 0004).
		t.Skipf("the netns executor runs only where Docker Engine runs on this machine, and this is %s", l.platform)
	}
	// The probe image's tag carries this build's digest, so it can only
	// exist if this binary imported it. Start without it (it is the lab's
	// own, labeled io.whyreach.probe=1) and check that it never appears.
	if imageExists(l.probeImage) {
		if out, err := exec.CommandContext(context.Background(), "docker", "image", "rm", l.probeImage).CombinedOutput(); err != nil {
			t.Fatalf("remove %s before the run: %v\n%s", l.probeImage, err, out)
		}
	}
	start := time.Now()
	inNetns := 0
	for _, dir := range scenarioDirs(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			r := bringUp(t, dir)
			source := ""
			for _, cfg := range []struct{ name, home string }{
				{"default-config", l.noProbe},
				{"probe-containers-on", l.withProbe},
			} {
				t.Run(cfg.name, func(t *testing.T) {
					d := diagnose(t, cfg.home, r.from, r.to)
					check(t, d, *r.s.Expect)
					if len(d.SideEffects) != 0 {
						t.Errorf("as root whyreach must not write to Docker: %v", d.SideEffects)
					}
					source = d.Question.From.ContainerID
					inNetns += checkNetns(t, d.Evidence, source)
				})
			}
			if source == "" {
				return // from the host: no namespace to enter
			}
			t.Run("run-probe", func(t *testing.T) {
				res := runProbe(t, l.noProbe, "tcp", r.to, r.from)
				if len(res.SideEffects) != 0 {
					t.Errorf("as root whyreach must not write to Docker: %v", res.SideEffects)
				}
				if n := checkNetns(t, res.Evidence, source); n == 0 {
					t.Errorf("run_probe sent nothing through the netns executor: %+v", res.Evidence)
				} else {
					inNetns += n
				}
			})
		})
	}
	if inNetns == 0 {
		t.Error("no check ran through the netns executor")
	}
	t.Logf("%d checks ran inside containers' network namespaces", inNetns)
	if ev := dockerEvents(t, start, time.Now(), "type=container", "label="+probeLabel); ev != "" {
		t.Errorf("probe containers were created during the run:\n%s", ev)
	}
	if imageExists(l.probeImage) {
		t.Errorf("whyreach imported its probe image %s", l.probeImage)
	}
}

// checkNetns checks the DNS and TCP records of checks that ran inside a
// container: each ran through the netns executor, in the network namespace
// the source container (an ID, or "" for the host) is in. It returns how
// many did.
func checkNetns(t *testing.T, evs []evidence.Evidence, source string) int {
	t.Helper()
	var want uint64
	if source != "" {
		want = netnsOf(t, source)
	}
	n := 0
	for _, ev := range evs {
		if ev.Kind != evidence.KindDNS && ev.Kind != evidence.KindTCP {
			continue
		}
		switch {
		case ev.Context.Kind != evidence.ContextContainer || ev.Context.Executor == "":
			// The host's own checks, or checks the gate skipped before any
			// executor ran (WR008).
			continue
		case ev.Context.Executor != evidence.ExecutorNetns:
			t.Errorf("%s %s ran through %q, want the netns executor", ev.Kind, ev.Subject, ev.Context.Executor)
			continue
		}
		switch ev.Status {
		case evidence.StatusOK:
			if ev.Context.NetnsID == 0 || ev.Context.NetnsID != want {
				t.Errorf("%s %s ran in namespace %d, want the source's %d", ev.Kind, ev.Subject, ev.Context.NetnsID, want)
			}
			n++
		case evidence.StatusSkipped:
			// Not sent, for a reason the record gives (a name that didn't
			// resolve, the allowlist).
		default:
			t.Errorf("%s %s through the netns executor: %s %+v", ev.Kind, ev.Subject, ev.Status, ev.Err)
		}
	}
	return n
}

// runProbe runs `whyreach probe KIND TARGET --from FROM --json` and decodes
// its result.
func runProbe(t *testing.T, configHome, kind, target, from string) *engine.ProbeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.bin, "probe", kind, target, "--from", from, "--json")
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+configHome,
		"XDG_STATE_HOME="+filepath.Join(l.home, "state"), "XDG_DATA_HOME="+filepath.Join(l.home, "data"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("whyreach probe %s %s --from %s: %v", kind, target, from, err)
	}
	var res engine.ProbeResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("decode the probe result: %v\n%s", err, out)
	}
	return &res
}

// netnsOf is the inode of a container's network namespace, read through
// its process.
func netnsOf(t *testing.T, id string) uint64 {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "docker", "inspect", "--format", "{{.State.Pid}}", id).Output()
	if err != nil {
		t.Fatalf("docker inspect %s: %v", id, err)
	}
	link, err := os.Readlink("/proc/" + strings.TrimSpace(string(out)) + "/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "net:["), "]"), 10, 64)
	if err != nil {
		t.Fatalf("namespace link %q: %v", link, err)
	}
	return ino
}

// dockerEvents lists the daemon's events between since and until that
// match the filters, one per line.
func dockerEvents(t *testing.T, since, until time.Time, filters ...string) string {
	t.Helper()
	args := []string{"events", "--since", strconv.FormatInt(since.Unix()-1, 10), "--until", strconv.FormatInt(until.Unix()+1, 10),
		"--format", "{{.Type}} {{.Action}} {{.Actor.Attributes.name}}"}
	for _, f := range filters {
		args = append(args, "--filter", f)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		t.Fatalf("docker events: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func imageExists(ref string) bool {
	return exec.CommandContext(context.Background(), "docker", "image", "inspect", ref).Run() == nil
}
