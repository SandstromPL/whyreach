//go:build lab && privileged

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
)

// TestLabNetns is M3's exit criterion (INITIAL.md §7): every lab scenario,
// run as root, where whyreach enters the containers' network namespaces
// itself (the netns executor). Each must reach the diagnosis the scenario
// expects with probe containers on, since entering the namespace gives the
// same evidence, while writing nothing to Docker: no probe image import, no
// probe container, empty side_effects. Each diagnosis runs with probe
// containers off (the default) and on: the netns executor wins either way.
//
// make lab-root runs it, with binaries built as the user.
func TestLabNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: run make lab-root")
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
					inNetns += checkNetns(t, d)
				})
			}
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
// the source container is in. It returns how many did.
func checkNetns(t *testing.T, d *engine.Diagnosis) int {
	t.Helper()
	var want uint64
	if id := d.Question.From.ContainerID; id != "" {
		want = netnsOf(t, id)
	}
	n := 0
	for _, ev := range d.Evidence {
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
