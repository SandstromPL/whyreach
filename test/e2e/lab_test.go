//go:build lab

// Package e2e runs the failure lab (INITIAL.md §6.3): each scenario in
// test/lab/<name>/ is a Compose project plus the diagnosis whyreach must
// return for it. The harness builds whyreach and the lab's stand-in server,
// brings each scenario up under a unique project name
// (whyreach-lab-<name>-<rand>), runs the real binary twice (with probe
// containers on, then with the default config) and tears the scenario down.
//
// Run it with `make lab`. It needs Docker, and touches only resources named
// whyreach-lab-* or labeled io.whyreach.lab=1 / io.whyreach.probe=1.
package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
)

const (
	labVersion = "lab"
	labLabel   = "io.whyreach.lab=1"
	probeLabel = "io.whyreach.probe=1"
)

// scenario is test/lab/<name>/scenario.yaml.
type scenario struct {
	Description string   `yaml:"description"`
	Projects    []string `yaml:"projects"` // compose files; default [compose.yaml]
	UpWait      *bool    `yaml:"up_wait"`  // default true: docker compose up --wait
	Settle      *struct {
		Service string `yaml:"service"`
		State   string `yaml:"state"`
	} `yaml:"settle"`
	From               string  `yaml:"from"`
	To                 string  `yaml:"to"`
	Expect             *expect `yaml:"expect"`               // with probe containers on
	ExpectWithoutProbe *expect `yaml:"expect_without_probe"` // with the default config
}

type expect struct {
	Verdict        string   `yaml:"verdict"`
	TopRule        string   `yaml:"top_rule"`
	Confidence     string   `yaml:"confidence"`
	MustNotFire    []string `yaml:"must_not_fire"`
	FixContains    string   `yaml:"fix_contains"`
	TCPOutcomes    []string `yaml:"tcp_outcomes"` // "via:outcome" that some TCP probe must show
	SideEffectsMax *int     `yaml:"side_effects_max"`
}

type lab struct {
	bin        string // the whyreach binary under test
	image      string // the lab server image
	probeImage string // the probe image the binary imports
	withProbe  string // XDG_CONFIG_HOME with probe_containers = true
	noProbe    string // XDG_CONFIG_HOME with no config file
}

var l lab

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
		fmt.Fprintln(os.Stderr, "lab: Docker is not reachable:", err)
		return 1
	}
	dir, err := os.MkdirTemp("", "whyreach-lab-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "lab:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	if err := setup(dir); err != nil {
		fmt.Fprintln(os.Stderr, "lab setup:", err)
		return 1
	}
	code := m.Run()
	if left := leftoverProbes(); left != "" {
		fmt.Fprintln(os.Stderr, "lab: probe containers were left behind:\n"+left)
		code = 1
	}
	// The images exist only for this run: both are tagged by content.
	_ = exec.Command("docker", "image", "rm", l.image, l.probeImage).Run()
	return code
}

func setup(dir string) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	l.bin = filepath.Join(dir, "whyreach")
	if err := goBuild(root, l.bin, "./cmd/whyreach", "-X main.version="+labVersion); err != nil {
		return err
	}
	digest, err := sha256File(l.bin)
	if err != nil {
		return err
	}
	l.probeImage = "whyreach-probe:" + executor.ImageTag(labVersion, digest)

	server := filepath.Join(dir, "labserver")
	if err := goBuild(root, server, "./test/labserver", ""); err != nil {
		return err
	}
	sd, err := sha256File(server)
	if err != nil {
		return err
	}
	l.image = "whyreach-lab-server:" + sd[:12]
	if err := importImage(server, l.image); err != nil {
		return err
	}

	l.noProbe = filepath.Join(dir, "config-default")
	l.withProbe = filepath.Join(dir, "config-probe")
	if err := os.MkdirAll(filepath.Join(l.withProbe, "whyreach"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(l.noProbe, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(l.withProbe, "whyreach", "config.toml"), []byte("[permissions]\nprobe_containers = true\n"), 0o600)
}

func repoRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", err
	}
	return filepath.Dir(strings.TrimSpace(string(out))), nil
}

func goBuild(root, out, pkg, ldflags string) error {
	args := []string{"build", "-trimpath", "-o", out}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	cmd := exec.Command("go", append(args, pkg)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %v\n%s", pkg, err, b)
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// importImage imports a static binary as a FROM-scratch image, no registry pull.
func importImage(bin, ref string) error {
	b, err := os.ReadFile(bin)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "labserver", Mode: 0o555, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := tw.Write(b); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	cmd := exec.Command("docker", "import", "--change", `ENTRYPOINT ["/labserver"]`, "--change", "LABEL "+labLabel, "-", ref)
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker import: %v\n%s", err, out)
	}
	return nil
}

func leftoverProbes() string {
	out, _ := exec.Command("docker", "ps", "-a", "--filter", "label="+probeLabel, "--format", "{{.Names}} {{.Status}}").Output()
	return strings.TrimSpace(string(out))
}

func TestLab(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("..", "lab", "*", "scenario.yaml"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios: %v", err)
	}
	slices.Sort(dirs)
	// Scenarios run one after another: they deliberately reuse service names
	// (api, worker), and a diagnosis looks at every container on the host.
	for _, path := range dirs {
		dir := filepath.Dir(path)
		t.Run(filepath.Base(dir), func(t *testing.T) { runScenario(t, dir) })
	}
}

func runScenario(t *testing.T, dir string) {
	var s scenario
	b, err := os.ReadFile(filepath.Join(dir, "scenario.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("scenario.yaml: %v", err)
	}
	if s.Expect == nil {
		t.Fatal("scenario.yaml has no expect")
	}
	if len(s.Projects) == 0 {
		s.Projects = []string{"compose.yaml"}
	}
	project := "whyreach-lab-" + filepath.Base(dir) + "-" + randHex(2)
	for _, file := range s.Projects {
		up(t, dir, projectFor(project, file), file, s.UpWait == nil || *s.UpWait)
	}
	if s.Settle != nil {
		settle(t, projectFor(project, s.Projects[0]), s.Settle.Service, s.Settle.State)
	}
	from := strings.ReplaceAll(s.From, "${PROJECT}", project)

	t.Run("probe-containers", func(t *testing.T) {
		d := diagnose(t, l.withProbe, from, s.To)
		check(t, d, *s.Expect)
	})
	if s.ExpectWithoutProbe != nil {
		t.Run("default-config", func(t *testing.T) {
			d := diagnose(t, l.noProbe, from, s.To)
			check(t, d, *s.ExpectWithoutProbe)
			if len(d.SideEffects) != 0 {
				t.Errorf("with probe containers off, whyreach must not write to Docker: %v", d.SideEffects)
			}
		})
	}
}

// projectFor names the project of a compose file: compose.yaml runs as the
// base project, compose.<x>.yaml as <base>-<x>.
func projectFor(base, file string) string {
	if file == "compose.yaml" {
		return base
	}
	return base + "-" + strings.TrimSuffix(strings.TrimPrefix(file, "compose."), ".yaml")
}

func compose(dir, project, file string, args ...string) *exec.Cmd {
	cmd := exec.Command("docker", append([]string{"compose", "-p", project, "-f", file}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "WHYREACH_LAB_IMAGE="+l.image)
	return cmd
}

func up(t *testing.T, dir, project, file string, wait bool) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := compose(dir, project, file, "down", "-v", "--remove-orphans", "--timeout", "1").CombinedOutput(); err != nil {
			t.Errorf("compose down %s: %v\n%s", project, err, out)
		}
	})
	args := []string{"up", "-d"}
	if wait {
		args = append(args, "--wait", "--wait-timeout", "60")
	}
	if out, err := compose(dir, project, file, args...).CombinedOutput(); err != nil {
		t.Fatalf("compose up %s: %v\n%s", project, err, out)
	}
}

// settle waits until a service's container reaches a state.
func settle(t *testing.T, project, service, state string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("docker", "ps", "-a",
			"--filter", "label=com.docker.compose.project="+project,
			"--filter", "label=com.docker.compose.service="+service,
			"--format", "{{.State}}").Output()
		if strings.TrimSpace(string(out)) == state {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s/%s never reached state %s", project, service, state)
}

// diagnose runs the real binary and decodes its JSON.
func diagnose(t *testing.T, configHome, from, to string) *engine.Diagnosis {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.bin, "--from", from, to, "--json")
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+configHome)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run whyreach: %v", err)
	}
	var d engine.Diagnosis
	if err := json.Unmarshal(stdout.Bytes(), &d); err != nil {
		t.Fatalf("exit %d, decode JSON: %v\nstdout: %s\nstderr: %s", code, err, stdout.String(), stderr.String())
	}
	if code != d.ExitCode() {
		t.Errorf("exit code %d, want %d for verdict %s", code, d.ExitCode(), d.Verdict)
	}
	t.Logf("%s in %s (exit %d): %s", d.Verdict, time.Since(start).Round(time.Millisecond), code, d.Summary)
	if stderr.Len() > 0 {
		t.Logf("stderr: %s", stderr.String())
	}
	return &d
}

func check(t *testing.T, d *engine.Diagnosis, e expect) {
	t.Helper()
	dump := func() string {
		b, _ := json.MarshalIndent(struct {
			Findings any
			Gaps     any
			Facts    any
		}{d.Findings, d.Gaps, d.Facts}, "", "  ")
		return string(b)
	}
	if d.Verdict != e.Verdict {
		t.Errorf("verdict = %s, want %s\n%s", d.Verdict, e.Verdict, dump())
	}
	if e.TopRule != "" {
		p := d.Primary()
		if p == nil || p.RuleID != e.TopRule || string(p.Confidence) != e.Confidence {
			t.Errorf("primary = %+v, want %s (%s)\n%s", p, e.TopRule, e.Confidence, dump())
		} else if e.FixContains != "" && !strings.Contains(p.Fix, e.FixContains) {
			t.Errorf("fix %q lacks %q", p.Fix, e.FixContains)
		}
	}
	for _, f := range d.Findings {
		if slices.Contains(e.MustNotFire, f.RuleID) {
			t.Errorf("%s must not fire: %s", f.RuleID, f.Title)
		}
	}
	for _, s := range d.Suppressed {
		if slices.Contains(e.MustNotFire, s.RuleID) {
			t.Errorf("%s must not fire, even suppressed: %s", s.RuleID, s.Title)
		}
	}
	for _, want := range e.TCPOutcomes {
		via, outcome, _ := strings.Cut(want, ":")
		found := slices.ContainsFunc(d.Evidence, func(ev evidence.Evidence) bool {
			p, ok := ev.Data.(evidence.TCPProbe)
			return ok && p.Via == via && p.Outcome == outcome
		})
		if !found {
			t.Errorf("no TCP probe via %s with outcome %s\n%s", via, outcome, dump())
		}
	}
	if e.SideEffectsMax != nil && len(d.SideEffects) > *e.SideEffectsMax {
		t.Errorf("side effects %v, want at most %d", d.SideEffects, *e.SideEffectsMax)
	}
	if d.ChangesMade {
		t.Error("changes_made must always be false")
	}
	for _, ev := range d.Evidence {
		if ev.Kind == evidence.KindContainer {
			if c, ok := ev.Data.(evidence.Container); ok && c.ID == "" {
				t.Errorf("container evidence without an ID: %+v", ev)
			}
		}
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
