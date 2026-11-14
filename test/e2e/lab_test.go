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
//
// As root, whyreach enters the containers' network namespaces itself (the
// netns executor), so TestLab gives way to TestLabNetns (build tag
// privileged; `make lab-root`). Root runs take prebuilt binaries
// (-lab.bin, -lab.server), so nothing is compiled as root.
package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/platform"
	"github.com/SandstromPL/whyreach/internal/rules"
)

const (
	labVersion = "lab"
	labLabel   = "io.whyreach.lab=1"
	probeLabel = "io.whyreach.probe=1"
)

// scenario is test/lab/<name>/scenario.yaml.
type scenario struct {
	Description string `yaml:"description"`
	// Image is a public image the scenario runs (the README demo): the
	// scenario is skipped where it isn't present, since the lab pulls
	// nothing.
	Image    string   `yaml:"image"`
	Projects []string `yaml:"projects"` // compose files; default [compose.yaml]
	UpWait   *bool    `yaml:"up_wait"`  // default true: docker compose up --wait
	Settle   *struct {
		Service string `yaml:"service"`
		State   string `yaml:"state"`
	} `yaml:"settle"`
	// HostListen starts listeners on the host for the scenario's duration:
	// "loopback" (127.0.0.1) or "docker0" (the default bridge's gateway), on
	// one free port, which ${HOST_PORT} names.
	HostListen         []string `yaml:"host_listen"`
	From               string   `yaml:"from"`
	To                 string   `yaml:"to"`
	Expect             *expect  `yaml:"expect"`               // with probe containers on
	ExpectWithoutProbe *expect  `yaml:"expect_without_probe"` // with the default config
	// ExpectOn replaces both expectations on a platform where the
	// scenario's premise doesn't hold (WR011's on Docker Desktop, which
	// provides host.docker.internal), keyed by platform name (INITIAL.md
	// §3.7). SkipOn skips the scenario on a platform, with the reason.
	ExpectOn map[string]*expectOn `yaml:"expect_on"`
	SkipOn   map[string]string    `yaml:"skip_on"`
	// ExpectDesktopWithoutProbe replaces the generic check of the default
	// config where Docker's PIDs aren't this machine's (Docker Desktop),
	// for a scenario whose honest answer there is another rule.
	ExpectDesktopWithoutProbe *expect `yaml:"expect_desktop_without_probe"`
}

// expectOn is what must hold on one platform, with probe containers on and
// off: the verdict is one of VerdictIn, and none of MustNotFire fires.
type expectOn struct {
	Why         string   `yaml:"why"`
	VerdictIn   []string `yaml:"verdict_in"`
	MustNotFire []string `yaml:"must_not_fire"`
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
	// platform is where the lab runs, as whyreach classifies it
	// (INITIAL.md §3.7): linux-engine, wsl2-engine, wsl2-desktop, …
	platform   string
	dockerHost string // DOCKER_HOST for whyreach: the -lab.desktop proxy, or "" for the default
	// expectOn is the platform whose expect_on and skip_on entries apply:
	// the platform itself, or wsl2-desktop's in the -lab.desktop rehearsal.
	expectOn   string
	bin        string // the whyreach binary under test
	image      string // the lab server image
	probeImage string // the probe image the binary imports
	withProbe  string // XDG_CONFIG_HOME with probe_containers = true
	noProbe    string // XDG_CONFIG_HOME with no config file
	home       string // XDG_STATE_HOME and XDG_DATA_HOME of every run: the audit log stays in the lab
}

var l lab

// Prebuilt binaries, for runs as root (make lab-root builds them as the
// user first): building as root would leave root-owned files in the
// user's Go caches.
var (
	prebuiltBin    = flag.String("lab.bin", "", "whyreach binary to test, built with -ldflags '-X main.version="+labVersion+"' (default: build it)")
	prebuiltServer = flag.String("lab.server", "", "test/labserver binary (default: build it)")
	// A dev-box stand-in for Docker Desktop (ADR 0004): whyreach reaches
	// Docker through a proxy whose GET /version says Docker Desktop, so it
	// treats Docker's PIDs as another machine's and reads every listener
	// in a probe container, as on Docker Desktop's WSL integration.
	labDesktop = flag.Bool("lab.desktop", false, "simulate Docker Desktop: whyreach talks to Docker through a proxy whose /version says Docker Desktop")
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if err := exec.CommandContext(context.Background(), "docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
		fmt.Fprintln(os.Stderr, "lab: Docker is not reachable:", err)
		return 1
	}
	dir, err := os.MkdirTemp("", "whyreach-lab-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "lab:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := setup(dir); err != nil {
		fmt.Fprintln(os.Stderr, "lab setup:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "lab: platform", l.platform)
	if *labDesktop {
		// What the rehearsal can't show: it runs as linux-desktop, so the
		// Windows host of Docker Desktop's WSL integration (its listeners'
		// unsupported record), the WSL2 VM's labels and the WSL2 fact run
		// only in unit tests and in the owner's run on Windows.
		fmt.Fprintln(os.Stderr, "lab: rehearsing wsl2-desktop's expectations; Windows' side (host.docker.internal, WSL2 labels) isn't simulated")
	}
	code := m.Run()
	if left := leftoverProbes(); left != "" {
		fmt.Fprintln(os.Stderr, "lab: probe containers were left behind:\n"+left)
		code = 1
	}
	// The images exist only for this run: both are tagged by content.
	_ = exec.CommandContext(context.Background(), "docker", "image", "rm", l.image, l.probeImage).Run()
	return code
}

// labPlatform classifies where the lab runs, as whyreach does: from this
// process's environment and the daemon's answer.
func labPlatform() (string, error) {
	out, err := exec.CommandContext(context.Background(), "docker", "version", "--format", "{{.Server.Os}}|{{.Server.Platform.Name}}|{{.Server.KernelVersion}}").Output()
	if err != nil {
		return "", fmt.Errorf("docker version: %w", err)
	}
	f := strings.SplitN(strings.TrimSpace(string(out)), "|", 3)
	if len(f) != 3 {
		return "", fmt.Errorf("docker version said %q", out)
	}
	return platform.Classify(platform.Detect(), platform.Daemon{OS: f[0], Platform: f[1], Kernel: f[2]}), nil
}

func setup(dir string) error {
	var err error
	if l.platform, err = labPlatform(); err != nil {
		return err
	}
	if *labDesktop {
		if !platform.EngineHere(l.platform) {
			return fmt.Errorf("-lab.desktop simulates Docker Desktop over Docker Engine, and this is %s", l.platform)
		}
		sock := filepath.Join(dir, "desktop.sock")
		if err := desktopProxy(sock); err != nil {
			return err
		}
		l.dockerHost = "unix://" + sock
		l.platform = platform.Classify(platform.Detect(), platform.Daemon{OS: "linux", Platform: simulatedDesktop})
	}
	l.expectOn = l.platform
	if *labDesktop {
		l.expectOn = platform.WSL2Desktop // the rehearsal stands in for Docker Desktop's WSL integration
	}
	l.bin = *prebuiltBin
	server := *prebuiltServer
	if l.bin == "" || server == "" {
		if os.Geteuid() == 0 {
			return errors.New("as root, pass prebuilt binaries with -lab.bin and -lab.server (make lab-root does)")
		}
		root, err := repoRoot()
		if err != nil {
			return err
		}
		l.bin, server = filepath.Join(dir, "whyreach"), filepath.Join(dir, "labserver")
		if err := goBuild(root, l.bin, "./cmd/whyreach", "-X main.version="+labVersion); err != nil {
			return err
		}
		if err := goBuild(root, server, "./test/labserver", ""); err != nil {
			return err
		}
	}
	digest, err := sha256File(l.bin)
	if err != nil {
		return err
	}
	l.probeImage = "whyreach-probe:" + executor.ImageTag(labVersion, digest)

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
	l.home = filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(l.withProbe, "whyreach"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(l.noProbe, 0o700); err != nil {
		return err
	}
	// [probe] names: a headless agent can't approve a lookup of an outside
	// name, and WR020's scenario diagnoses example.com (INITIAL.md §10 Q11).
	// The CLI looks up any name, so it changes nothing for TestLab.
	cfg := "[permissions]\nprobe_containers = true\n\n[probe]\nnames = [\"example.com\"]\n"
	return os.WriteFile(filepath.Join(l.withProbe, "whyreach", "config.toml"), []byte(cfg), 0o600)
}

func repoRoot() (string, error) {
	out, err := exec.CommandContext(context.Background(), "go", "env", "GOMOD").Output()
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
	cmd := exec.CommandContext(context.Background(), "go", append(args, pkg)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, b)
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
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
	cmd := exec.CommandContext(context.Background(), "docker", "import", "--change", `ENTRYPOINT ["/labserver"]`, "--change", "LABEL "+labLabel, "-", ref)
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker import: %w\n%s", err, out)
	}
	return nil
}

func leftoverProbes() string {
	out, _ := exec.CommandContext(context.Background(), "docker", "ps", "-a", "--filter", "label="+probeLabel, "--format", "{{.Names}} {{.Status}}").Output()
	return strings.TrimSpace(string(out))
}

func TestLab(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root whyreach enters network namespaces itself, so the default-config expectations don't apply: TestLabNetns covers root (make lab-root)")
	}
	// Scenarios run one after another: they deliberately reuse service names
	// (api, worker), and a diagnosis looks at every container on the host.
	for _, dir := range scenarioDirs(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) { runScenario(t, dir) })
	}
}

// scenarioDirs lists test/lab/<scenario>, sorted.
func scenarioDirs(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "lab", "*", "scenario.yaml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no scenarios: %v", err)
	}
	slices.Sort(paths)
	dirs := make([]string, 0, len(paths))
	for _, p := range paths {
		dirs = append(dirs, filepath.Dir(p))
	}
	return dirs
}

// runScenario runs a scenario with probe containers on, then with the
// default config. Where Docker's PIDs aren't this machine's (Docker
// Desktop's WSL integration), containers' listening sockets can be read
// only in probe containers, so the default config can't meet the same
// expectations: it must degrade honestly instead (checkDegraded; ADR 0004).
func runScenario(t *testing.T, dir string) {
	r := bringUp(t, dir)
	if eo := r.s.ExpectOn[l.expectOn]; eo != nil {
		t.Logf("on %s: %s", l.expectOn, eo.Why)
		for _, run := range []struct{ name, config string }{{"probe-containers", l.withProbe}, {"default-config", l.noProbe}} {
			t.Run(run.name, func(t *testing.T) {
				d := diagnose(t, run.config, r.from, r.to)
				for _, p := range onProblems(d, *eo) {
					t.Error(p)
				}
				readNoLocalPID(t, d)
				if run.config == l.noProbe && len(d.SideEffects) != 0 {
					t.Errorf("with probe containers off, whyreach must not write to Docker: %v", d.SideEffects)
				}
			})
		}
		return
	}
	t.Run("probe-containers", func(t *testing.T) {
		d := diagnose(t, l.withProbe, r.from, r.to)
		check(t, d, *r.s.Expect)
		readNoLocalPID(t, d)
	})
	if r.s.ExpectWithoutProbe != nil {
		t.Run("default-config", func(t *testing.T) {
			d := diagnose(t, l.noProbe, r.from, r.to)
			switch {
			case platform.EngineHere(l.platform):
				check(t, d, *r.s.ExpectWithoutProbe)
			case r.s.ExpectDesktopWithoutProbe != nil:
				check(t, d, *r.s.ExpectDesktopWithoutProbe)
				readNoLocalPID(t, d)
			default:
				for _, p := range degradedProblems(d, *r.s.Expect) {
					t.Error(p)
				}
				readNoLocalPID(t, d)
			}
			if len(d.SideEffects) != 0 {
				t.Errorf("with probe containers off, whyreach must not write to Docker: %v", d.SideEffects)
			}
		})
	}
}

// running is a scenario that is up: its definition, its Compose project,
// and the question with every ${VAR} filled in.
type running struct {
	s        scenario
	project  string
	from, to string
}

// bringUp reads a scenario, brings its projects up and waits for them; the
// test's cleanup tears them down.
func bringUp(t *testing.T, dir string) running {
	t.Helper()
	return bringUpAs(t, dir, "whyreach-lab-"+filepath.Base(dir)+"-"+randHex(2), dir)
}

// bringUpAs brings a scenario up under the given project name, running
// Compose on the files in composeDir: the agent benchmark uses a neutral
// name and comment-free copies, since both would otherwise give the
// answer away.
func bringUpAs(t *testing.T, dir, project, composeDir string) running {
	t.Helper()
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
	if why, ok := s.SkipOn[l.expectOn]; ok {
		t.Skipf("skipped on %s: %s", l.expectOn, why)
	}
	if s.Image != "" {
		if err := exec.CommandContext(context.Background(), "docker", "image", "inspect", s.Image).Run(); err != nil {
			t.Skipf("%s isn't present and the lab pulls nothing: docker pull %s to run this scenario", s.Image, s.Image)
		}
	}
	if len(s.Projects) == 0 {
		s.Projects = []string{"compose.yaml"}
	}
	// ${LAB_PORT} is a free host port, for scenarios that publish one or
	// listen on one: a fixed number could be taken on the machine.
	vars := map[string]string{"${PROJECT}": project, "${LAB_PORT}": freePort(t)}
	if len(s.HostListen) > 0 {
		vars["${HOST_PORT}"] = hostListen(t, s.HostListen)
	}
	for _, file := range s.Projects {
		up(t, composeDir, projectFor(project, file), file, s.UpWait == nil || *s.UpWait, vars)
	}
	if s.Settle != nil {
		settle(t, projectFor(project, s.Projects[0]), s.Settle.Service, s.Settle.State)
	}
	if strings.Contains(s.From+s.To, "${UNUSED_IP}") {
		vars["${UNUSED_IP}"] = unusedIP(t, project+"_default")
	}
	expand := func(v string) string {
		for k, val := range vars {
			v = strings.ReplaceAll(v, k, val)
		}
		return v
	}
	return running{s: s, project: project, from: expand(s.From), to: expand(s.To)}
}

// projectFor names the project of a compose file: compose.yaml runs as the
// base project, compose.<x>.yaml as <base>-<x>.
func projectFor(base, file string) string {
	if file == "compose.yaml" {
		return base
	}
	return base + "-" + strings.TrimSuffix(strings.TrimPrefix(file, "compose."), ".yaml")
}

func compose(dir, project, file string, vars map[string]string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(context.Background(), "docker", append([]string{"compose", "-p", project, "-f", file}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "WHYREACH_LAB_IMAGE="+l.image, "LAB_PORT="+vars["${LAB_PORT}"])
	return cmd
}

func up(t *testing.T, dir, project, file string, wait bool, vars map[string]string) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := compose(dir, project, file, vars, "down", "-v", "--remove-orphans", "--timeout", "1").CombinedOutput(); err != nil {
			t.Errorf("compose down %s: %v\n%s", project, err, out)
		}
	})
	args := []string{"up", "-d"}
	if wait {
		args = append(args, "--wait", "--wait-timeout", "60")
	}
	if out, err := compose(dir, project, file, vars, args...).CombinedOutput(); err != nil {
		t.Fatalf("compose up %s: %v\n%s", project, err, out)
	}
}

// freePort returns a TCP port that is free on the host right now.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

// hostListen listens on the host for the rest of the test, on one free
// port at each address asked for, and returns the port. Connections are
// held open like a real server's.
func hostListen(t *testing.T, where []string) string {
	t.Helper()
	port := "0"
	for _, w := range where {
		addr := "127.0.0.1"
		// The default bridge's gateway is an address of this machine only
		// where Docker Engine runs here; Docker Desktop's bridges are in
		// its own VM, so there the listener stays on loopback.
		if w == "docker0" && platform.EngineHere(l.platform) {
			addr = bridgeGateway(t)
		}
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", net.JoinHostPort(addr, port))
		if err != nil {
			t.Fatalf("host listener on %s: %v", addr, err)
		}
		port = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					_, _ = io.Copy(io.Discard, c)
					_ = c.Close()
				}()
			}
		}()
	}
	return port
}

// bridgeGateway is the default bridge's gateway: the host's docker0 address.
func bridgeGateway(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}").Output()
	if err != nil {
		t.Fatalf("docker network inspect bridge: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// unusedIP returns an address on a network's subnet that no container holds.
func unusedIP(t *testing.T, network string) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "docker", "network", "inspect", network, "--format", "{{(index .IPAM.Config 0).Subnet}}").Output()
	if err != nil {
		t.Fatalf("docker network inspect %s: %v", network, err)
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(string(out)))
	if err != nil || !p.Addr().Is4() || p.Bits() > 24 {
		t.Fatalf("subnet of %s: %q %v", network, out, err)
	}
	b := p.Masked().Addr().As4()
	b[3] = 200 // compose hands out low addresses
	return netip.AddrFrom4(b).String()
}

// settle waits until a service's container reaches a state.
func settle(t *testing.T, project, service, state string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.CommandContext(context.Background(), "docker", "ps", "-a",
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
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+configHome,
		"XDG_STATE_HOME="+filepath.Join(l.home, "state"), "XDG_DATA_HOME="+filepath.Join(l.home, "data"))
	if l.dockerHost != "" {
		cmd.Env = append(cmd.Env, "DOCKER_HOST="+l.dockerHost)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
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
	// The expectations assume whyreach sees the platform the lab does.
	if p, ok := evidence.NewView(d.Question, d.Evidence).Platform(); ok && p.P.Name != l.platform {
		t.Errorf("whyreach recorded platform %s, and the lab runs on %s: the expectations don't apply", p.P.Name, l.platform)
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

// strength orders the verdicts that name a cause, weakest first.
var strength = map[string]int{engine.VerdictInconclusive: 0, engine.VerdictLikelyCause: 1, engine.VerdictCause: 2}

// degradedProblems checks a diagnosis made without probe containers where
// Docker's PIDs aren't this machine's (Docker Desktop): containers'
// listening sockets can't be read there, so the cause may be weaker than
// with probe containers, but never another one. The verdict is the
// expected one or weaker (no problem reproduced may only become
// inconclusive), the primary finding, if any, is the expected rule at no
// higher confidence, nothing in must_not_fire fires, and a weaker verdict
// comes with a gap that says how to allow probe containers.
func degradedProblems(d *engine.Diagnosis, e expect) []string {
	var out []string
	weaker := d.Verdict != e.Verdict
	switch {
	case !weaker:
	case e.Verdict == engine.VerdictNoProblem:
		if d.Verdict != engine.VerdictInconclusive {
			out = append(out, fmt.Sprintf("verdict %s, want %s or, without probe containers, %s", d.Verdict, e.Verdict, engine.VerdictInconclusive))
		}
	default:
		ws, okW := strength[e.Verdict]
		gs, okG := strength[d.Verdict]
		if !okW || !okG || gs > ws {
			out = append(out, fmt.Sprintf("verdict %s, want %s or weaker", d.Verdict, e.Verdict))
		}
	}
	// The primary finding, a weak lead in an inconclusive diagnosis
	// included, is the expected rule or none. A scenario that expects no
	// cause is held to must_not_fire alone.
	if p := d.Primary(); p != nil && d.Verdict != engine.VerdictNoProblem && (e.TopRule != "" || d.Verdict != engine.VerdictInconclusive) {
		conf := map[string]int{"low": 0, "medium": 1, "high": 2}
		if e.TopRule == "" || p.RuleID != e.TopRule || conf[string(p.Confidence)] > conf[e.Confidence] {
			out = append(out, fmt.Sprintf("primary %s (%s), want %s at %s or lower, or none", p.RuleID, p.Confidence, e.TopRule, e.Confidence))
		}
	}
	for _, f := range append(slices.Clone(d.Findings), suppressedAsFindings(d)...) {
		if slices.Contains(e.MustNotFire, f.RuleID) {
			out = append(out, fmt.Sprintf("%s must not fire: %s", f.RuleID, f.Title))
		}
	}
	if weaker && !slices.ContainsFunc(d.Gaps, func(g engine.Gap) bool { return strings.Contains(g.HowToEnable, "probe_containers = true") }) {
		out = append(out, fmt.Sprintf("a weaker verdict (%s, want %s) needs a gap that says how to allow probe containers: %+v", d.Verdict, e.Verdict, d.Gaps))
	}
	if d.ChangesMade {
		out = append(out, "changes_made must always be false")
	}
	return out
}

// onProblems checks a diagnosis against a platform's own expectation.
func onProblems(d *engine.Diagnosis, e expectOn) []string {
	var out []string
	if len(e.VerdictIn) > 0 && !slices.Contains(e.VerdictIn, d.Verdict) {
		out = append(out, fmt.Sprintf("verdict %s, want one of %v", d.Verdict, e.VerdictIn))
	}
	for _, f := range append(slices.Clone(d.Findings), suppressedAsFindings(d)...) {
		if slices.Contains(e.MustNotFire, f.RuleID) {
			out = append(out, fmt.Sprintf("%s must not fire: %s", f.RuleID, f.Title))
		}
	}
	if d.ChangesMade {
		out = append(out, "changes_made must always be false")
	}
	return out
}

// readNoLocalPID checks, where Docker's PIDs aren't this machine's, that
// whyreach never tried to read a container's listening sockets through
// /proc/<pid> on this machine, whether the read worked or not (on Docker
// Desktop it would fail the cgroup check, and the diagnosis would only
// degrade), and that every listener read that worked came from a probe
// container.
func readNoLocalPID(t *testing.T, d *engine.Diagnosis) {
	t.Helper()
	if platform.EngineHere(l.platform) {
		return
	}
	for _, ev := range d.Evidence {
		if ev.Kind != evidence.KindListeners || ev.Context.Kind != evidence.ContextContainer {
			continue
		}
		switch {
		case ev.Source == engine.ProcListenerSource:
			t.Errorf("on %s, whyreach read %s's listening sockets through /proc/<pid> on this machine (%s)", l.platform, ev.Context.Name, ev.Status)
		case ev.OK() && ev.Context.Executor != evidence.ExecutorProbeContainer:
			t.Errorf("on %s, %s's listeners were read by %q (%s), not in a probe container", l.platform, ev.Context.Name, ev.Context.Executor, ev.Source)
		}
	}
}

// suppressedAsFindings lists the suppressed findings' rules and titles,
// which must_not_fire covers too.
func suppressedAsFindings(d *engine.Diagnosis) []rules.Finding {
	var out []rules.Finding
	for _, s := range d.Suppressed {
		out = append(out, rules.Finding{RuleID: s.RuleID, Title: s.Title})
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
