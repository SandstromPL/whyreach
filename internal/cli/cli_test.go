package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/policy"
)

var (
	workerID = strings.Repeat("b", 64)
	apiID    = strings.Repeat("a", 64)
	dbID     = strings.Repeat("d", 64)
)

// fakeDocker is a tiny Docker host for command tests: worker and api share
// a network, and api is bound to loopback. With db set, shop-db-1 joins
// them, listening on 5432 and publishing dbPorts.
type fakeDocker struct {
	db      bool
	dbPorts []evidence.PortMap
}

func (fakeDocker) Negotiate(context.Context) (docker.Version, error) {
	return docker.Version{Version: "29.9.3", APIVersion: "1.56", Os: "linux", Arch: "amd64"}, nil
}
func (fakeDocker) Endpoint() string   { return "unix:///var/run/docker.sock" }
func (fakeDocker) APIVersion() string { return "1.56" }

func (f fakeDocker) containers() []evidence.Container {
	mk := func(id, name, svc, ip string, pid int) evidence.Container {
		return evidence.Container{
			ID: id, Name: name, State: evidence.StateRunning, Pid: pid, NetworkMode: "shop_default",
			Compose:  &evidence.ComposeRef{Project: "shop", Service: svc},
			Networks: []evidence.NetAttachment{{Network: "shop_default", IPv4: netip.MustParseAddr(ip), Names: []string{name, svc}}},
		}
	}
	out := []evidence.Container{mk(workerID, "shop-worker-1", "worker", "172.22.0.2", 10), mk(apiID, "shop-api-1", "api", "172.22.0.3", 20)}
	if f.db {
		db := mk(dbID, "shop-db-1", "db", "172.22.0.4", 30)
		db.Ports = f.dbPorts
		out = append(out, db)
	}
	return out
}

func (f fakeDocker) ListContainers(context.Context, bool, ...string) ([]docker.Summary, error) {
	var out []docker.Summary
	for _, c := range f.containers() {
		out = append(out, docker.Summary{ID: c.ID, Names: []string{"/" + c.Name}, State: c.State, Labels: map[string]string{
			docker.LabelComposeProject: c.Compose.Project, docker.LabelComposeService: c.Compose.Service,
		}})
	}
	return out, nil
}

func (f fakeDocker) InspectContainer(_ context.Context, ref string) (evidence.Container, error) {
	for _, c := range f.containers() {
		if c.ID == ref || c.Name == ref {
			return c, nil
		}
	}
	return evidence.Container{}, &docker.APIError{Status: 404, Message: "No such container"}
}

func (fakeDocker) ListNetworks(context.Context) ([]docker.Network, error) {
	return []docker.Network{{ID: "n1", Name: "shop_default", Driver: "bridge", Subnets: []netip.Prefix{netip.MustParsePrefix("172.22.0.0/16")}}}, nil
}

func (fakeDocker) InspectNetwork(_ context.Context, ref string) (docker.Network, error) {
	if ref != "shop_default" {
		return docker.Network{}, &docker.APIError{Status: 404, Message: "network not found"}
	}
	return docker.Network{ID: "n1", Name: "shop_default", Driver: "bridge", Subnets: []netip.Prefix{netip.MustParsePrefix("172.22.0.0/16")}}, nil
}

func (fakeDocker) Host() ([]evidence.Socket, error) { return nil, nil }

func (fakeDocker) Container(pid int, _ string) ([]evidence.Socket, error) {
	switch pid {
	case 20:
		return []evidence.Socket{{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.1:8080")}}, nil
	case 30:
		return []evidence.Socket{{Proto: "tcp", Local: netip.MustParseAddrPort("0.0.0.0:5432")}}, nil
	}
	return nil, nil
}

// fakePolicy builds a policy over the fake Docker host, with probe
// containers off and no audit log.
func fakePolicy(_ Options, logger *slog.Logger, client string) (*policy.Policy, error) {
	return policy.New(policy.Deps{
		Settings: policy.Settings{Docker: true, ConfigPath: "/test/config.toml"},
		Docker:   fakeDocker{}, Listeners: fakeDocker{}, Client: client, Logger: logger,
	})
}

func execute(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), args, Options{
		Version: "test", Stdout: &stdout, Stderr: &stderr, Getenv: func(string) string { return "" },
		NewPolicy: fakePolicy,
	})
	return code, stdout.String(), stderr.String()
}

func TestCommands(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		code      int
		stdout    string
		stderr    string
		notStdout string
	}{
		{name: "version", args: []string{"version"}, code: ExitNoProblem, stdout: "whyreach test"},
		{name: "--version", args: []string{"--version"}, code: ExitNoProblem, stdout: "whyreach test"},
		{name: "short form finds the cause", args: []string{"--from", "container:shop-worker-1", "api:8080"}, code: ExitCause, stdout: "WR002"},
		{name: "diagnose subcommand", args: []string{"diagnose", "--from", "container:shop-worker-1", "api:8080"}, code: ExitCause, stdout: "cause identified (high)"},
		{name: "json", args: []string{"--from", "container:shop-worker-1", "api:8080", "--json"}, code: ExitCause, stdout: `"verdict": "cause_identified"`},
		{name: "no arguments", args: nil, code: ExitUsage, stderr: "missing HOST:PORT"},
		{name: "diagnose without target", args: []string{"diagnose"}, code: ExitUsage, stderr: "exactly one HOST:PORT"},
		{name: "two targets", args: []string{"api:8080", "db:5432"}, code: ExitUsage},
		{name: "unknown flag", args: []string{"--fro", "x", "api:8080"}, code: ExitUsage, stderr: "unknown flag"},
		{name: "bad source", args: []string{"--from", "pod:x", "api:8080"}, code: ExitUsage, stderr: "invalid from"},
		{name: "CIDR target", args: []string{"--from", "container:shop-worker-1", "10.0.0.0/8:80"}, code: ExitUsage, stderr: "one host:port per call"},
		{name: "metadata address", args: []string{"169.254.169.254:80"}, code: ExitUsage, stderr: "blocked by policy"},
		{name: "unknown container", args: []string{"--from", "container:nope", "api:8080"}, code: ExitUsage, stderr: `no container named "nope"`},
		{name: "probe with a bad spec", args: []string{"__probe", "--spec", "[]"}, code: ExitInternal, stderr: "want 1 to"},
		{name: "probe is hidden", args: []string{"--help"}, code: ExitNoProblem, stdout: "diagnose", notStdout: "__probe"},
		{name: "inspect a container", args: []string{"inspect", "container", "shop-api-1"}, code: ExitNoProblem, stdout: "shop-api-1"},
		{name: "inspect a network", args: []string{"inspect", "network", "shop_default", "--json"}, code: ExitNoProblem, stdout: `"driver": "bridge"`},
		{name: "inspect an unknown container", args: []string{"inspect", "container", "nope"}, code: ExitUsage, stderr: "no container"},
		{name: "inspect with no scope", args: []string{"inspect"}, code: ExitUsage, stderr: "want: inspect host"},
		{name: "probe listeners in a container", args: []string{"probe", "listeners", "--from", "container:shop-api-1"}, code: ExitNoProblem, stdout: "127.0.0.1:8080"},
		{name: "probe from a container needs tier 2b", args: []string{"probe", "tcp", "api:8080", "--from", "container:shop-worker-1"}, code: ExitNoProblem, stdout: "permission_denied: probe containers are"},
		{name: "probe with a bad kind", args: []string{"probe", "icmp", "api"}, code: ExitUsage, stderr: "want: probe tcp"},
		{name: "probe a CIDR", args: []string{"probe", "tcp", "10.0.0.0/8:80"}, code: ExitUsage, stderr: "one host:port per call"},
		{name: "doctor", args: []string{"doctor"}, code: ExitNoProblem, stdout: "whyreach is ready"},
		{name: "doctor json", args: []string{"doctor", "--json"}, code: ExitNoProblem, stdout: `"name": "container listeners"`},
		{name: "mcp without a server", args: []string{"mcp", "serve"}, code: ExitInternal, stderr: "no MCP server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := execute(t, tt.args...)
			if code != tt.code {
				t.Errorf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tt.code, stdout, stderr)
			}
			if !strings.Contains(stdout, tt.stdout) {
				t.Errorf("stdout lacks %q:\n%s", tt.stdout, stdout)
			}
			if !strings.Contains(stderr, tt.stderr) {
				t.Errorf("stderr lacks %q:\n%s", tt.stderr, stderr)
			}
			if tt.notStdout != "" && strings.Contains(stdout, tt.notStdout) {
				t.Errorf("stdout shows %q:\n%s", tt.notStdout, stdout)
			}
		})
	}
}

// fullWriter fails every write, as stdout redirected to /dev/full does.
type fullWriter struct{}

func (fullWriter) Write([]byte) (int, error) {
	return 0, errors.New("write /dev/full: no space left on device")
}

// A command whose output can't be written exits 4 (internal), never 3: the
// caller made no mistake.
func TestFailedWriteIsInternal(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))
	run := func(stdout io.Writer, args ...string) (int, string) {
		var stderr bytes.Buffer
		code := Execute(context.Background(), args, Options{
			Version: "test", Stdout: stdout, Stderr: &stderr, Getenv: func(string) string { return "" }, NewPolicy: fakePolicy,
		})
		return code, stderr.String()
	}
	for _, args := range [][]string{{"report", "list"}, {"report", "list", "--json"}} { // no bundles yet
		if code, stderr := run(fullWriter{}, args...); code != ExitInternal {
			t.Errorf("%q: exit %d, want %d (%s)", args, code, ExitInternal, stderr)
		}
	}
	var saved bytes.Buffer
	if code, stderr := run(&saved, "--from", "container:shop-worker-1", "api:8080", "--json", "--report"); code != ExitCause {
		t.Fatalf("diagnose --report: exit %d (%s)", code, stderr)
	}
	var d struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(saved.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"version"},
		{"rules", "list"},
		{"rules", "list", "--json"},
		{"rules", "explain", "WR002"},
		{"doctor"},
		{"doctor", "--json"},
		{"inspect", "container", "shop-api-1", "--json"},
		{"probe", "listeners", "--from", "container:shop-api-1", "--json"},
		{"--from", "container:shop-worker-1", "api:8080", "--json"},
		{"report", "list"},
		{"report", "list", "--json"},
		{"report", "show", d.ID},
		{"report", "export", d.ID},
	} {
		if code, stderr := run(fullWriter{}, args...); code != ExitInternal || !strings.Contains(stderr, "no space left") {
			t.Errorf("%q: exit %d, want %d (%s)", args, code, ExitInternal, stderr)
		}
	}
}

// deniedListeners reads no container's listeners: /proc refuses them, as
// with hidepid=1.
type deniedListeners struct{ fakeDocker }

func (deniedListeners) Container(pid int, _ string) ([]evidence.Socket, error) {
	return nil, fmt.Errorf("open /proc/%d/net/tcp: %w", pid, fs.ErrPermission)
}

// A listener read that /proc refuses is no matter for probe containers,
// which never read listeners on Docker Engine: probe listeners must not
// advise them.
func TestListenersDeniedAdvice(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"probe", "listeners", "--from", "container:shop-api-1"}, Options{
		Version: "test", Stdout: &stdout, Stderr: &stderr, Getenv: func(string) string { return "" },
		NewPolicy: func(_ Options, logger *slog.Logger, client string) (*policy.Policy, error) {
			return policy.New(policy.Deps{
				Settings: policy.Settings{Docker: true, ConfigPath: "/test/config.toml"},
				Docker:   fakeDocker{}, Listeners: deniedListeners{}, Client: client, Logger: logger,
			})
		},
	})
	if code != ExitNoProblem || !strings.Contains(stdout.String(), "permission_denied") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "probe containers") {
		t.Errorf("a refused listener read advises probe containers:\n%s", stdout.String())
	}
	// Checks probe containers would run still say how to allow them.
	p, err := fakePolicy(Options{}, slog.New(slog.DiscardHandler), policy.ClientCLI)
	if err != nil {
		t.Fatal(err)
	}
	howTo := probeHowTo(p)
	for _, msg := range []string{executor.ProbeContainersOff, executor.ErrCannotEnter.Error() + ": operation not permitted"} {
		e := evidence.Evidence{Kind: evidence.KindTCP, Status: evidence.StatusPermissionDenied, Err: &evidence.Error{Code: evidence.CodePermissionDenied, Message: msg}}
		if !strings.Contains(howTo(e), "probe_containers = true") {
			t.Errorf("%s: advice %q", msg, howTo(e))
		}
	}
}

func TestProbeSubcommandWritesEvidence(t *testing.T) {
	code, stdout, stderr := execute(t, "__probe", "--spec", `[{"kind":"listeners"}]`)
	if code != ExitNoProblem {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var ev evidence.Evidence
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &ev); err != nil || ev.Kind != evidence.KindListeners {
		t.Errorf("stdout is not one listeners record: %v\n%s", err, stdout)
	}
}

func TestLogsGoToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	Execute(context.Background(), []string{"--from", "container:shop-worker-1", "api:8080", "--json"}, Options{
		Version: "test", Stdout: &stdout, Stderr: &stderr, Getenv: func(k string) string {
			if k == "WHYREACH_LOG" {
				return "debug"
			}
			return ""
		},
		NewPolicy: func(o Options, logger *slog.Logger, client string) (*policy.Policy, error) {
			logger.Debug("hello from the engine")
			return fakePolicy(o, logger, client)
		},
	})
	var d engine.Diagnosis
	if err := json.Unmarshal(stdout.Bytes(), &d); err != nil {
		t.Errorf("stdout must hold only the JSON: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "hello from the engine") {
		t.Errorf("debug log missing from stderr: %s", stderr.String())
	}
}

// In a container without --network host, whyreach's own namespace must not
// pass for the host's: a host target gets unsupported gaps that say how to
// fix it, never a finding about the host (M4 correctness review).
func TestHiddenHostIsAGap(t *testing.T) {
	// A container on the port, published elsewhere or not at all, mustn't
	// stand in for the host's own listeners: the host may serve 5432 itself.
	for name, dk := range map[string]fakeDocker{
		"no db":                     {},
		"db published as 15432":     {db: true, dbPorts: []evidence.PortMap{{ContainerPort: 5432, Proto: "tcp", HostPort: 15432}}},
		"db listens, not published": {db: true},
	} {
		t.Run(name, func(t *testing.T) {
			deps := policy.Deps{
				Settings: policy.Settings{Docker: true, ConfigPath: "/test/config.toml"},
				Docker:   dk, Listeners: dk, Client: policy.ClientCLI,
				Interfaces: func() (evidence.HostAddrs, error) { return evidence.HostAddrs{}, nil },
			}
			hideHost(&deps)
			p, err := policy.New(deps)
			if err != nil {
				t.Fatal(err)
			}
			for _, args := range []policy.DiagnoseArgs{{From: "host", To: "localhost:5432"}, {From: "container:shop-worker-1", To: "host.docker.internal:5432"}} {
				d, err := p.Diagnose(context.Background(), args)
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range d.Findings {
					if f.RuleID == "WR001" || f.RuleID == "WR012" || f.RuleID == "WR019" {
						t.Errorf("%v: %s judged the host from whyreach's own namespace: %s", args, f.RuleID, f.Title)
					}
				}
				if args.From == "host" && d.Verdict != "inconclusive" {
					t.Errorf("%v: %s, want inconclusive", args, d.Verdict)
				}
				advised := false
				for _, g := range d.Gaps {
					advised = advised || (g.Why == "unsupported" && strings.Contains(g.HowToEnable, "--network host"))
				}
				if !advised {
					t.Errorf("%v: no gap says to run with --network host: %+v", args, d.Gaps)
				}
			}
			// Containers' listeners, read through /proc/<pid> (--pid host), stay.
			in, err := p.Inspect(context.Background(), "container:shop-api-1")
			if err != nil || !strings.Contains(strings.Join(in.Container.Listening, " "), "127.0.0.1:8080") {
				t.Errorf("container listeners: %+v, %v", in, err)
			}
		})
	}
}

// selfDocker answers inspects of the containers it holds.
type selfDocker struct {
	fakeDocker
	cs map[string]evidence.Container
}

func (d selfDocker) InspectContainer(_ context.Context, ref string) (evidence.Container, error) {
	if c, ok := d.cs[ref]; ok {
		return c, nil
	}
	return evidence.Container{}, &docker.APIError{Status: 404, Message: "No such container"}
}

// Docker's record of whyreach's own container decides whether it shares
// the host's network and PIDs; the Docker bridge in sight decides the
// network only without it.
func TestViewFromContainer(t *testing.T) {
	own, other, unknown := strings.Repeat("e", 64), strings.Repeat("f", 64), strings.Repeat("0", 64)
	proc := t.TempDir()
	if err := os.Mkdir(filepath.Join(proc, "4242"), 0o700); err != nil { // a host PID in sight
		t.Fatal(err)
	}
	mode := func(m string, pid int) selfDocker {
		return selfDocker{cs: map[string]evidence.Container{own: {ID: own, NetworkMode: m, Pid: pid}, other: {ID: other, NetworkMode: "host", Pid: 99}}}
	}
	tests := []struct {
		name   string
		dk     engine.Docker
		id     string
		bridge bool
		want   view
	}{
		{"--network host --pid host, with no bridge named docker0 or br-*", mode("host", 4242), own, false, view{network: true, pids: true}},
		{"--network host without --pid host", mode("host", 777), own, true, view{network: true}},
		{"the default bridge, whatever the interfaces show", mode("bridge", 777), own, true, view{}},
		{"a user-defined network, --pid host", mode("shop_default", 4242), own, true, view{pids: true}},
		{"joined to a container on the host's network", mode("container:"+other, 4242), own, false, view{network: true, pids: true}},
		{"Docker doesn't know it, a bridge in sight", mode("host", 4242), unknown, true, view{network: true, pids: true}},
		{"Docker doesn't know it, no bridge in sight", mode("host", 4242), unknown, false, view{pids: true}},
		{"no Docker", nil, own, false, view{pids: true}},
		{"no container ID", mode("host", 4242), "", false, view{pids: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := viewFromContainer(context.Background(), tt.dk, tt.id, func() bool { return tt.bridge }, proc, slog.New(slog.DiscardHandler))
			if got != tt.want {
				t.Errorf("view = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Without the host's PIDs, a container's listeners are an unsupported
// record with the advice, never a bare "no such file".
func TestHiddenPIDsIsAGap(t *testing.T) {
	deps := policy.Deps{
		Settings: policy.Settings{Docker: true, ConfigPath: "/test/config.toml"},
		Docker:   fakeDocker{}, Listeners: hiddenPIDs{fakeDocker{}}, Client: policy.ClientCLI,
		Interfaces: func() (evidence.HostAddrs, error) { return evidence.HostAddrs{}, nil },
	}
	p, err := policy.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	d, err := p.Diagnose(context.Background(), policy.DiagnoseArgs{From: "container:shop-worker-1", To: "localhost:8080"})
	if err != nil {
		t.Fatal(err)
	}
	advised := false
	for _, g := range d.Gaps {
		advised = advised || (g.Why == "unsupported" && strings.Contains(g.HowToEnable, "--pid host"))
	}
	if !advised {
		t.Errorf("no gap says to run with --pid host: %+v", d.Gaps)
	}
}
