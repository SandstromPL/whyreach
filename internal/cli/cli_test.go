package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/policy"
)

var (
	workerID = strings.Repeat("b", 64)
	apiID    = strings.Repeat("a", 64)
)

// fakeDocker is a tiny Docker host for command tests: worker and api share
// a network, and api is bound to loopback.
type fakeDocker struct{}

func (fakeDocker) Negotiate(context.Context) (docker.Version, error) {
	return docker.Version{Version: "29.9.3", APIVersion: "1.56", Os: "linux", Arch: "amd64"}, nil
}
func (fakeDocker) Endpoint() string   { return "unix:///var/run/docker.sock" }
func (fakeDocker) APIVersion() string { return "1.56" }

func (fakeDocker) containers() []evidence.Container {
	mk := func(id, name, svc, ip string, pid int) evidence.Container {
		return evidence.Container{
			ID: id, Name: name, State: evidence.StateRunning, Pid: pid, NetworkMode: "shop_default",
			Compose:  &evidence.ComposeRef{Project: "shop", Service: svc},
			Networks: []evidence.NetAttachment{{Network: "shop_default", IPv4: netip.MustParseAddr(ip), Names: []string{name, svc}}},
		}
	}
	return []evidence.Container{mk(workerID, "shop-worker-1", "worker", "172.22.0.2", 10), mk(apiID, "shop-api-1", "api", "172.22.0.3", 20)}
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
	if pid == 20 {
		return []evidence.Socket{{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.1:8080")}}, nil
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
