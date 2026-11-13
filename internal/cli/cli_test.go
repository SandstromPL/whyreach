package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/rules"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/cli -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs (run go test ./internal/cli -update):\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

var (
	workerID = strings.Repeat("b", 64)
	apiID    = strings.Repeat("a", 64)
	question = evidence.Question{
		From: evidence.Source{Kind: evidence.SourceContainer, Ref: "container:shop-worker-1", ContainerID: workerID},
		To:   evidence.Target{Host: "api", Port: 8080, Proto: "tcp", Class: evidence.TargetName},
	}
	workerEv = evidence.Evidence{
		ID: "ev-02", Kind: evidence.KindContainer, Status: evidence.StatusOK,
		Context: evidence.ContextRef{Kind: evidence.ContextContainer, Container: workerID[:12], Name: "worker"},
		Data:    evidence.Container{ID: workerID, Name: "shop-worker-1", State: evidence.StateRunning, Compose: &evidence.ComposeRef{Project: "shop", Service: "worker"}},
	}
)

func diagnoses() map[string]*engine.Diagnosis {
	wr002 := rules.Finding{
		RuleID: "WR002", Title: "api listens only on 127.0.0.1:8080 inside its container", Layer: rules.LayerListener,
		Confidence: rules.High, Supporting: []string{"ev-03", "ev-04", "ev-06"},
		Explanation: "api's only listener for port 8080 is 127.0.0.1:8080 (in api). A socket bound to loopback accepts connections only from inside api's own network namespace, so worker can't reach it.",
		Fix:         "Make the server in api listen on 0.0.0.0:8080 (or [::]:8080), for example with --host 0.0.0.0 or a HOST=0.0.0.0 setting, then restart api.",
		DocURL:      "docs/rules/WR002.md",
	}
	wr004 := rules.Finding{
		RuleID: "WR004", Title: "worker and api share no network", Layer: rules.LayerNaming, Confidence: rules.High,
		Supporting:  []string{"ev-02", "ev-03"},
		Explanation: "api is on network a_default (Compose project a), and worker only on network b_default (Compose project b).",
		Fix:         "Put worker on api's network.", DocURL: "docs/rules/WR004.md",
	}
	base := func() *engine.Diagnosis {
		return &engine.Diagnosis{
			ID: "dg-test", SchemaVersion: engine.SchemaVersion, Question: question,
			Findings: []rules.Finding{}, Facts: []engine.Fact{}, Gaps: []engine.Gap{}, SideEffects: []string{},
			Evidence: []evidence.Evidence{workerEv}, Timing: engine.Timing{StartedAt: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC), TotalMS: 180},
		}
	}
	cause := base()
	cause.Verdict = engine.VerdictCause
	cause.Summary = "worker can't reach api:8080: " + wr002.Title + "."
	cause.Findings = []rules.Finding{wr002}
	cause.Facts = []engine.Fact{
		{Text: "worker and api share network shop_default", Evidence: []string{"ev-02", "ev-03"}},
		{Text: `"api" → 172.22.0.3 via 127.0.0.11:53, in worker`, Evidence: []string{"ev-05"}},
		{Text: "connect 172.22.0.3:8080 from worker: refused, ECONNREFUSED (0.1 ms)", Evidence: []string{"ev-06"}},
		{Text: "listening on port 8080 in api: 127.0.0.1:8080/tcp", Evidence: []string{"ev-04"}},
	}
	cause.SideEffects = []string{"ephemeral probe container wr-probe-3f2a9c1d (removed)"}

	also := base()
	also.Verdict = engine.VerdictCause
	also.Summary = "worker can't reach api:8080: worker and api share no network."
	also.Findings = []rules.Finding{wr004, wr002}

	ok := base()
	ok.Verdict = engine.VerdictNoProblem
	ok.Summary = "worker connected to api:8080 (172.22.0.3:8080): no problem reproduced."
	ok.Facts = []engine.Fact{{Text: "connect 172.22.0.3:8080 from worker: connected (0.2 ms)", Evidence: []string{"ev-06"}}}

	inconclusive := base()
	inconclusive.Verdict = engine.VerdictInconclusive
	inconclusive.Summary = "No cause found for worker → api:8080, but 1 thing could not be checked (see gaps)."
	inconclusive.Gaps = []engine.Gap{{
		What: "name lookup and TCP connect from worker", Why: "permission", Detail: "probe containers are off (tier 2b)",
		HowToEnable: "Enable probe containers: set probe_containers = true under [permissions] in ~/.config/whyreach/config.toml.",
	}}
	return map[string]*engine.Diagnosis{"cause": cause, "also-found": also, "no-problem": ok, "inconclusive": inconclusive}
}

func TestRenderTextGolden(t *testing.T) {
	for name, d := range diagnoses() {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			RenderText(&b, d)
			golden(t, "text-"+name+".golden", b.Bytes())
		})
	}
}

func TestDiagnosisJSONGolden(t *testing.T) {
	d := diagnoses()["cause"]
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "json-cause.golden", append(b, '\n'))
	// Agents read the structured form first: it must lead with the verdict.
	if !bytes.HasPrefix(b, []byte("{\n  \"verdict\": \"cause_identified\",\n  \"summary\":")) {
		t.Errorf("JSON must lead with verdict and summary:\n%s", b[:80])
	}
}

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

func (fakeDocker) Host() ([]evidence.Socket, error) { return nil, nil }

func (fakeDocker) Container(pid int, _ string) ([]evidence.Socket, error) {
	if pid == 20 {
		return []evidence.Socket{{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.1:8080")}}, nil
	}
	return nil, nil
}

func execute(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), args, Options{
		Version: "test", Stdout: &stdout, Stderr: &stderr, Getenv: func(string) string { return "" },
		NewEngine: func(_ Options, logger *slog.Logger) (*engine.Engine, error) {
			return engine.New(engine.Deps{Docker: fakeDocker{}, Listeners: fakeDocker{}, Logger: logger}), nil
		},
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
		NewEngine: func(_ Options, logger *slog.Logger) (*engine.Engine, error) {
			logger.Debug("hello from the engine")
			return engine.New(engine.Deps{Docker: fakeDocker{}, Listeners: fakeDocker{}, Logger: logger}), nil
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

func TestRenderTextSanitizesDockerStrings(t *testing.T) {
	d := diagnoses()["cause"]
	evil := "api\x1b[2J\x1b]0;pwned\x07\u202eexe.txt"
	d.Findings[0].Title = evil
	d.Facts[0].Text = evil
	d.SideEffects = []string{evil}
	var b bytes.Buffer
	RenderText(&b, d)
	out := b.String()
	for _, bad := range []string{"\x1b", "\x07", "\u202e"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q:\n%q", bad, out)
		}
	}
	if !strings.Contains(out, "api\uFFFD[2J") {
		t.Errorf("want the escape replaced, not dropped:\n%q", out)
	}
	if got := Sanitize("a\tb\nc\rd"); got != "a\tb\nc\uFFFDd" {
		t.Errorf("Sanitize = %q", got)
	}
}
