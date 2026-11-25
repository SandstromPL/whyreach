//go:build lab && realcases

package e2e

// The real-case check (docs/research/real-cases.md, INITIAL.md §6.5). Each
// case in test/realcases/<case>/ is a broken setup rebuilt from a Stack
// Overflow question, a Docker forum topic or a GitHub issue. The harness
// brings it up, checks that it fails the way the asker said (the symptom
// check: a plain connect, no whyreach), then runs whyreach with probe
// containers on and with the default config, and writes what whyreach said
// to bin/realcases/results.json, masked like the benchmark's results. It
// knows nothing of the labels: docs/research/real-cases/score.py compares
// the two afterwards.

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/test/bench"
)

var (
	rcSymptomsOnly = flag.Bool("realcases.symptoms-only", false, "bring each case up and check its symptom only; don't run whyreach")
	rcOnly         = flag.String("realcases.only", "", "comma-separated case names to run (default: every case)")
)

// realCase is test/realcases/<case>/case.yaml (test/realcases/README.md).
type realCase struct {
	Source        string   `yaml:"source"`
	Author        string   `yaml:"author"`
	Licence       string   `yaml:"licence"`
	Asked         string   `yaml:"asked"`
	Projects      []string `yaml:"projects"`
	UpWait        *bool    `yaml:"up_wait"`
	SettleSeconds *int     `yaml:"settle_seconds"`
	HostListen    []string `yaml:"host_listen"`
	From          string   `yaml:"from"`
	To            string   `yaml:"to"`
	Symptom       string   `yaml:"symptom"`
	Images        []string `yaml:"images"`
	Stubbed       []struct {
		What string `yaml:"what"`
		How  string `yaml:"how"`
		Why  string `yaml:"why"`
	} `yaml:"stubbed"`
	Assumptions []string `yaml:"assumptions"`
	Read        []string `yaml:"read"`
}

type rcResult struct {
	Case    string    `json:"case"`
	Source  string    `json:"source"`
	Symptom rcSymptom `json:"symptom"`
	Runs    []rcRun   `json:"runs,omitempty"`
	Error   string    `json:"error,omitempty"`
}

type rcSymptom struct {
	Want   string `json:"want"`
	Got    string `json:"got"`
	Detail string `json:"detail,omitempty"`
	Match  bool   `json:"match"`
}

type rcRun struct {
	Config      string      `json:"config"`
	Verdict     string      `json:"verdict"`
	Summary     string      `json:"summary"`
	Findings    []rcFinding `json:"findings"` // primary first
	Suppressed  []string    `json:"suppressed,omitempty"`
	Gaps        int         `json:"gaps"`
	SideEffects int         `json:"side_effects"`
}

type rcFinding struct {
	Rule       string `json:"rule"`
	Confidence string `json:"confidence"`
	Fix        string `json:"fix"`
}

func TestRealCases(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run as yourself: as root whyreach enters network namespaces itself, which isn't how the check is defined")
	}
	dirs := realCaseDirs(t)
	m := newBenchMasker(t)
	var results []rcResult
	t.Cleanup(func() { writeRealCaseResults(t, m, results) })
	// One after another, like the lab: cases reuse service names, and a
	// diagnosis looks at every container on the host.
	for _, dir := range dirs {
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			r := rcResult{Case: name}
			defer func() {
				if r.Symptom.Got == "" && r.Error == "" {
					r.Error = "the case didn't come up (see the test log)"
				}
				results = append(results, r)
			}()
			runRealCase(t, m, dir, &r)
		})
	}
}

func realCaseDirs(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "realcases", "*", "case.yaml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no cases in test/realcases: %v", err)
	}
	var only []string
	if *rcOnly != "" {
		only = strings.Split(*rcOnly, ",")
	}
	slices.Sort(paths)
	var dirs []string
	for _, p := range paths {
		d := filepath.Dir(p)
		if only == nil || slices.Contains(only, filepath.Base(d)) {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

func runRealCase(t *testing.T, m *bench.Masker, dir string, r *rcResult) {
	var c realCase
	b, err := os.ReadFile(filepath.Join(dir, "case.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("case.yaml: %v", err)
	}
	r.Source = c.Source
	if c.From == "" || c.To == "" || c.Symptom == "" {
		t.Fatal("case.yaml needs from, to and symptom")
	}
	for _, img := range c.Images {
		if err := exec.CommandContext(context.Background(), "docker", "image", "inspect", img).Run(); err != nil {
			r.Error = "image not present: " + img
			t.Skipf("%s isn't present and the check pulls nothing: docker pull %s", img, img)
		}
	}
	if len(c.Projects) == 0 {
		c.Projects = []string{"compose.yaml"}
	}
	project := "whyreach-lab-" + randHex(4)
	vars := map[string]string{"${PROJECT}": project, "${LAB_PORT}": freePort(t)}
	if len(c.HostListen) > 0 {
		vars["${HOST_PORT}"] = hostListen(t, c.HostListen)
	}
	for _, file := range c.Projects {
		p := projectFor(project, file)
		rcUp(t, dir, p, file, c.UpWait == nil || *c.UpWait, vars)
		for _, n := range rcNetworks(p) {
			for _, s := range networkSubnets(t, n) {
				m.Keep(s)
			}
		}
	}
	settleFor := 15
	if c.SettleSeconds != nil {
		settleFor = *c.SettleSeconds
	}
	time.Sleep(time.Duration(settleFor) * time.Second)
	expand := func(v string) string {
		for k, val := range vars {
			v = strings.ReplaceAll(v, k, val)
		}
		return v
	}
	from, to := expand(c.From), expand(c.To)
	got, detail := symptomCheck(t, from, to)
	r.Symptom = rcSymptom{Want: c.Symptom, Got: got, Detail: m.String(detail), Match: symptomMatches(c.Symptom, got)}
	t.Logf("symptom: want %s, got %s %s", c.Symptom, got, detail)
	if !r.Symptom.Match {
		t.Errorf("the rebuild doesn't fail the way the asker said: want %s, got %s (%s)", c.Symptom, got, detail)
		return
	}
	if *rcSymptomsOnly {
		return
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	runs := filepath.Join(root, "bin", "realcases", "runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, run := range []struct{ name, config string }{{"probe-containers", l.withProbe}, {"default-config", l.noProbe}} {
		d := diagnose(t, run.config, from, to)
		// The whole diagnosis stays on this machine, unmasked, for reading
		// afterwards; only the summary below is published.
		if raw, err := json.MarshalIndent(d, "", " "); err == nil {
			_ = os.WriteFile(filepath.Join(runs, r.Case+"."+run.name+".json"), raw, 0o600)
		}
		r.Runs = append(r.Runs, summarizeRun(m, run.name, d))
	}
}

// rcUp brings one Compose file up; the test's cleanup takes it down.
func rcUp(t *testing.T, dir, project, file string, wait bool, vars map[string]string) {
	t.Helper()
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(context.Background(), "docker", append([]string{"compose", "-p", project, "-f", file}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "WHYREACH_LAB_IMAGE="+l.image, "LAB_PORT="+vars["${LAB_PORT}"],
			"HOST_PORT="+vars["${HOST_PORT}"], "REALCASE_PROJECT="+project)
		return cmd.CombinedOutput()
	}
	t.Cleanup(func() {
		if out, err := run("down", "-v", "--remove-orphans", "--timeout", "1"); err != nil {
			t.Errorf("compose down %s: %v\n%s", project, err, out)
		}
	})
	args := []string{"up", "-d", "--pull", "never"}
	if wait {
		args = append(args, "--wait", "--wait-timeout", "90")
	}
	if out, err := run(args...); err != nil {
		t.Fatalf("compose up %s: %v\n%s", project, err, out)
	}
}

// rcNetworks lists a Compose project's networks.
func rcNetworks(project string) []string {
	out, err := exec.CommandContext(context.Background(), "docker", "network", "ls",
		"--filter", "label=com.docker.compose.project="+project, "--format", "{{.Name}}").Output()
	if err != nil {
		return nil
	}
	return strings.Fields(string(out))
}

// symptomCheck connects from the case's source to its target as the
// asker's app did, without whyreach: from the host, a dial here; from a
// container, the lab server's check (a one-second connect) in a container
// that shares the source's network namespace, and with it the source's
// /etc/hosts and resolv.conf.
func symptomCheck(t *testing.T, from, to string) (got, detail string) {
	t.Helper()
	if from == "host" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", to)
		if err != nil {
			return classifyConnect(err.Error()), err.Error()
		}
		_ = c.Close()
		return "connected", ""
	}
	svc, project, ok := strings.Cut(strings.TrimPrefix(from, "service:"), "@")
	if !ok || !strings.HasPrefix(from, "service:") {
		t.Fatalf("from %q: want host or service:<service>@<project>", from)
	}
	out, err := exec.CommandContext(context.Background(), "docker", "ps", "-q",
		"--filter", "label=com.docker.compose.project="+project,
		"--filter", "label=com.docker.compose.service="+svc).Output()
	ids := strings.Fields(string(out))
	if err != nil || len(ids) == 0 {
		return "source-not-running", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--name", "whyreach-lab-symptom-"+randHex(4),
		"--label", labLabel, "--pull", "never", "--network", "container:"+ids[0], l.image, "check", to).CombinedOutput()
	if err == nil {
		return "connected", ""
	}
	msg := strings.TrimSpace(string(res))
	return classifyConnect(msg), msg
}

// classifyConnect names a failed connect by its error, as the asker's app
// would have seen it.
func classifyConnect(msg string) string {
	switch {
	case strings.Contains(msg, "lookup "):
		return "name-not-found"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "network is unreachable"):
		return "no-route"
	case strings.Contains(msg, "connection reset"):
		return "reset-or-closed"
	}
	return "other"
}

func symptomMatches(want, got string) bool {
	switch want {
	case "failure":
		return got != "connected" && got != "source-not-running"
	case "reset-or-closed":
		// A connect alone can't see a server that accepts and then closes.
		return got == "reset-or-closed" || got == "connected"
	}
	return want == got
}

func summarizeRun(m *bench.Masker, config string, d *engine.Diagnosis) rcRun {
	r := rcRun{Config: config, Verdict: d.Verdict, Summary: m.String(d.Summary), Gaps: len(d.Gaps), SideEffects: len(d.SideEffects)}
	for _, f := range d.Findings {
		r.Findings = append(r.Findings, rcFinding{Rule: f.RuleID, Confidence: string(f.Confidence), Fix: m.String(f.Fix)})
	}
	for _, s := range d.Suppressed {
		r.Suppressed = append(r.Suppressed, s.RuleID+" by "+s.By)
	}
	return r
}

// writeRealCaseResults writes bin/realcases/results.json, refusing if the
// masked text still shows anything private.
func writeRealCaseResults(t *testing.T, m *bench.Masker, results []rcResult) {
	t.Helper()
	if len(results) == 0 {
		return
	}
	slices.SortFunc(results, func(a, b rcResult) int { return strings.Compare(a.Case, b.Case) })
	docker, _ := exec.CommandContext(context.Background(), "docker", "version", "--format", "{{.Server.Version}}").Output()
	commit, _ := exec.CommandContext(context.Background(), "git", "rev-parse", "--short", "HEAD").Output()
	doc := map[string]any{
		"date":           time.Now().UTC().Format(time.DateOnly),
		"whyreach":       strings.TrimSpace(string(commit)),
		"docker_engine":  strings.TrimSpace(string(docker)),
		"platform":       l.platform,
		"symptoms_only":  *rcSymptomsOnly,
		"cases":          results,
		"case_count":     len(results),
		"symptom_checks": "labserver check: a one-second TCP connect from the source's network namespace",
	}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Error(err)
		return
	}
	if leaks := m.Leaks(string(b)); len(leaks) > 0 {
		t.Errorf("results not written: the masked text still shows %v", leaks)
		return
	}
	root, err := repoRoot()
	if err != nil {
		t.Error(err)
		return
	}
	out := filepath.Join(root, "bin", "realcases", "results.json")
	if *rcSymptomsOnly {
		out = filepath.Join(root, "bin", "realcases", "symptoms.json")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		t.Error(err)
		return
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
		t.Error(err)
	}
	t.Logf("wrote %s", out)
}
