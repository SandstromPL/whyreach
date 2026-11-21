//go:build lab

package e2e

// TestCIExample is CI mode's exit criterion (INITIAL.md §7, M6): the CI
// example diagnoses a deliberately broken Compose test. The example lives in
// one place, docs/ci.md. The test reads its three steps from the YAML block
// there and runs their scripts the way GitHub Actions runs a bash step (the
// script as a file, under bash --noprofile --norc -eo pipefail), with the
// runner's files (RUNNER_TEMP, GITHUB_PATH, GITHUB_STEP_SUMMARY) in
// temporary directories.
//
// The broken stack is the lab's wr002-loopback-bind: api listens only on
// 127.0.0.1:8080, so the stack's test, a connect from worker to api:8080,
// fails first, and the example must name WR002.
//
// Nothing is downloaded. The install step's curl is a stand-in that answers
// from a release the test builds from this checkout, in the release's layout
// (buildRelease), and records the URLs it was asked for: they must be the
// pinned release's archive and checksums.txt on this project's GitHub
// Releases. With WHYREACH_CI_RELEASE set to a version, the real curl
// downloads that release instead: the ci-example workflow does that on
// GitHub, when started by hand after a release.
//
// The diagnose step runs redacted and unredacted with probe containers, the
// example's default. Its sudo variant runs only where WHYREACH_CI_SUDO=1
// says that passwordless sudo is there to use (GitHub's runners, through
// the ci-example workflow): the test never runs sudo otherwise.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/platform"
)

// ciDoc holds the example, the one copy of its steps.
const ciDoc = "docs/ci.md"

// ciStep is a step of the example's workflow, as far as the test reads it.
type ciStep struct {
	ID    string         `yaml:"id"`
	Name  string         `yaml:"name"`
	If    string         `yaml:"if"`
	Shell string         `yaml:"shell"`
	Uses  string         `yaml:"uses"`
	With  map[string]any `yaml:"with"`
	Env   map[string]any `yaml:"env"`
	Run   string         `yaml:"run"`
}

// ciExample is the example's three whyreach steps and the steps before them.
type ciExample struct {
	before                    []ciStep
	install, diagnose, upload ciStep
}

// ciVariant is one way to run the diagnose step.
type ciVariant struct {
	name   string
	redact bool
	sudo   bool
}

func TestCIExample(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root, whyreach enters the containers' network namespaces itself, which isn't the example's default (probe containers); its sudo variant runs with WHYREACH_CI_SUDO=1")
	}
	if *labDesktop || !platform.EngineHere(l.platform) {
		t.Skipf("the example is for CI runners with Docker Engine (linux-engine), and this is %s", l.expectOn)
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	ex := readCIExample(t, root)
	checkCIExample(t, ex)

	version := fmt.Sprint(ex.install.Env["WHYREACH_VERSION"])
	download := os.Getenv("WHYREACH_CI_RELEASE")
	if download != "" {
		if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(download) {
			t.Fatalf("WHYREACH_CI_RELEASE is %q, want a release such as 0.2.0", download)
		}
		version = download
	}

	// The broken stack, and its test, which must fail before whyreach runs.
	dir := filepath.Join(root, "test", "lab", "wr002-loopback-bind")
	r := bringUpAs(t, dir, "whyreach-lab-ci-"+randHex(2), dir)
	if out, err := compose(dir, r.project, "compose.yaml", nil, "exec", "-T", "worker", "/labserver", "check", "api:8080").CombinedOutput(); err == nil {
		t.Fatalf("the stack's test passed, and the example needs a failed one: %s", out)
	}

	// Install.
	archive := fmt.Sprintf("whyreach_%s_linux_%s.tar.gz", version, runtime.GOARCH)
	base := "https://github.com/SandstromPL/whyreach/releases/download/v" + version + "/"
	release := t.TempDir()
	shim := curlShim(t)
	if download == "" {
		buildRelease(t, root, release, archive, version)
	}
	// The install step's RUNNER_TEMP outlives its subtest: the steps after
	// it run the binary it installed there.
	parent, rt := t, t.TempDir()
	var binDir string
	t.Run("install", func(t *testing.T) {
		ghPath, curlLog := filepath.Join(t.TempDir(), "path"), filepath.Join(t.TempDir(), "curl.log")
		env := ciEnv(rt, t.TempDir(), "GITHUB_PATH="+ghPath, "WHYREACH_VERSION="+version)
		if download == "" {
			env = prependPath(append(env, "WHYREACH_TEST_RELEASE="+release, "WHYREACH_TEST_CURL_LOG="+curlLog), shim)
		}
		out, err := runStep(t, ex.install.Run, env, rt)
		if err != nil {
			t.Fatalf("the install step failed: %v\n%s", err, out)
		}
		t.Logf("install step:\n%s", out)
		if download == "" {
			if got, want := fileLines(t, curlLog), []string{base + archive, base + "checksums.txt"}; !slices.Equal(got, want) {
				t.Errorf("the install step asked for %q, want only %q", got, want)
			}
		}
		paths := fileLines(t, ghPath)
		if len(paths) != 1 {
			t.Fatalf("GITHUB_PATH got %q, want the one directory whyreach is in", paths)
		}
		binDir = paths[0]
		bin := filepath.Join(binDir, "whyreach")
		got, err := exec.CommandContext(context.Background(), bin, "version").Output()
		if err != nil || strings.TrimSpace(string(got)) != "whyreach "+version {
			t.Fatalf("the installed whyreach says %q (%v), want whyreach %s", got, err, version)
		}
		if download == "" {
			if b, err := os.ReadFile(bin); err != nil || !bytes.Equal(b, fromArchive(t, filepath.Join(release, archive), "whyreach")) {
				t.Errorf("the installed binary isn't the archive's (%v)", err)
			}
		}
		// The probe image this binary imports goes with the test.
		digest, err := sha256File(bin)
		if err != nil {
			t.Fatal(err)
		}
		image := "whyreach-probe:" + executor.ImageTag(version, digest)
		parent.Cleanup(func() { _ = exec.CommandContext(context.Background(), "docker", "image", "rm", image).Run() })
	})
	if binDir == "" {
		t.FailNow()
	}
	if download == "" {
		for _, bad := range []struct {
			name   string
			tamper func(t *testing.T, dir string)
		}{
			{"tampered-archive", func(t *testing.T, dir string) {
				f, err := os.OpenFile(filepath.Join(dir, archive), os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write([]byte{0})
				if cerr := f.Close(); err == nil {
					err = cerr
				}
				if err != nil {
					t.Fatal(err)
				}
			}},
			{"no-checksum-line", func(t *testing.T, dir string) {
				line := strings.Repeat("0", 64) + "  whyreach_" + version + "_linux_other.tar.gz\n"
				if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(line), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		} {
			t.Run("install-"+bad.name, func(t *testing.T) {
				rel := t.TempDir()
				for _, f := range []string{archive, "checksums.txt"} {
					copyFile(t, filepath.Join(release, f), filepath.Join(rel, f))
				}
				bad.tamper(t, rel)
				rt, ghPath := t.TempDir(), filepath.Join(t.TempDir(), "path")
				env := prependPath(ciEnv(rt, t.TempDir(), "GITHUB_PATH="+ghPath, "WHYREACH_VERSION="+version,
					"WHYREACH_TEST_RELEASE="+rel, "WHYREACH_TEST_CURL_LOG="+filepath.Join(t.TempDir(), "curl.log")), shim)
				out, err := runStep(t, ex.install.Run, env, rt)
				if err == nil {
					t.Fatalf("the install step succeeded with a %s:\n%s", bad.name, out)
				}
				if b, _ := os.ReadFile(ghPath); len(b) > 0 {
					t.Errorf("it put %q on GITHUB_PATH", b)
				}
				if _, err := os.Stat(filepath.Join(rt, "whyreach", "bin", "whyreach")); err == nil {
					t.Error("it extracted the binary")
				}
			})
		}
	}

	// Diagnose: the connection the stack's test makes, a working one, a
	// service that doesn't exist, and a line without a target.
	pairs := strings.Join([]string{
		"# worker's connection, which the stack's test makes",
		"service:worker@" + r.project + " api:8080",
		"service:api@" + r.project + " 127.0.0.1:8080",
		"",
		"service:wroker@" + r.project + " api:8080",
		"service:worker@" + r.project,
	}, "\n") + "\n"
	stack := stackValues(t, r.project)
	variants := []ciVariant{{name: "redacted", redact: true}, {name: "unredacted"}}
	if os.Getenv("WHYREACH_CI_SUDO") == "1" {
		variants = append(variants, ciVariant{name: "sudo-redacted", redact: true, sudo: true}, ciVariant{name: "sudo-unredacted", sudo: true})
	}
	for _, v := range variants {
		t.Run("diagnose-"+v.name, func(t *testing.T) { runCIDiagnose(t, ex.diagnose, binDir, pairs, v, stack) })
	}
}

// readCIExample returns the example's steps: from the one YAML block in
// docs/ci.md that has them, the job with the three whyreach steps.
func readCIExample(t *testing.T, root string) ciExample {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, ciDoc))
	if err != nil {
		t.Fatal(err)
	}
	var blocks []string
	var block []string
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case !in && line == "```yaml":
			in, block = true, nil
		case in && line == "```":
			in = false
			if s := strings.Join(block, "\n"); strings.Contains(s, "id: whyreach-diagnose") {
				blocks = append(blocks, s)
			}
		case in:
			block = append(block, line)
		}
	}
	if len(blocks) != 1 {
		t.Fatalf("%s has %d YAML blocks with the whyreach steps, want 1", ciDoc, len(blocks))
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []ciStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(blocks[0]), &wf); err != nil {
		t.Fatalf("%s's example: %v", ciDoc, err)
	}
	for _, job := range wf.Jobs {
		var ex ciExample
		var order []string
		for _, s := range job.Steps {
			switch s.ID {
			case "whyreach-install":
				ex.install = s
			case "whyreach-diagnose":
				ex.diagnose = s
			case "whyreach-upload":
				ex.upload = s
			default:
				if len(order) == 0 {
					ex.before = append(ex.before, s)
				}
				continue
			}
			order = append(order, s.ID)
		}
		if len(order) == 0 {
			continue
		}
		if want := []string{"whyreach-install", "whyreach-diagnose", "whyreach-upload"}; !slices.Equal(order, want) {
			t.Fatalf("%s's whyreach steps are %q, want %q in that order", ciDoc, order, want)
		}
		return ex
	}
	t.Fatalf("no job in %s's example has the whyreach steps", ciDoc)
	return ciExample{}
}

// checkCIExample checks what the example promises without running it.
func checkCIExample(t *testing.T, ex ciExample) {
	t.Helper()
	for _, s := range []ciStep{ex.install, ex.diagnose, ex.upload} {
		if s.If != "failure()" {
			t.Errorf("step %s runs if %q: it must run only after a failure (if: failure())", s.ID, s.If)
		}
	}
	for _, s := range []ciStep{ex.install, ex.diagnose} {
		if s.Shell != "bash" {
			t.Errorf("step %s runs in %q, want shell: bash", s.ID, s.Shell)
		}
		if strings.Contains(s.Run, "${{") {
			t.Errorf("step %s's script expands an expression: pass it through env, since a value from the event could inject commands", s.ID)
		}
	}
	if v := fmt.Sprint(ex.install.Env["WHYREACH_VERSION"]); !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(v) {
		t.Errorf("the install step pins %q, want a release such as 0.2.0", v)
	}
	if got, want := fmt.Sprint(ex.diagnose.Env["WHYREACH_REDACT"]), "${{ github.event.repository.visibility != 'private' }}"; got != want {
		t.Errorf("WHYREACH_REDACT is %q, want %q: redacted unless the repository is private", got, want)
	}
	if got := fmt.Sprint(ex.diagnose.Env["WHYREACH_SUDO"]); got != "false" {
		t.Errorf("WHYREACH_SUDO is %q: the default is probe containers (false)", got)
	}
	if strings.TrimSpace(fmt.Sprint(ex.diagnose.Env["WHYREACH_PAIRS"])) == "" {
		t.Error("the example lists no connection in WHYREACH_PAIRS")
	}
	if !strings.HasPrefix(ex.upload.Uses, "actions/upload-artifact@") {
		t.Errorf("the upload step uses %q, want actions/upload-artifact", ex.upload.Uses)
	}
	if got, want := fmt.Sprint(ex.upload.With["path"]), "${{ runner.temp }}/whyreach/diagnosis"; got != want {
		t.Errorf("the upload step uploads %q, want %q, where the diagnose step writes", got, want)
	}
	for _, s := range ex.before {
		if strings.Contains(s.Run, "compose down") {
			t.Errorf("step %q stops the stack before whyreach can look at it", s.Name)
		}
	}
}

// runCIDiagnose runs the diagnose step and checks the log, the job summary
// and the artifact it leaves.
func runCIDiagnose(t *testing.T, step ciStep, binDir, pairs string, v ciVariant, stack []string) {
	rt, summary := t.TempDir(), filepath.Join(t.TempDir(), "summary.md")
	env := prependPath(ciEnv(rt, t.TempDir(), "GITHUB_STEP_SUMMARY="+summary, "WHYREACH_PAIRS="+pairs,
		"WHYREACH_REDACT="+strconv.FormatBool(v.redact), "WHYREACH_SUDO="+strconv.FormatBool(v.sudo)), binDir)
	start := time.Now()
	log, err := runStep(t, step.Run, env, rt)
	t.Logf("the diagnose step took %s; its log:\n%s", time.Since(start).Round(time.Millisecond), log)
	if err != nil {
		t.Fatalf("the diagnose step failed (it must always exit 0): %v\n%s", err, log)
	}
	for _, want := range []string{
		"::notice title=whyreach::connection 1: cause or likely cause found (exit 1)",
		"::group::whyreach, connection 1: cause or likely cause found",
		"WR002",
		"::notice title=whyreach::connection 2: no problem reproduced (exit 0)",
		"::warning title=whyreach::connection 3: no diagnosis (exit 3)",
		"no container runs Compose service",
		"::warning title=whyreach::connection 4: write it as SOURCE TARGET",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("the log lacks %q:\n%s", want, log)
		}
	}

	// The artifact: a bundle for each connection diagnosed, none for the others.
	art := filepath.Join(rt, "whyreach", "diagnosis")
	if got := dirNames(t, art); !slices.Equal(got, []string{"1", "2"}) {
		t.Fatalf("the artifact holds %q, want a bundle for connections 1 and 2", got)
	}
	bundleFiles := []string{"diagnosis.json", "evidence.jsonl", "manifest.json", "report.md"}
	for _, n := range []string{"1", "2"} {
		if got := dirNames(t, filepath.Join(art, n)); !slices.Equal(got, bundleFiles) {
			t.Errorf("bundle %s holds %q, want %q", n, got, bundleFiles)
		}
	}
	var d1, d2 struct {
		Verdict  string `json:"verdict"`
		Findings []struct {
			RuleID     string `json:"rule_id"`
			Confidence string `json:"confidence"`
		} `json:"findings"`
		SideEffects []string `json:"side_effects"`
	}
	readJSON(t, filepath.Join(art, "1", "diagnosis.json"), &d1)
	readJSON(t, filepath.Join(art, "2", "diagnosis.json"), &d2)
	if d1.Verdict != "cause_identified" || len(d1.Findings) == 0 || d1.Findings[0].RuleID != "WR002" || d1.Findings[0].Confidence != "high" {
		t.Errorf("connection 1: %+v, want WR002 at high, cause_identified", d1)
	}
	if d2.Verdict != "no_problem_reproduced" {
		t.Errorf("connection 2: %s, want no_problem_reproduced", d2.Verdict)
	}
	var m struct {
		Redaction struct {
			Enabled     bool `json:"enabled"`
			PrivateKept bool `json:"private_addresses_kept"`
		} `json:"redaction"`
	}
	readJSON(t, filepath.Join(art, "1", "manifest.json"), &m)
	if m.Redaction.Enabled != v.redact || (v.redact && m.Redaction.PrivateKept) {
		t.Errorf("bundle 1's redaction: %+v, want enabled %v with private addresses replaced", m.Redaction, v.redact)
	}
	sum, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"WR002", "no problem reproduced"} {
		if !strings.Contains(string(sum), want) {
			t.Errorf("the job summary lacks %q:\n%s", want, sum)
		}
	}

	// How whyreach looked from inside worker: probe containers, or as root
	// through the netns executor, with no Docker write.
	executorWant := "probe-container"
	if v.sudo {
		executorWant = "netns"
		if len(d1.SideEffects) != 0 {
			t.Errorf("as root, whyreach must not write to Docker: %q", d1.SideEffects)
		}
	} else if !slices.ContainsFunc(d1.SideEffects, func(s string) bool { return strings.Contains(s, "probe container") }) {
		t.Errorf("connection 1 ran no probe container (%q): the config file didn't take effect", d1.SideEffects)
	}
	if got := tcpExecutors(t, filepath.Join(art, "1", "evidence.jsonl"), "worker"); !slices.Equal(got, []string{executorWant}) {
		t.Errorf("worker's TCP checks ran through %q, want %s", got, executorWant)
	}

	// Redaction: nothing of the stack's addresses and container IDs in what
	// the step writes for others to read.
	texts := map[string]string{"the log": log, "the job summary": string(sum)}
	files, _ := filepath.Glob(filepath.Join(art, "*", "*"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		texts[strings.TrimPrefix(f, art+"/")] = string(b)
	}
	if v.redact {
		secrets := stack
		if home, err := os.UserHomeDir(); err == nil && !strings.HasPrefix(rt, home) {
			secrets = append(secrets, home)
		}
		for name, text := range texts {
			for _, s := range secrets {
				if strings.Contains(text, s) {
					t.Errorf("%s shows %s, which redaction should have replaced", name, s)
				}
			}
		}
	} else if !slices.ContainsFunc(stack, func(s string) bool { return strings.Contains(texts["1/report.md"], s) }) {
		t.Errorf("the unredacted report shows none of the stack's addresses:\n%s", texts["1/report.md"])
	}
	if left := leftoverProbes(); left != "" {
		t.Errorf("probe containers were left behind:\n%s", left)
	}
}

// curlShim writes a stand-in for curl that fetches nothing: it records each
// URL in WHYREACH_TEST_CURL_LOG and answers from WHYREACH_TEST_RELEASE, by
// the URL's last element, or fails as curl -f does on a 404.
func curlShim(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
# TestCIExample's stand-in for curl: it fetches nothing.
out= url= prev=
for a in "$@"; do
  case "$prev" in -o | --output) out=$a ;; esac
  case "$a" in http://* | https://*) url=$a ;; esac
  prev=$a
done
echo "$url" >> "$WHYREACH_TEST_CURL_LOG"
if [ -n "$out" ] && [ -f "$WHYREACH_TEST_RELEASE/${url##*/}" ]; then
  exec cp "$WHYREACH_TEST_RELEASE/${url##*/}" "$out"
fi
echo "curl: (22) The requested URL returned error: 404" >&2
exit 22
`
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// ciEnv is a step's environment: this process's, without whyreach's
// directories and GitHub's and the runner's own variables, plus the
// runner's directories and extra.
func ciEnv(runnerTemp, workspace string, extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case k == "XDG_CONFIG_HOME", k == "XDG_STATE_HOME", k == "XDG_DATA_HOME",
			strings.HasPrefix(k, "WHYREACH_"), strings.HasPrefix(k, "GITHUB_"), strings.HasPrefix(k, "RUNNER_"):
			continue
		}
		env = append(env, kv)
	}
	return append(append(env, "RUNNER_TEMP="+runnerTemp, "GITHUB_WORKSPACE="+workspace), extra...)
}

// prependPath puts dir first on env's PATH, as a line in GITHUB_PATH does
// for the steps after it.
func prependPath(env []string, dir string) []string {
	out := make([]string, 0, len(env)+1)
	found := false
	for _, kv := range env {
		if p, ok := strings.CutPrefix(kv, "PATH="); ok {
			kv, found = "PATH="+dir+string(os.PathListSeparator)+p, true
		}
		out = append(out, kv)
	}
	if !found {
		out = append(out, "PATH="+dir)
	}
	return out
}

// runStep runs a step's script as GitHub Actions runs a step with shell:
// bash, and returns its output, stdout and stderr together as in the log.
func runStep(t *testing.T, script string, env []string, dir string) (string, error) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "step.sh")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-eo", "pipefail", f)
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// stackValues returns what redaction must hide of the running project: its
// containers' IDs (full and short), addresses, gateways and MAC addresses,
// and its network's subnet.
func stackValues(t *testing.T, project string) []string {
	t.Helper()
	ctx := context.Background()
	ids, err := exec.CommandContext(ctx, "docker", "ps", "-q", "--no-trunc", "--filter", "label=com.docker.compose.project="+project).Output()
	if err != nil {
		t.Fatal(err)
	}
	var vals []string
	for _, id := range strings.Fields(string(ids)) {
		out, err := exec.CommandContext(ctx, "docker", "inspect", "--format",
			"{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.Gateway}} {{.MacAddress}} {{end}}", id).Output()
		if err != nil {
			t.Fatal(err)
		}
		vals = append(vals, id, id[:12])
		vals = append(vals, strings.Fields(string(out))...)
	}
	subnet, err := exec.CommandContext(ctx, "docker", "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", project+"_default").Output()
	if err != nil {
		t.Fatal(err)
	}
	vals = append(vals, strings.Fields(string(subnet))...)
	slices.Sort(vals)
	vals = slices.Compact(vals)
	if len(vals) < 5 {
		t.Fatalf("found too little of the stack to check redaction against: %q", vals)
	}
	return vals
}

// tcpExecutors returns how the TCP checks from a container ran, from a
// bundle's evidence.jsonl, each way once.
func tcpExecutors(t *testing.T, path, container string) []string {
	t.Helper()
	var out []string
	for _, line := range fileLines(t, path) {
		var e struct {
			Kind    string `json:"kind"`
			Context struct {
				Name     string `json:"name"`
				Executor string `json:"executor"`
			} `json:"context"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if e.Kind == "probe.tcp" && e.Context.Name == container && !slices.Contains(out, e.Context.Executor) {
			out = append(out, e.Context.Executor)
		}
	}
	return out
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// fileLines returns a file's non-empty lines; a missing file has none.
func fileLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// dirNames lists a directory's entries, sorted.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
