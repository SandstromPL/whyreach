//go:build lab && agent

package e2e

// The new-user check (M4's exit criterion, INITIAL.md §7): a fresh headless
// Claude Code gets only the README and the release files, installs
// whyreach, connects it as an MCP client would, and starts the demo; a
// second fresh agent, with whyreach's four tools and nothing else, then
// diagnoses the demo through the configuration the first one wrote.
//
// The release files come from WHYREACH_RELEASE_DIR (goreleaser's dist/, from
// make release-snapshot) when it is set. Otherwise the test builds the same
// layout itself: the archive whyreach_<version>_linux_<arch>.tar.gz with
// the binary, LICENSE, README.md and demo/compose.yaml at its root, and
// checksums.txt (.goreleaser.yaml).
//
// The agents work in a fresh directory that stands in for their home,
// with a clean Claude Code each (agentenv_test.go); the demo runs as a
// Compose project with a neutral name (whyreach-lab-<6 hex>), which the
// test removes afterwards. The second agent starts in an empty directory,
// and noHints checks what it is given first: like TestAgent's, it must
// find the cause, not read it. Run it with make lab-agent.
//
// The first agent may read the sandbox, write only the MCP configuration,
// and run the few commands the README's steps need; Compose only as the
// README starts and reads the demo, under the test's project name. That
// keeps an honest agent in its sandbox. It is no boundary against a hostile
// checkout: the agent follows the repository's README with the user's
// Docker access, and, like every make target, the test runs the
// repository's own code. Run it on a checkout you trust.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/test/bench"
)

const (
	newUserVersion = "0.1.0"
	// demoScenario is the lab's name for the README's demo
	// (test/lab/demo-localhost): what the diagnosing agent must not be told.
	demoScenario = "demo-localhost"
	// demoTarget is what the demo's worker can't reach: the problem itself.
	demoTarget = "http://localhost:8080"
)

func TestAgentNewUser(t *testing.T) {
	if _, err := exec.LookPath("claude"); err != nil {
		t.Skip("the claude CLI is not installed")
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	sandbox := agentDirs(t)
	home, work := filepath.Join(sandbox, "home"), filepath.Join(sandbox, "work")
	release := filepath.Join(sandbox, "release")
	if err := os.Mkdir(release, 0o700); err != nil {
		t.Fatal(err)
	}
	project := bench.NeutralProject()
	archive := fmt.Sprintf("whyreach_%s_linux_%s.tar.gz", newUserVersion, runtime.GOARCH)
	if dist := os.Getenv("WHYREACH_RELEASE_DIR"); dist != "" {
		matches, _ := filepath.Glob(filepath.Join(dist, "whyreach_*_linux_"+runtime.GOARCH+".tar.gz"))
		if len(matches) != 1 {
			t.Fatalf("want one archive for linux/%s in %s, got %v", runtime.GOARCH, dist, matches)
		}
		archive = filepath.Base(matches[0])
		for _, f := range []string{archive, "checksums.txt"} {
			copyFile(t, filepath.Join(dist, f), filepath.Join(release, f))
		}
	} else {
		buildRelease(t, root, release, archive)
	}
	copyFile(t, filepath.Join(root, "README.md"), filepath.Join(sandbox, "README.md"))
	binary := filepath.Join(home, ".local", "bin", "whyreach")
	mcpConfig := filepath.Join(sandbox, "mcp.json")
	extract := filepath.Join(sandbox, "whyreach")
	composeFile := filepath.Join(extract, "demo", "compose.yaml")

	// The demo is the user's to start; whatever happens, it goes.
	t.Cleanup(func() {
		files, _ := filepath.Glob(filepath.Join(sandbox, "*", "demo", "compose.yaml"))
		files = append(files, filepath.Join(root, "demo", "compose.yaml"))
		cmd := exec.CommandContext(context.Background(), "docker", "compose", "-p", project, "-f", files[0], "down", "-v", "--timeout", "1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("compose down %s: %v\n%s", project, err, out)
		}
	})

	// The sandbox is the agents' home, with a clean Claude Code that keeps
	// its own configuration and sign-in where they are; whyreach's XDG
	// directories are in the sandbox too.
	env := cleanClaudeEnv(home, filepath.Join(sandbox, "tmp"), claudeConfigDir(t),
		"XDG_CONFIG_HOME="+filepath.Join(sandbox, "config"),
		"XDG_STATE_HOME="+filepath.Join(sandbox, "state"),
		"XDG_DATA_HOME="+filepath.Join(sandbox, "data"),
	)

	// 1. Install, connect, start the demo: the README and the release files.
	install := fmt.Sprintf(`You are a developer trying whyreach for the first time. All you have is its README (%s) and the release files you already downloaded into %s: the archive for this machine and checksums.txt. You have no internet access, so skip the download step. Follow the README to do three things, without asking questions:
1. Verify the checksum, extract the archive into %s, and install whyreach. Your home directory is %s (HOME is set to it): install the binary to %s, and write nothing outside %s.
2. Connect an MCP client. This machine's client reads the JSON configuration form the README gives, from the file %s. Write that file for the whyreach you installed.
3. Start the README's demo from %s and leave it running, but name its Compose project %s instead of the name in the file: start every docker compose command with docker compose -p %s.
When all three are done, reply with the single line DONE.`,
		filepath.Join(sandbox, "README.md"), release, extract, home, binary, sandbox, mcpConfig, extract, project, project)
	// Reads stay in the sandbox, the one file written is the MCP
	// configuration, and Compose runs only as the README starts and reads
	// the demo, under the test's project name.
	allowed := []string{
		"Read(/" + sandbox + "/**)", "Edit(/" + mcpConfig + ")",
		"Bash(tar:*)", "Bash(sha256sum:*)", "Bash(mkdir:*)", "Bash(install:*)", "Bash(ls:*)", "Bash(cd:*)", "Bash(uname:*)",
		"Bash(" + binary + ":*)",
	}
	for _, f := range []string{"demo/compose.yaml", composeFile} {
		for _, sub := range []string{"up -d --wait", "logs worker", "ps"} {
			allowed = append(allowed, "Bash(docker compose -p "+project+" -f "+f+" "+sub+")")
		}
	}
	first := runClaude(t, sandbox, env, 8*time.Minute, install, "--tools", "Bash,Read,Write", "--allowedTools", strings.Join(allowed, ","))
	checkClean(t, first.client, []string{"Bash", "Read", "Write"})
	t.Logf("install: %d turns, $%.4f, %.0f s\ncommands:\n  %s\nanswer: %s", first.turns, first.cost, first.seconds,
		strings.ReplaceAll(strings.Join(first.commands, "\n"), "\n", "\n  "), first.final)

	// What the first agent left: the binary from the archive, a working
	// MCP configuration, the demo, and nothing in the real home.
	want := fromArchive(t, filepath.Join(release, archive), "whyreach")
	if got, err := os.ReadFile(binary); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the installed binary at %s isn't the archive's: %v", binary, err)
	}
	if got, err := os.ReadFile(composeFile); err != nil || !bytes.Equal(got, fromArchive(t, filepath.Join(release, archive), "demo/compose.yaml")) {
		t.Fatalf("the demo at %s isn't the archive's: %v", composeFile, err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	b, err := os.ReadFile(mcpConfig)
	if err != nil || json.Unmarshal(b, &cfg) != nil {
		t.Fatalf("no MCP configuration at %s: %v\n%s", mcpConfig, err, b)
	}
	// The second agent starts every server listed: whyreach's, and only it.
	if s, ok := cfg.MCPServers["whyreach"]; !ok || len(cfg.MCPServers) != 1 || s.Command != binary || !slices.Equal(s.Args, []string{"mcp", "serve"}) {
		t.Fatalf("the MCP configuration doesn't start the installed whyreach alone: %s", b)
	}
	// Compose records the file each container came from: the archive's demo.
	out, err := exec.CommandContext(context.Background(), "docker", "ps", "--filter", "label=com.docker.compose.project="+project,
		"--format", `{{.Names}} {{.Label "com.docker.compose.project.config_files"}}`).Output()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if err != nil || len(lines) != 2 {
		t.Fatalf("the demo isn't running as %s: %q, %v", project, out, err)
	}
	for _, l := range lines {
		if _, files, _ := strings.Cut(l, " "); files != composeFile {
			t.Fatalf("a demo container came from %q, not %s", files, composeFile)
		}
	}
	if realHome, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(realHome, ".local", "bin", "whyreach")); err == nil {
			t.Errorf("whyreach was installed in the real home directory")
		}
	}

	// 2. Diagnose the demo with whyreach's tools and nothing else, through
	// the configuration the first agent wrote, from an empty directory.
	if entries, err := os.ReadDir(work); err != nil || len(entries) > 0 {
		t.Fatalf("the diagnosing agent's working directory %s isn't empty: %d entries, %v", work, len(entries), err)
	}
	ask := bench.DiagnosePrompt("service:worker@"+project, demoTarget, "its log says Connection refused")
	args := []string{"--mcp-config", mcpConfig, "--tools", "", "--allowedTools", strings.Join(tools, ",")}
	noHints(t, demoScenario, demoTarget, append(append([]string{ask, project, work, string(b)}, args...), env...)...)
	second := runClaude(t, work, env, 8*time.Minute, ask, args...)
	checkClean(t, second.client, tools, "whyreach:connected")
	t.Logf("diagnose: %d turns, $%.4f, %.0f s, tools %v\nanswer: %s", second.turns, second.cost, second.seconds, second.tools, second.final)
	got := ""
	if m := regexp.MustCompile(`(?m)^\W*RESULT:\s*\W*(WR\d{3}|none)\b`).FindAllStringSubmatch(second.final, -1); len(m) > 0 {
		got = m[len(m)-1][1]
	}
	if got != "WR007" {
		t.Errorf("the agent answered %q, want WR007", got)
	}
	for _, c := range second.tools {
		if !slices.Contains(tools, "mcp__whyreach__"+c) {
			t.Errorf("the agent used %s, which is not one of whyreach's tools", c)
		}
	}
	if b, err := os.ReadFile(filepath.Join(sandbox, "state", "whyreach", "audit.jsonl")); err != nil || !strings.Contains(string(b), `"primary":"WR007"`) {
		t.Errorf("the installed whyreach's audit log has no WR007 diagnosis: %v\n%s", err, b)
	}
}

// buildRelease builds what .goreleaser.yaml would for this machine's
// architecture: the static binary with the release's version, the archive
// with LICENSE, README.md and demo/compose.yaml at its root, and
// checksums.txt.
func buildRelease(t *testing.T, root, dir, archive string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "whyreach")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-trimpath", "-ldflags", "-s -w -X main.version="+newUserVersion, "-o", bin, "./cmd/whyreach")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name, src string
		mode      int64
	}{
		{"whyreach", bin, 0o755}, {"LICENSE", filepath.Join(root, "LICENSE"), 0o644},
		{"README.md", filepath.Join(root, "README.md"), 0o644}, {"demo/compose.yaml", filepath.Join(root, "demo", "compose.yaml"), 0o644},
	} {
		data, err := os.ReadFile(f.src)
		if err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(data)), ModTime: time.Now(), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, archive), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+"  "+archive+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fromArchive returns a file from a release archive.
func fromArchive(t *testing.T, archive, name string) []byte {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("no %s in %s: %v", name, archive, err)
		}
		if h.Name == name {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
