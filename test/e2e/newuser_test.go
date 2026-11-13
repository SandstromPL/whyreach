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
// The agents work in a temporary directory that stands in for their home;
// the demo runs as the Compose project whyreach-lab-demo, which the test
// removes afterwards. Run it with make lab-agent.
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
	"bufio"
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
)

const (
	newUserVersion = "0.1.0"
	demoProject    = "whyreach-lab-demo"
)

func TestAgentNewUser(t *testing.T) {
	if _, err := exec.LookPath("claude"); err != nil {
		t.Skip("the claude CLI is not installed")
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	sandbox := t.TempDir()
	home := filepath.Join(sandbox, "home")
	release := filepath.Join(sandbox, "release")
	for _, d := range []string{home, release} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
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
		cmd := exec.CommandContext(context.Background(), "docker", "compose", "-p", demoProject, "-f", files[0], "down", "-v", "--timeout", "1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("compose down %s: %v\n%s", demoProject, err, out)
		}
	})

	// The sandbox is the agents' home; Claude Code keeps reading its own
	// config (and sign-in) from the real one.
	claudeConfig := os.Getenv("CLAUDE_CONFIG_DIR")
	if claudeConfig == "" {
		realHome, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		claudeConfig = filepath.Join(realHome, ".claude")
	}
	env := append(os.Environ(),
		"HOME="+home, "CLAUDE_CONFIG_DIR="+claudeConfig,
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
		filepath.Join(sandbox, "README.md"), release, extract, home, binary, sandbox, mcpConfig, extract, demoProject, demoProject)
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
			allowed = append(allowed, "Bash(docker compose -p "+demoProject+" -f "+f+" "+sub+")")
		}
	}
	first := runClaude(t, sandbox, env, install, "--tools", "Bash,Read,Write", "--allowedTools", strings.Join(allowed, ","))
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
	if s, ok := cfg.MCPServers["whyreach"]; !ok || s.Command != binary || !slices.Equal(s.Args, []string{"mcp", "serve"}) {
		t.Fatalf("the MCP configuration doesn't start the installed whyreach: %s", b)
	}
	out, err := exec.CommandContext(context.Background(), "docker", "ps", "--filter", "label=com.docker.compose.project="+demoProject, "--format", "{{.Names}}").Output()
	if err != nil || strings.Count(strings.TrimSpace(string(out)), "\n") != 1 {
		t.Fatalf("the demo isn't running as %s: %q, %v", demoProject, out, err)
	}
	if realHome, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(realHome, ".local", "bin", "whyreach")); err == nil {
			t.Errorf("whyreach was installed in the real home directory")
		}
	}

	// 2. Diagnose the demo with whyreach's tools and nothing else, through
	// the configuration the first agent wrote.
	ask := fmt.Sprintf("On this machine, the worker service of the Docker Compose project %s can't connect to http://localhost:8080 (its log says Connection refused). "+
		"Find out why, using the whyreach tools. Finish with one line `RESULT: <rule ID>` naming the rule of the cause whyreach found (such as WR002), "+
		"or `RESULT: none` if whyreach found no settled cause.", demoProject)
	second := runClaude(t, sandbox, env, ask, "--mcp-config", mcpConfig, "--strict-mcp-config", "--tools", "",
		"--allowedTools", strings.Join(tools, ","))
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

type claudeRun struct {
	final    string
	tools    []string
	commands []string // what the agent ran with Bash
	turns    int
	cost     float64
	seconds  float64
}

// runClaude runs a fresh headless Claude Code in dir and reads its stream.
func runClaude(t *testing.T, dir string, env []string, prompt string, args ...string) claudeRun {
	t.Helper()
	model := agentModel
	if m := os.Getenv("WHYREACH_AGENT_MODEL"); m != "" {
		model = m
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	all := append([]string{"-p", prompt, "--model", model, "--output-format", "stream-json", "--verbose", "--no-session-persistence"}, args...)
	cmd := exec.CommandContext(ctx, "claude", all...)
	cmd.Dir, cmd.Env = dir, env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	if err := cmd.Run(); err != nil {
		t.Fatalf("claude: %v\nstderr: %s", err, stderr.String())
	}
	r := claudeRun{seconds: time.Since(start).Seconds()}
	sc := bufio.NewScanner(&stdout)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev struct {
			Type    string `json:"type"`
			Message struct {
				Content []struct {
					Type  string `json:"type"`
					Name  string `json:"name"`
					Input struct {
						Command  string `json:"command"`
						FilePath string `json:"file_path"`
					} `json:"input"`
				} `json:"content"`
			} `json:"message"`
			Result  string  `json:"result"`
			Turns   int     `json:"num_turns"`
			CostUSD float64 `json:"total_cost_usd"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		switch ev.Type {
		case "assistant":
			for _, c := range ev.Message.Content {
				if c.Type != "tool_use" {
					continue
				}
				r.tools = append(r.tools, strings.TrimPrefix(c.Name, "mcp__whyreach__"))
				switch {
				case c.Input.Command != "":
					r.commands = append(r.commands, c.Input.Command)
				case c.Input.FilePath != "":
					r.commands = append(r.commands, c.Name+" "+c.Input.FilePath)
				}
			}
		case "result":
			r.final, r.turns, r.cost = ev.Result, ev.Turns, ev.CostUSD
		}
	}
	return r
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
