//go:build lab && agent

package e2e

// What the agent checks (make lab-agent: TestAgent, TestAgentNewUser) do so
// that an agent sees a scenario only as a developer would, most of it
// shared with the agent benchmark (make lab-bench;
// docs/research/agent-benchmark.md, "Arms"):
//
//   - The scenario runs as a Compose project with a neutral name
//     (whyreach-lab-<6 hex>), from copies of its Compose files without the
//     comments that explain it. make lab's project names, which Docker
//     gives every container and network, name the scenario.
//   - Claude Code runs clean: none of the user's settings (with their
//     plugins, hooks and permission rules), MCP servers, CLAUDE.md files,
//     memory or slash commands, and a minimal environment.
//   - The agent checks' directories (the working directory, which Claude
//     Code tells an agent that has built-in tools, its home and temporary
//     files, and whyreach's XDG directories, which whyreach's advice
//     names) sit under a fresh directory whose name says nothing about the
//     scenario: t.TempDir()'s is the test's, a subtest's ends with the
//     scenario's name.
//
// noHints checks what an agent check hands its agent before the agent
// starts; bench.Hints decides what names a scenario or its cause, and
// test/bench's TestScenariosGiveNoHints checks every scenario's problem
// report and Compose copies in make test.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/SandstromPL/whyreach/test/bench"
)

// agentDirs makes a fresh directory for one agent check, holding home,
// work and tmp for the agent's HOME, working directory and TMPDIR, and
// returns it. Its name says nothing about the scenario. The test's cleanup
// removes it: call agentDirs before the scenario comes up, since Compose
// takes the project down from the copies of its files kept there.
func agentDirs(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "whyreach-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	for _, d := range []string{"home", "work", "tmp"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// bringUpNeutral brings a scenario up as a neutral Compose project, from
// copies of its Compose files without comments under root.
func bringUpNeutral(t *testing.T, dir, root string) running {
	t.Helper()
	project := bench.NeutralProject()
	return bringUpAs(t, dir, project, prepareCompose(t, dir, root, project))
}

// prepareCompose copies a scenario's Compose files without comments into
// root/projects/<project>, and returns that directory.
func prepareCompose(t *testing.T, dir, root, project string) string {
	t.Helper()
	var s scenario
	raw, err := os.ReadFile(filepath.Join(dir, "scenario.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Projects) == 0 {
		s.Projects = []string{"compose.yaml"}
	}
	out := filepath.Join(root, "projects", project)
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range s.Projects {
		src, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		clean, err := bench.StripComments(src)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if h := bench.NameHints(filepath.Base(dir), string(clean)); len(h) > 0 {
			t.Fatalf("%s names the scenario or a rule even without comments: %v", f, h)
		}
		if err := os.WriteFile(filepath.Join(out, f), clean, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// claudeConfigDir is where Claude Code keeps its own configuration and
// sign-in: CLAUDE_CONFIG_DIR, or ~/.claude. Agents get it explicitly,
// since their HOME is a fresh directory.
func claudeConfigDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(home, ".claude")
}

// cleanClaudeArgs keep the user's Claude Code configuration out of a
// headless run: no user settings, so none of their plugins, hooks or
// permission rules; no MCP server but those given with --mcp-config; no
// slash commands or skills. The stream comes as JSON, and no session is
// saved.
var cleanClaudeArgs = []string{
	"--setting-sources", "project,local", "--strict-mcp-config", "--disable-slash-commands",
	"--output-format", "stream-json", "--verbose", "--no-session-persistence",
}

// cleanClaudeEnv is a headless Claude Code's whole environment: home and
// tmp for HOME and TMPDIR, Claude Code's own configuration, no CLAUDE.md
// files, memory or updates, and nothing from the user's shell; then extra.
// Docker is at its default socket, as for make lab-bench.
func cleanClaudeEnv(home, tmp, claudeConf string, extra ...string) []string {
	return append([]string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + home, "TMPDIR=" + tmp,
		"CLAUDE_CONFIG_DIR=" + claudeConf, "SHELL=/bin/bash", "LANG=C.UTF-8", "TERM=dumb",
		"CLAUDE_CODE_DISABLE_CLAUDE_MDS=1", "CLAUDE_CODE_DISABLE_AUTO_MEMORY=1", "DISABLE_AUTOUPDATER=1",
	}, extra...)
}

// noHints fails the test, before an agent starts, if anything the harness
// hands the agent names the scenario or its cause (bench.Hints): its
// prompt, with the target left out (the target is the problem itself),
// its other arguments, its environment, its Compose project, the
// directories it works in and its MCP configuration. CLAUDE_CONFIG_DIR is
// the user's own and stays with Claude Code, so it is left out too.
func noHints(t *testing.T, scenario, target string, texts ...string) {
	t.Helper()
	for _, s := range texts {
		if strings.HasPrefix(s, "CLAUDE_CONFIG_DIR=") {
			continue
		}
		if target != "" {
			s = strings.ReplaceAll(s, target, "<target>")
		}
		if h := bench.Hints(scenario, s); len(h) > 0 {
			t.Fatalf("the agent would see %v, which names the scenario %s or its cause, in %q", h, scenario, s)
		}
	}
}

type claudeRun struct {
	final    string
	tools    []string // the tools called, whyreach's without the mcp__whyreach__ prefix
	commands []string // what the agent ran with Bash, and the files it wrote
	turns    int
	cost     float64
	seconds  float64
}

// runClaude runs a fresh headless Claude Code with the clean client's
// flags in dir, with env as its whole environment, and reads its stream.
func runClaude(t *testing.T, dir string, env []string, timeout time.Duration, prompt string, args ...string) claudeRun {
	t.Helper()
	model := agentModel
	if m := os.Getenv("WHYREACH_AGENT_MODEL"); m != "" {
		model = m
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	all := append(append([]string{"-p", prompt, "--model", model}, cleanClaudeArgs...), args...)
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
