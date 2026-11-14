//go:build lab && agent

package e2e

// The agent check (M2's exit criterion, INITIAL.md §6.3 and §7): for each
// lab scenario, a headless Claude Code on a small model gets only
// whyreach's four MCP tools (--tools "" removes every built-in tool,
// --strict-mcp-config every other server) and a one-line problem report,
// and must name the cause whyreach's lab expects.
//
// It sees the scenario only as a developer would (agentenv_test.go): a
// neutral Compose project from comment-free copies of the scenario's
// files, directories whose names say nothing, and a clean Claude Code that
// reads none of the user's configuration and changes none of it. noHints
// checks what the agent is given before it starts.
//
// Run it with `make lab-agent`. It needs Docker, the claude CLI and network
// access for the model, and spends a little of the user's model quota.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/test/bench"
)

// agentModel is the small model the check runs on; WHYREACH_AGENT_MODEL
// overrides it.
const agentModel = "haiku"

var tools = []string{
	"mcp__whyreach__diagnose_connection", "mcp__whyreach__inspect_environment",
	"mcp__whyreach__run_probe", "mcp__whyreach__save_report",
}

type agentResult struct {
	Scenario  string   `json:"scenario"`
	Want      string   `json:"want"`
	Got       string   `json:"got"`
	Pass      bool     `json:"pass"`
	ToolCalls []string `json:"tool_calls"`
	Turns     int      `json:"turns"`
	Seconds   float64  `json:"seconds"`
	CostUSD   float64  `json:"cost_usd"`
	Client    string   `json:"client"` // what the MCP server logged about the client
}

func TestAgent(t *testing.T) {
	if _, err := exec.LookPath("claude"); err != nil {
		t.Skip("the claude CLI is not installed")
	}
	var results []agentResult
	for _, dir := range scenarioDirs(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			r := runAgent(t, dir)
			results = append(results, r)
			if !r.Pass {
				t.Errorf("agent answered %q, want %q (tools: %v)", r.Got, r.Want, r.ToolCalls)
			}
		})
	}
	out := os.Getenv("WHYREACH_AGENT_RESULTS")
	if out == "" {
		return
	}
	b, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
		t.Error(err)
	}
}

func runAgent(t *testing.T, dir string) agentResult {
	name := filepath.Base(dir)
	root := agentDirs(t)
	r := bringUpNeutral(t, dir, root)
	res := agentResult{Scenario: name, Want: "none"}
	if e := r.s.Expect; e.TopRule != "" && (e.Verdict == "cause_identified" || e.Verdict == "likely_cause") {
		res.Want = e.TopRule
	}

	// whyreach's XDG directories are the run's own: its advice names its
	// config file, and save_report its reports.
	xdg := filepath.Join(root, "xdg")
	// Probe containers are on by default: a headless run has no one to
	// answer a consent request, and the config lists example.com under
	// [probe] names for the same reason (WR020's scenario looks it up).
	// WHYREACH_AGENT_PROBES=off runs with the default config instead, so the
	// server asks the client.
	if os.Getenv("WHYREACH_AGENT_PROBES") == "off" {
		if res.Want != "none" && r.s.ExpectWithoutProbe != nil && r.s.ExpectWithoutProbe.TopRule == "" {
			res.Want = "none" // the rule needs a probe container
		}
	} else {
		if err := os.MkdirAll(filepath.Join(xdg, "config", "whyreach"), 0o700); err != nil {
			t.Fatal(err)
		}
		copyFile(t, filepath.Join(l.withProbe, "whyreach", "config.toml"), filepath.Join(xdg, "config", "whyreach", "config.toml"))
	}
	logPath := filepath.Join(root, "server.log")
	server := map[string]any{
		"command": "/bin/sh",
		"args":    []string{"-c", `exec "$0" mcp serve 2>>"$1"`, l.bin, logPath},
		"env": map[string]string{
			"XDG_CONFIG_HOME": filepath.Join(xdg, "config"),
			"XDG_STATE_HOME":  filepath.Join(xdg, "state"),
			"XDG_DATA_HOME":   filepath.Join(xdg, "data"),
			"WHYREACH_LOG":    "info",
		},
	}
	cfg, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"whyreach": server}})
	cfgPath := filepath.Join(root, "mcp.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	work := filepath.Join(root, "work")
	env := cleanClaudeEnv(filepath.Join(root, "home"), filepath.Join(root, "tmp"), claudeConfigDir(t))
	prompt := bench.DiagnosePrompt(r.from, r.to, "")
	args := []string{"--mcp-config", cfgPath, "--tools", "", "--allowedTools", strings.Join(tools, ",")}
	noHints(t, name, r.to, append(append([]string{prompt, r.project, work, string(cfg)}, args...), env...)...)
	run := runClaude(t, work, env, 4*time.Minute, prompt, args...)
	res.ToolCalls, res.Turns, res.Seconds, res.CostUSD = run.tools, run.turns, run.seconds, run.cost
	checkClean(t, run, tools, "whyreach:connected")

	if m := regexp.MustCompile(`(?m)^\W*RESULT:\s*\W*(WR\d{3}|none)\b`).FindAllStringSubmatch(run.final, -1); len(m) > 0 {
		res.Got = m[len(m)-1][1]
	}
	res.Pass = strings.EqualFold(res.Got, res.Want)
	for _, c := range res.ToolCalls {
		if !slices.Contains(tools, "mcp__whyreach__"+c) {
			res.Pass = false
			t.Errorf("the agent used %s, which is not one of whyreach's tools", c)
		}
	}
	if b, err := os.ReadFile(filepath.Join(xdg, "state", "whyreach", "audit.jsonl")); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if strings.Contains(line, `"tool":"probe_containers_consent"`) || strings.Contains(line, `"tool":"name_lookup_consent"`) {
				t.Logf("consent: %s", line)
			}
		}
	}
	if b, err := os.ReadFile(logPath); err == nil {
		if m := regexp.MustCompile(`"msg":"MCP client (connected|calls)"[^\n]*`).Find(b); m != nil {
			res.Client = string(m)
		}
	}
	t.Logf("%s: want %s, got %s in %.0f s, %d turns, $%.4f, tools %v\nanswer: %s",
		res.Scenario, res.Want, res.Got, res.Seconds, res.Turns, res.CostUSD, res.ToolCalls, run.final)
	return res
}
