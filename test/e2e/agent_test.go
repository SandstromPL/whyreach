//go:build lab && agent

package e2e

// The agent check (M2's exit criterion, INITIAL.md §7): for each lab
// scenario, a headless Claude Code on a small model gets only whyreach's
// four MCP tools (--tools "" removes every built-in tool, --strict-mcp-config
// every other server) and a one-line problem report, and must name the
// cause whyreach's lab expects. Like spikes/mcphello/claude-check.sh, it
// adds nothing to the user's Claude Code config.
//
// Run it with `make lab-agent`. It needs Docker, the claude CLI and network
// access for the model, and spends a little of the user's model quota.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
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
	dirs, err := filepath.Glob(filepath.Join("..", "lab", "*", "scenario.yaml"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios: %v", err)
	}
	slices.Sort(dirs)
	var results []agentResult
	for _, path := range dirs {
		dir := filepath.Dir(path)
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
	r := bringUp(t, dir)
	res := agentResult{Scenario: filepath.Base(dir), Want: "none"}
	if e := r.s.Expect; e.TopRule != "" && (e.Verdict == "cause_identified" || e.Verdict == "likely_cause") {
		res.Want = e.TopRule
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "server.log")
	// Probe containers are on by default: a headless run has no one to
	// answer a consent request, and the config lists example.com under
	// [probe] names for the same reason (WR020's scenario looks it up).
	// WHYREACH_AGENT_PROBES=off runs with the default config instead, so the
	// server asks the client.
	configHome := l.withProbe
	if os.Getenv("WHYREACH_AGENT_PROBES") == "off" {
		configHome = l.noProbe
		if res.Want != "none" && r.s.ExpectWithoutProbe != nil && r.s.ExpectWithoutProbe.TopRule == "" {
			res.Want = "none" // the rule needs a probe container
		}
	}
	server := map[string]any{
		"command": "/bin/sh",
		"args":    []string{"-c", `exec "$0" mcp serve 2>>"$1"`, l.bin, logPath},
		"env": map[string]string{
			"XDG_CONFIG_HOME": configHome,
			"XDG_STATE_HOME":  filepath.Join(tmp, "state"),
			"XDG_DATA_HOME":   filepath.Join(tmp, "data"),
			"WHYREACH_LOG":    "info",
		},
	}
	cfg, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"whyreach": server}})
	cfgPath := filepath.Join(tmp, "mcp.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	model := agentModel
	if m := os.Getenv("WHYREACH_AGENT_MODEL"); m != "" {
		model = m
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "claude", "-p", prompt(r),
		"--model", model, "--mcp-config", cfgPath, "--strict-mcp-config", "--tools", "",
		"--allowedTools", strings.Join(tools, ","),
		"--output-format", "stream-json", "--verbose", "--no-session-persistence")
	cmd.Dir = tmp // no project CLAUDE.md or settings reach the agent
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	if err := cmd.Run(); err != nil {
		t.Fatalf("claude: %v\nstderr: %s", err, stderr.String())
	}
	res.Seconds = time.Since(start).Seconds()

	final := ""
	sc := bufio.NewScanner(&stdout)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev struct {
			Type    string `json:"type"`
			Message struct {
				Content []struct {
					Type string `json:"type"`
					Name string `json:"name"`
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
				if c.Type == "tool_use" {
					res.ToolCalls = append(res.ToolCalls, strings.TrimPrefix(c.Name, "mcp__whyreach__"))
				}
			}
		case "result":
			final, res.Turns, res.CostUSD = ev.Result, ev.Turns, ev.CostUSD
		}
	}
	if m := regexp.MustCompile(`(?m)^\W*RESULT:\s*\W*(WR\d{3}|none)\b`).FindAllStringSubmatch(final, -1); len(m) > 0 {
		res.Got = m[len(m)-1][1]
	}
	res.Pass = strings.EqualFold(res.Got, res.Want)
	for _, c := range res.ToolCalls {
		if !slices.Contains(tools, "mcp__whyreach__"+c) {
			res.Pass = false
			t.Errorf("the agent used %s, which is not one of whyreach's tools", c)
		}
	}
	if b, err := os.ReadFile(filepath.Join(tmp, "state", "whyreach", "audit.jsonl")); err == nil {
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
		res.Scenario, res.Want, res.Got, res.Seconds, res.Turns, res.CostUSD, res.ToolCalls, final)
	return res
}

// prompt is the problem report a developer would give: who can't reach
// what, and nothing about the cause.
func prompt(r running) string {
	who := "On this machine (the host itself, not inside a container), a program"
	if svc, ok := strings.CutPrefix(r.from, "service:"); ok {
		name, project, _ := strings.Cut(svc, "@")
		who = fmt.Sprintf("In the Docker Compose project %q on this machine, the %s service", project, name)
	}
	return who + " can't connect to " + r.to + ". Find out why, using the whyreach tools. " +
		"Finish with one line `RESULT: <rule ID>` naming the rule of the cause whyreach found (such as WR002), " +
		"or `RESULT: none` if whyreach reproduced no problem or found no settled cause."
}
