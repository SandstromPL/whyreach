package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ruledocs "github.com/SandstromPL/whyreach/docs/rules"
	"github.com/SandstromPL/whyreach/internal/report"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// TestReportCommands: diagnose --report saves an unredacted bundle in the
// data directory; report list, show and export find it; export writes a
// redacted copy next to it (INITIAL.md §4.11, §4.12).
func TestReportCommands(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))
	reports := filepath.Join(tmp, "data", "whyreach", "reports")

	if code, stdout, _ := execute(t, "report", "list"); code != ExitNoProblem || !strings.Contains(stdout, "No report bundles") {
		t.Errorf("empty list: %d %q", code, stdout)
	}
	code, stdout, stderr := execute(t, "--from", "container:shop-worker-1", "api:8080", "--json", "--report")
	if code != ExitCause || !strings.Contains(stderr, "saved the report bundle") {
		t.Fatalf("diagnose --report: %d, stderr %q", code, stderr)
	}
	var d struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(stdout), &d); err != nil {
		t.Fatalf("with --json, stdout holds the JSON alone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(reports, d.ID+"-unredacted", "manifest.json")); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ = execute(t, "report", "list")
	if code != ExitNoProblem || !strings.Contains(stdout, d.ID) || !strings.Contains(stdout, "WR002") || !strings.Contains(stdout, "container:shop-worker-1 → api:8080") {
		t.Errorf("list: %d %q", code, stdout)
	}
	code, stdout, _ = execute(t, "report", "list", "--json")
	var list []report.Bundle
	if err := json.Unmarshal([]byte(stdout), &list); err != nil || code != ExitNoProblem || len(list) != 1 || list[0].Redacted {
		t.Errorf("list --json: %d %v %+v", code, err, list)
	}
	if code, stdout, _ = execute(t, "report", "show", d.ID); code != ExitNoProblem || !strings.Contains(stdout, "# whyreach diagnosis "+d.ID) {
		t.Errorf("show: %d %q", code, stdout)
	}
	code, stdout, _ = execute(t, "report", "export", d.ID)
	if code != ExitNoProblem || !strings.HasPrefix(stdout, filepath.Join(reports, d.ID+".tar.gz")) || !strings.Contains(stdout, "private addresses kept") {
		t.Errorf("export: %d %q", code, stdout)
	}
	if code, stdout, _ = execute(t, "report", "export", d.ID, "--redact-private"); code != ExitNoProblem || !strings.Contains(stdout, "private addresses replaced too") {
		t.Errorf("export --redact-private: %d %q", code, stdout)
	}
	for _, args := range [][]string{{"report", "show"}, {"report", "show", "../../etc/passwd"}, {"report", "export", "dg-20991231T000000Z-abcdef"}} {
		if code, _, _ := execute(t, args...); code != ExitUsage {
			t.Errorf("%q: exit %d, want %d", args, code, ExitUsage)
		}
	}
}

// A reference that isn't a diagnosis ID is a usage error even when it names
// the reports directory itself, whose path the error repeats; a bundle that
// is there but can't be read is an internal one.
func TestReportRefusals(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))
	reports := filepath.Join(tmp, "data", "whyreach", "reports")
	broken := filepath.Join(reports, "dg-20991231T000000Z-abcdef")
	if err := os.MkdirAll(broken, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "manifest.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		args []string
		code int
	}{
		{[]string{"report", "show", reports}, ExitUsage},
		{[]string{"report", "export", reports}, ExitUsage},
		{[]string{"report", "show", broken}, ExitUsage},
		{[]string{"report", "show", "dg-20991231T000000Z-abcdef"}, ExitInternal},
		{[]string{"report", "export", "dg-20991231T000000Z-abcdef"}, ExitInternal},
	} {
		if code, _, stderr := execute(t, tt.args...); code != tt.code {
			t.Errorf("%q: exit %d, want %d (%s)", tt.args, code, tt.code, stderr)
		}
	}
}

func TestRulesCommands(t *testing.T) {
	code, stdout, _ := execute(t, "rules", "list")
	if code != ExitNoProblem {
		t.Fatalf("exit %d", code)
	}
	for _, r := range rules.All() {
		if !strings.Contains(stdout, r.ID()) {
			t.Errorf("rules list lacks %s", r.ID())
		}
	}
	if code, stdout, _ = execute(t, "rules", "explain", "wr002"); code != ExitNoProblem || !strings.HasPrefix(stdout, "# WR002:") || !strings.Contains(stdout, "## The fix") {
		t.Errorf("explain: %d %q", code, stdout[:min(len(stdout), 200)])
	}
	if code, _, stderr := execute(t, "rules", "explain", "WR999"); code != ExitUsage || !strings.Contains(stderr, "WR020") {
		t.Errorf("unknown rule: %d %q", code, stderr)
	}
}

// Every rule has a page with a title, and every page a rule: the catalog
// and docs/rules move together (CLAUDE.md, adding a rule).
func TestEveryRuleHasItsPage(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range rules.All() {
		ids[r.ID()] = true
		page, ok := ruledocs.Page(r.ID())
		if !ok || ruledocs.Title(page) == "" {
			t.Errorf("%s has no page with a title", r.ID())
		}
	}
	pages, err := filepath.Glob(filepath.Join("..", "..", "docs", "rules", "WR*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pages {
		if id := strings.TrimSuffix(filepath.Base(p), ".md"); !ids[id] {
			t.Errorf("%s documents no rule in the catalog", p)
		}
	}
}
