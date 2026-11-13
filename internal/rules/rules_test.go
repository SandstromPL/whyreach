package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// fixture is one file in testdata/WRxxx/: a question, the evidence, and the
// findings the rule must return (none for a must-not-fire case).
type fixture struct {
	Description string              `json:"description"`
	Question    evidence.Question   `json:"question"`
	Evidence    []evidence.Evidence `json:"evidence"`
	Want        []wantFinding       `json:"want"`
}

type wantFinding struct {
	RuleID        string     `json:"rule_id"`
	Confidence    Confidence `json:"confidence"`
	Supporting    []string   `json:"supporting"`
	Contradicting []string   `json:"contradicting,omitempty"`
	FixContains   string     `json:"fix_contains,omitempty"` // checked separately
	FixLacks      string     `json:"fix_lacks,omitempty"`    // checked separately: text the fix must not have
}

func loadFixture(t *testing.T, path string) fixture {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return f
}

// TestFixtures runs every rule against its fixtures. Each rule needs at
// least one case where it fires and one where it must not (CLAUDE.md).
func TestFixtures(t *testing.T) {
	for _, r := range All() {
		t.Run(r.ID(), func(t *testing.T) {
			files, err := filepath.Glob(filepath.Join("testdata", r.ID(), "*.json"))
			if err != nil {
				t.Fatal(err)
			}
			var fires, quiet int
			for _, path := range files {
				f := loadFixture(t, path)
				if len(f.Want) == 0 {
					quiet++
				} else {
					fires++
				}
				t.Run(strings.TrimSuffix(filepath.Base(path), ".json"), func(t *testing.T) {
					v := evidence.NewView(f.Question, f.Evidence)
					got := r.Evaluate(v)
					var gotW []wantFinding
					for i, g := range got {
						gotW = append(gotW, wantFinding{RuleID: g.RuleID, Confidence: g.Confidence, Supporting: g.Supporting, Contradicting: g.Contradicting})
						checkFinding(t, r, g, v)
						if i < len(f.Want) && !strings.Contains(g.Fix, f.Want[i].FixContains) {
							t.Errorf("fix %q lacks %q", g.Fix, f.Want[i].FixContains)
						}
						if i < len(f.Want) && f.Want[i].FixLacks != "" && strings.Contains(g.Fix, f.Want[i].FixLacks) {
							t.Errorf("fix %q has %q", g.Fix, f.Want[i].FixLacks)
						}
					}
					if diff := cmp.Diff(f.Want, gotW, cmpopts.EquateEmpty(), cmpopts.IgnoreFields(wantFinding{}, "FixContains", "FixLacks")); diff != "" {
						t.Errorf("%s\n(-want +got):\n%s", f.Description, diff)
					}
				})
			}
			if fires == 0 || quiet == 0 {
				t.Errorf("%s needs fixtures that fire (%d) and that must not fire (%d)", r.ID(), fires, quiet)
			}
		})
	}
}

// checkFinding enforces what every finding must carry.
func checkFinding(t *testing.T, r Rule, f Finding, v evidence.View) {
	t.Helper()
	if f.RuleID != r.ID() || f.Layer != r.Layer() {
		t.Errorf("finding %s/layer %d from rule %s/layer %d", f.RuleID, f.Layer, r.ID(), r.Layer())
	}
	if f.Title == "" || f.Explanation == "" || f.Fix == "" || f.DocURL != "docs/rules/"+r.ID()+".md" {
		t.Errorf("incomplete finding: %+v", f)
	}
	if len(f.Supporting) == 0 {
		t.Errorf("a finding must cite its evidence: %+v", f)
	}
	for _, id := range append(slices.Clone(f.Supporting), f.Contradicting...) {
		if _, ok := v.Get(id); !ok {
			t.Errorf("finding cites unknown evidence %s", id)
		}
	}
	if !slices.IsSorted(f.Supporting) && len(f.Supporting) < 10 {
		t.Errorf("supporting IDs are not sorted: %v", f.Supporting)
	}
}

// TestEvaluateIsDeterministic runs each fixture twice and compares the full
// findings: same evidence, byte-identical output.
func TestEvaluateIsDeterministic(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*", "*.json"))
	for _, path := range files {
		f := loadFixture(t, path)
		v := evidence.NewView(f.Question, f.Evidence)
		for _, r := range All() {
			a, _ := json.Marshal(r.Evaluate(v))
			b, _ := json.Marshal(r.Evaluate(v))
			if string(a) != string(b) {
				t.Errorf("%s on %s is not deterministic", r.ID(), path)
			}
		}
	}
}

func TestRegistry(t *testing.T) {
	seen := map[string]bool{}
	prev := Layer(0)
	for _, r := range All() {
		if seen[r.ID()] {
			t.Errorf("duplicate rule %s", r.ID())
		}
		seen[r.ID()] = true
		if r.Layer() < prev {
			t.Errorf("%s (layer %d) is listed after layer %d", r.ID(), r.Layer(), prev)
		}
		prev = r.Layer()
		if len(r.Requires()) == 0 {
			t.Errorf("%s requires nothing", r.ID())
		}
		if _, err := os.Stat(filepath.Join("..", "..", DocURL(r.ID()))); err != nil {
			t.Errorf("%s has no doc page: %v", r.ID(), err)
		}
	}
	if _, ok := ByID("WR002"); !ok {
		t.Error("ByID(WR002) failed")
	}
	if _, ok := ByID("WR999"); ok {
		t.Error("ByID(WR999) succeeded")
	}
}

func TestRank(t *testing.T) {
	f := func(id string, layer Layer, c Confidence) Finding {
		return Finding{RuleID: id, Layer: layer, Confidence: c}
	}
	ruleIDs := func(fs []Finding) []string {
		var out []string
		for _, x := range fs {
			out = append(out, x.RuleID)
		}
		return out
	}
	tests := []struct {
		name       string
		in         []Finding
		primary    string
		also       []string
		suppressed map[string]string
	}{
		{
			name:    "earliest layer wins over a later high finding",
			in:      []Finding{f("WR002", LayerListener, High), f("WR004", LayerNaming, High)},
			primary: "WR004", also: []string{"WR002"},
		},
		{
			name:    "the destination layer comes first",
			in:      []Finding{f("WR004", LayerNaming, High), f("WR008", LayerDestination, High), f("WR007", LayerAddressing, High)},
			primary: "WR008", also: []string{"WR007", "WR004"},
		},
		{
			name:       "consequences are suppressed",
			in:         []Finding{f("WR016", LayerPath, Low), f("WR004", LayerNaming, High), f("WR005", LayerNaming, Medium), f("WR001", LayerListener, High), f("WR002", LayerListener, High)},
			primary:    "WR004",
			also:       []string{"WR002"},
			suppressed: map[string]string{"WR005": "WR004", "WR016": "WR004", "WR001": "WR002"},
		},
		{
			name:       "a starting destination explains nothing listening",
			in:         []Finding{f("WR001", LayerListener, High), f("WR010", LayerDestination, High), f("WR003", LayerListener, High)},
			primary:    "WR010",
			suppressed: map[string]string{"WR001": "WR010", "WR003": "WR010"},
		},
		{
			name:       "an unpublished port explains the empty host",
			in:         []Finding{f("WR001", LayerListener, High), f("WR019", LayerAddressing, High)},
			primary:    "WR019",
			suppressed: map[string]string{"WR001": "WR019"},
		},
		{
			name:       "a published port used between containers",
			in:         []Finding{f("WR003", LayerListener, High), f("WR006", LayerAddressing, High), f("WR012", LayerListener, High)},
			primary:    "WR006",
			suppressed: map[string]string{"WR003": "WR006", "WR012": "WR006"},
		},
		{
			name:    "a missing host-gateway mapping, and a host service on loopback after it",
			in:      []Finding{f("WR012", LayerListener, High), f("WR011", LayerAddressing, High)},
			primary: "WR011", also: []string{"WR012"},
		},
		{
			name:    "a typo and a failing upstream: the typo first",
			in:      []Finding{f("WR020", LayerNaming, High), f("WR005", LayerNaming, High)},
			primary: "WR005", also: []string{"WR020"},
		},
		{
			name:    "nothing found",
			in:      nil,
			primary: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Rank(tt.in)
			got := ""
			if r.Primary != nil {
				got = r.Primary.RuleID
			}
			if got != tt.primary {
				t.Errorf("primary = %q, want %q", got, tt.primary)
			}
			if diff := cmp.Diff(tt.also, ruleIDs(r.AlsoFound)); diff != "" {
				t.Errorf("also found (-want +got):\n%s", diff)
			}
			gotSup := map[string]string{}
			for _, s := range r.Suppressed {
				gotSup[s.RuleID] = s.By
			}
			if tt.suppressed == nil {
				tt.suppressed = map[string]string{}
			}
			if diff := cmp.Diff(tt.suppressed, gotSup); diff != "" {
				t.Errorf("suppressed (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConfidence(t *testing.T) {
	if High.Lower() != Medium || Medium.Lower() != Low || Low.Lower() != Low {
		t.Error("Lower must step down one level and stop at low")
	}
	if High.Rank() <= Medium.Rank() || Medium.Rank() <= Low.Rank() {
		t.Error("Rank order")
	}
}
