package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// TestCompactGolden covers the structured content MCP clients show the
// model (ADR 0001) for the same diagnoses as the text goldens.
func TestCompactGolden(t *testing.T) {
	for name, d := range diagnoses() {
		t.Run(name, func(t *testing.T) {
			b, err := json.MarshalIndent(Compact(d), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			golden(t, "compact-"+name+".golden", append(b, '\n'))
			if !bytes.HasPrefix(b, []byte("{\n  \"verdict\": ")) || !bytes.Contains(b[:200], []byte(`"summary"`)) {
				t.Errorf("the compact form must lead with verdict and summary:\n%s", b[:120])
			}
			if bytes.Contains(b, []byte(`"evidence": [`)) && bytes.Contains(b, []byte(`"kind": "docker.container"`)) {
				t.Error("raw evidence belongs in report bundles, not the compact form")
			}
		})
	}
}

// TestCompactFitsTheBudget feeds Compact a diagnosis far over budget.
func TestCompactFitsTheBudget(t *testing.T) {
	d := diagnoses()["cause"]
	long := strings.Repeat("a very long explanation with many words ", 60)
	for i := range 8 {
		d.Findings = append(d.Findings, rules.Finding{
			RuleID: "WR00" + string(rune('1'+i)), Title: long, Confidence: rules.Medium, Explanation: long, Fix: long,
			Supporting: []string{"ev-01", "ev-02", "ev-03"}, DocURL: "docs/rules/WR001.md",
		})
	}
	for range 10 {
		d.Facts = append(d.Facts, engine.Fact{Text: long, Evidence: []string{"ev-04"}})
		d.Gaps = append(d.Gaps, engine.Gap{What: long, Why: "permission", Detail: long, HowToEnable: long})
	}
	d.Suppressed = []rules.Suppressed{{Finding: rules.Finding{RuleID: "WR001"}, By: "WR002"}}
	c := Compact(d)
	b, _ := json.Marshal(c)
	if len(b) > Budget {
		t.Errorf("compact form is %d bytes, over the %d budget", len(b), Budget)
	}
	if c.Verdict != d.Verdict || c.Summary == "" || len(c.Findings) == 0 || c.Findings[0].Fix == "" {
		t.Errorf("trimming must keep the verdict, summary and the primary fix: %+v", c)
	}
	if !strings.Contains(c.Omitted, "more findings") || !strings.Contains(c.Omitted, "WR001 (explained by WR002)") {
		t.Errorf("omitted = %q", c.Omitted)
	}
}

func TestCompactProbe(t *testing.T) {
	r := &engine.ProbeResult{Kind: "tcp", From: "container:worker", Target: "api:8080", Evidence: []evidence.Evidence{
		{ID: "ev-01", Kind: evidence.KindTCP, Subject: "api:8080", Status: evidence.StatusPermissionDenied,
			Context: evidence.ContextRef{Kind: evidence.ContextContainer, Name: "worker"},
			Err:     &evidence.Error{Code: evidence.CodePermissionDenied, Message: "probe containers are off (tier 2b)"}},
	}}
	c := CompactProbe(r, "turn them on")
	if c.HowToEnable != "turn them on" || len(c.Results) != 1 || c.Results[0].Kind != "tcp" ||
		!strings.Contains(c.Summary, "permission_denied") || c.SideEffects == nil {
		t.Errorf("compact probe = %+v", c)
	}
	var b bytes.Buffer
	RenderProbe(&b, c)
	if !strings.Contains(b.String(), "[ev-01] connect api:8080 from worker") {
		t.Errorf("text = %s", b.String())
	}
}
