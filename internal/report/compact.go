package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// Budget is the most the compact diagnosis may take as JSON: about 1.5k
// tokens (INITIAL.md §3.6). Compact trims until it fits.
const Budget = 6000

// Diagnosis is the compact form of a diagnosis that MCP clients read first
// (ADR 0001): verdict and summary lead, findings carry their fix and the
// evidence IDs behind them, facts are short, and raw evidence is left for
// report bundles.
type Diagnosis struct {
	Verdict     string             `json:"verdict" jsonschema:"no_problem_reproduced, cause_identified, likely_cause or inconclusive"`
	Summary     string             `json:"summary" jsonschema:"one sentence"`
	ID          string             `json:"id" jsonschema:"pass to save_report to keep the full evidence"`
	From        string             `json:"from"`
	To          string             `json:"to"`
	Findings    []Finding          `json:"findings" jsonschema:"primary first, then independent findings in fix order"`
	Facts       []engine.Fact      `json:"facts" jsonschema:"what was observed, with evidence IDs; every address names its network namespace"`
	Gaps        []Gap              `json:"gaps,omitempty" jsonschema:"what could not be checked and how to enable it"`
	NextChecks  []engine.NextCheck `json:"next_checks" jsonschema:"follow-up whyreach tool calls with ready-to-use arguments"`
	SideEffects []string           `json:"side_effects" jsonschema:"Docker writes made, such as ephemeral probe containers"`
	ChangesMade bool               `json:"changes_made" jsonschema:"always false: whyreach never changes anything"`
	Omitted     string             `json:"omitted,omitempty" jsonschema:"what was cut to keep this short; save_report has it all"`
}

// Finding is one cause or independent problem.
type Finding struct {
	RuleID        string   `json:"rule_id"`
	Title         string   `json:"title"`
	Confidence    string   `json:"confidence" jsonschema:"high, medium or low"`
	Explanation   string   `json:"explanation,omitempty"`
	Fix           string   `json:"fix" jsonschema:"advice only; whyreach never applies it"`
	Evidence      []string `json:"evidence"`
	Contradicting []string `json:"contradicting,omitempty"`
	Doc           string   `json:"doc"`
}

// Gap is something that could not be checked.
type Gap struct {
	What        string `json:"what"`
	Why         string `json:"why"`
	Detail      string `json:"detail,omitempty"`
	HowToEnable string `json:"how_to_enable,omitempty"`
}

// Limits of the compact form, before the budget's final trim.
const (
	maxFindings   = 4
	maxGaps       = 4
	maxNextChecks = 3
	maxText       = 600
	maxFactText   = 220
	maxDetail     = 240
)

// Compact derives the compact form of a diagnosis.
func Compact(d *engine.Diagnosis) Diagnosis {
	c := Diagnosis{
		Verdict: d.Verdict, Summary: cut(d.Summary, maxText), ID: d.ID,
		From: d.Question.From.Ref, To: d.Question.To.String(),
		Findings: []Finding{}, Facts: []engine.Fact{}, NextChecks: []engine.NextCheck{},
		SideEffects: d.SideEffects, ChangesMade: d.ChangesMade,
	}
	if c.SideEffects == nil {
		c.SideEffects = []string{}
	}
	var dropped []string
	for i, f := range d.Findings {
		if i == maxFindings {
			dropped = append(dropped, fmt.Sprintf("%d more findings", len(d.Findings)-i))
			break
		}
		c.Findings = append(c.Findings, compactFinding(f, i == 0 && d.Verdict != engine.VerdictNoProblem))
	}
	for _, f := range d.Facts {
		c.Facts = append(c.Facts, engine.Fact{Text: cut(f.Text, maxFactText), Evidence: f.Evidence})
	}
	for i, g := range d.Gaps {
		if i == maxGaps {
			dropped = append(dropped, fmt.Sprintf("%d more gaps", len(d.Gaps)-i))
			break
		}
		c.Gaps = append(c.Gaps, Gap{What: cut(g.What, maxDetail), Why: g.Why, Detail: cut(g.Detail, maxDetail), HowToEnable: cut(g.HowToEnable, maxText)})
	}
	for i, n := range d.NextChecks {
		if i == maxNextChecks {
			break
		}
		c.NextChecks = append(c.NextChecks, engine.NextCheck{Why: cut(n.Why, maxDetail), Tool: n.Tool, Args: n.Args})
	}
	if len(d.Suppressed) > 0 {
		var ids []string
		for _, s := range d.Suppressed {
			ids = append(ids, s.RuleID+" (explained by "+s.By+")")
		}
		dropped = append(dropped, "consequences "+strings.Join(ids, ", "))
	}
	c.Omitted = strings.Join(dropped, "; ")
	fit(&c)
	return c
}

func compactFinding(f rules.Finding, primary bool) Finding {
	out := Finding{
		RuleID: f.RuleID, Title: cut(f.Title, maxDetail), Confidence: string(f.Confidence),
		Fix: cut(f.Fix, maxText), Evidence: f.Supporting, Contradicting: f.Contradicting, Doc: f.DocURL,
	}
	if out.Evidence == nil {
		out.Evidence = []string{}
	}
	if primary {
		out.Explanation = cut(f.Explanation, maxText)
	}
	return out
}

// fit trims the least important parts until the JSON is within Budget:
// first the later facts and gaps' details, then later findings' fixes.
func fit(c *Diagnosis) {
	size := func() int {
		b, _ := json.Marshal(c)
		return len(b)
	}
	for size() > Budget {
		switch {
		case len(c.Facts) > 4:
			c.Facts = c.Facts[:len(c.Facts)-1]
			c.note("later facts")
		case gapDetails(c):
		case len(c.Findings) > 1:
			c.Findings = c.Findings[:len(c.Findings)-1]
			c.note("later findings")
		case len(c.Gaps) > 1:
			c.Gaps = c.Gaps[:len(c.Gaps)-1]
			c.note("later gaps")
		case len(c.Facts) > 0:
			c.Facts = c.Facts[:len(c.Facts)-1]
			c.note("later facts")
		case len(c.Findings) > 0 && c.Findings[0].Explanation != "":
			c.Findings[0].Explanation = ""
			c.note("the explanation")
		case len(c.NextChecks) > 1:
			c.NextChecks = c.NextChecks[:len(c.NextChecks)-1]
			c.note("later next checks")
		case len([]rune(c.Summary)) > 300:
			c.Summary = cut(c.Summary, 300)
			c.note("the end of the summary")
		default:
			return // nothing left to trim
		}
	}
}

func gapDetails(c *Diagnosis) bool {
	for i := range c.Gaps {
		if c.Gaps[i].Detail != "" {
			c.Gaps[i].Detail = ""
			c.note("gap details")
			return true
		}
	}
	return false
}

func (c *Diagnosis) note(what string) {
	if !strings.Contains(c.Omitted, what) {
		if c.Omitted != "" {
			c.Omitted += "; "
		}
		c.Omitted += what
	}
}

// cut shortens s to n runes, marking the cut.
func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n-1])) + "…"
}

// ProbeResult is the compact form of run_probe's result.
type ProbeResult struct {
	Kind        string   `json:"kind"`
	From        string   `json:"from"`
	Target      string   `json:"target,omitempty"`
	Summary     string   `json:"summary"`
	Results     []Record `json:"results"`
	HowToEnable string   `json:"how_to_enable,omitempty"`
	SideEffects []string `json:"side_effects"`
	ChangesMade bool     `json:"changes_made"`
}

// Record is one evidence record in a line.
type Record struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status" jsonschema:"ok means observed; a refused connect is ok with outcome refused"`
	Text   string `json:"text"`
}

// CompactProbe derives run_probe's result. howTo is the advice for a check
// that needs a permission it doesn't have.
func CompactProbe(r *engine.ProbeResult, howTo string) ProbeResult {
	out := ProbeResult{Kind: r.Kind, From: r.From, Target: r.Target, Results: []Record{}, SideEffects: r.SideEffects, ChangesMade: r.ChangesMade}
	if out.SideEffects == nil {
		out.SideEffects = []string{}
	}
	var lines []string
	for _, e := range r.Evidence {
		line := EvidenceLine(e)
		out.Results = append(out.Results, Record{ID: e.ID, Kind: kindName(e.Kind), Status: string(e.Status), Text: line})
		lines = append(lines, line)
		if e.Status == evidence.StatusPermissionDenied {
			out.HowToEnable = howTo
		}
	}
	out.Summary = strings.Join(lines, "; ")
	if out.Summary == "" {
		out.Summary = "no result"
	}
	return out
}

func kindName(k evidence.Kind) string {
	switch k {
	case evidence.KindDNS:
		return "dns"
	case evidence.KindTCP:
		return "tcp"
	case evidence.KindListeners:
		return "listeners"
	default:
		return string(k)
	}
}

// EvidenceLine describes one record in a sentence, naming where it was
// observed.
func EvidenceLine(e evidence.Evidence) string {
	where := e.Context.String()
	if e.Context.Kind == evidence.ContextHost {
		where = "the host"
	}
	if !e.OK() {
		msg := ""
		if e.Err != nil {
			msg = ": " + e.Err.Message
		}
		return fmt.Sprintf("%s %s from %s: %s%s", kindVerb(e.Kind), e.Subject, where, e.Status, msg)
	}
	switch d := e.Data.(type) {
	case evidence.TCPProbe:
		s := fmt.Sprintf("connect %s from %s: %s", d.Addr, where, d.Outcome)
		if d.Errno != "" {
			s += ", " + d.Errno
		}
		s += fmt.Sprintf(" (%.1f ms)", evidence.Millis(d.RTT))
		if d.Via == evidence.ViaMetadata {
			s += ", address from Docker metadata"
		}
		if d.Outcome == evidence.OutcomeClosed {
			s += ": accepted, then closed at once without a byte"
		}
		return s
	case evidence.DNSProbe:
		if len(d.Answers) == 0 {
			return fmt.Sprintf("%q did not resolve in %s (%s from %s)", d.Name, where, d.Rcode, d.Server)
		}
		var as []string
		for _, a := range d.Answers {
			as = append(as, a.String())
		}
		via := "via " + d.Server
		if d.Via == evidence.ViaHosts {
			via = "via /etc/hosts"
		}
		return fmt.Sprintf("%q → %s %s, in %s", d.Name, strings.Join(as, ", "), via, where)
	case evidence.Listeners:
		var socks []string
		for _, s := range d.Sockets {
			if s.IsDockerDNS() {
				continue
			}
			if len(socks) == 30 {
				socks = append(socks, "…")
				break
			}
			socks = append(socks, s.Local.String())
		}
		if len(socks) == 0 {
			return "nothing listens on TCP in " + where
		}
		return "listening on TCP in " + where + ": " + strings.Join(socks, ", ")
	default:
		return fmt.Sprintf("%s %s in %s: %s", e.Kind, e.Subject, where, e.Status)
	}
}

func kindVerb(k evidence.Kind) string {
	switch k {
	case evidence.KindDNS:
		return "look up"
	case evidence.KindTCP:
		return "connect"
	case evidence.KindListeners:
		return "read listeners"
	default:
		return string(k)
	}
}
