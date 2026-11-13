// Package report renders diagnoses for people and agents: the terminal text
// (also the MCP text summary), the compact structured form that MCP clients
// read first (ADR 0001), and report bundles. It collects nothing.
package report

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/rules"
)

const wrapWidth = 78

// RenderText writes a diagnosis for people (INITIAL.md §5). Names, labels
// and error messages come from Docker and from probes, so the whole text is
// sanitized before it reaches the terminal.
func RenderText(w io.Writer, d *engine.Diagnosis) {
	var b strings.Builder
	renderText(&b, d)
	_, _ = io.WriteString(w, Sanitize(b.String())) // a failed write to the terminal is not actionable
}

// Sanitize replaces control characters (escape sequences start with one),
// bidirectional-text overrides and other invisible format characters (the
// Unicode tag block among them) with U+FFFD, keeping newlines and tabs, so a
// container label or an error message can't drive the terminal or hide text
// from the person reading it.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n', r == '\t':
			return r
		case unicode.IsControl(r), unicode.Is(unicode.Bidi_Control, r), unicode.Is(unicode.Cf, r):
			return '\uFFFD'
		default:
			return r
		}
	}, s)
}

func renderText(w io.Writer, d *engine.Diagnosis) {
	fmt.Fprintf(w, "%s %s → %s — %s\n", verdictMark(d.Verdict), sourceLabel(d), d.Question.To.String(), verdictText(d))

	findings := d.Findings
	if d.Verdict != engine.VerdictNoProblem && len(findings) > 0 {
		// The primary finding's title says what the summary would.
		fmt.Fprintln(w)
		renderFinding(w, findings[0], d.Facts)
		findings = findings[1:]
	} else {
		writeWrapped(w, "  ", "  ", d.Summary)
		if len(d.Facts) > 0 {
			fmt.Fprintln(w)
			renderFacts(w, "  facts", d.Facts)
		}
	}
	if len(findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "also found")
		for _, f := range findings {
			fmt.Fprintf(w, "%-6s %s (%s)\n", f.RuleID, f.Title, f.Confidence)
			writeWrapped(w, "  fix    ", "         ", f.Fix)
		}
	}
	if len(d.Gaps) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "could not check")
		for _, g := range d.Gaps {
			writeWrapped(w, "  • ", "    ", fmt.Sprintf("%s (%s): %s", g.What, g.Why, g.Detail))
			if g.HowToEnable != "" {
				writeWrapped(w, "    → ", "      ", g.HowToEnable)
			}
		}
	}
	fmt.Fprintln(w)
	writeSideEffects(w, d)
}

// sourceLabel is the source's display name: its Compose service or name.
func sourceLabel(d *engine.Diagnosis) string {
	if src, ok := evidence.NewView(d.Question, d.Evidence).Source(); ok {
		return src.C.DisplayName()
	}
	if d.Question.From.Kind == evidence.SourceHost {
		return "host"
	}
	return d.Question.From.Ref
}

func verdictMark(v string) string {
	switch v {
	case engine.VerdictNoProblem:
		return "✓"
	case engine.VerdictCause, engine.VerdictLikelyCause:
		return "✗"
	default:
		return "?"
	}
}

func verdictText(d *engine.Diagnosis) string {
	switch d.Verdict {
	case engine.VerdictCause, engine.VerdictLikelyCause:
		return fmt.Sprintf("%s (%s)", strings.ReplaceAll(d.Verdict, "_", " "), d.Findings[0].Confidence)
	default:
		return strings.ReplaceAll(d.Verdict, "_", " ")
	}
}

func renderFinding(w io.Writer, f rules.Finding, facts []engine.Fact) {
	fmt.Fprintf(w, "%-6s %s\n", f.RuleID, f.Title)
	writeWrapped(w, "       ", "       ", f.Explanation)
	renderFacts(w, "  facts", facts)
	writeWrapped(w, "  fix    ", "         ", f.Fix)
	fmt.Fprintf(w, "  docs   %s\n", f.DocURL)
}

// renderFacts lists facts under a label padded to the "  fix    " column,
// with their evidence IDs aligned after them.
func renderFacts(w io.Writer, label string, facts []engine.Fact) {
	width := 0
	for _, f := range facts {
		width = max(width, len([]rune(f.Text)))
	}
	width = min(width, 56)
	col := max(len(label)+1, 9)
	for i, f := range facts {
		prefix := strings.Repeat(" ", col)
		if i == 0 {
			prefix = label + strings.Repeat(" ", col-len(label))
		}
		ids := ""
		if len(f.Evidence) > 0 {
			ids = "[" + strings.Join(f.Evidence, " ") + "]"
		}
		pad := max(width-len([]rune(f.Text)), 0)
		fmt.Fprintf(w, "%s• %s%s  %s\n", prefix, f.Text, strings.Repeat(" ", pad), ids)
	}
}

// writeSideEffects reports Docker writes and changes, which are always none
// (INITIAL.md §3.3).
func writeSideEffects(w io.Writer, d *engine.Diagnosis) {
	effects := "none"
	if len(d.SideEffects) > 0 {
		effects = strings.Join(d.SideEffects, "; ")
	}
	changes := "changes made: none"
	if d.ChangesMade {
		changes = "changes made: yes"
	}
	line := "side effects: " + effects
	if len([]rune(line))+len(" · "+changes) <= wrapWidth {
		fmt.Fprintln(w, line+" · "+changes)
		return
	}
	writeWrapped(w, "", "  ", line)
	fmt.Fprintln(w, changes)
}

// writeWrapped writes text wrapped at wrapWidth, with first on the first
// line and indent on the others.
func writeWrapped(w io.Writer, first, indent, text string) {
	words := strings.Fields(text)
	line := first
	empty := true
	for _, word := range words {
		if !empty && len([]rune(line))+1+len([]rune(word)) > wrapWidth {
			fmt.Fprintln(w, line)
			line, empty = indent, true
		}
		if empty {
			line += word
			empty = false
		} else {
			line += " " + word
		}
	}
	if !empty {
		fmt.Fprintln(w, line)
	}
}
