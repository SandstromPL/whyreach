package engine

import (
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// SchemaVersion of the Diagnosis JSON.
const SchemaVersion = 1

// Verdicts, decided in this order (INITIAL.md §4.4).
const (
	VerdictNoProblem    = "no_problem_reproduced" // the connect from the source succeeded
	VerdictCause        = "cause_identified"      // the primary finding is high
	VerdictLikelyCause  = "likely_cause"          // the primary finding is medium
	VerdictInconclusive = "inconclusive"          // anything else; see the gaps
)

// Diagnosis is the answer. It leads with the verdict and a one-sentence
// summary (ADR 0001: agents read the structured form first).
type Diagnosis struct {
	Verdict       string              `json:"verdict"`
	Summary       string              `json:"summary"`
	ID            string              `json:"id"`
	SchemaVersion int                 `json:"schema_version"`
	Question      evidence.Question   `json:"question"`
	Findings      []rules.Finding     `json:"findings"`             // primary first, then "also found" in fix order
	Suppressed    []rules.Suppressed  `json:"suppressed,omitempty"` // consequences of another finding
	Facts         []Fact              `json:"facts"`
	Gaps          []Gap               `json:"gaps"`
	NextChecks    []NextCheck         `json:"next_checks"`
	SideEffects   []string            `json:"side_effects"`
	ChangesMade   bool                `json:"changes_made"` // always false
	Timing        Timing              `json:"timing"`
	Evidence      []evidence.Evidence `json:"evidence"`
}

// Primary is the primary finding, if any.
func (d *Diagnosis) Primary() *rules.Finding {
	if len(d.Findings) == 0 {
		return nil
	}
	return &d.Findings[0]
}

// Fact is a short observation with the evidence behind it.
type Fact struct {
	Text     string   `json:"text"`
	Evidence []string `json:"evidence"`
}

// Gap is something whyreach could not check, and how to make it checkable.
// Missing evidence is never a negative result.
type Gap struct {
	What        string   `json:"what"`
	Why         string   `json:"why"` // permission, unsupported, timeout, failed, error, policy
	Detail      string   `json:"detail,omitempty"`
	HowToEnable string   `json:"how_to_enable,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

// NextCheck is a machine-actionable follow-up: a whyreach tool and its
// arguments.
type NextCheck struct {
	Why  string            `json:"why"`
	Tool string            `json:"tool"`
	Args map[string]string `json:"args"`
}

// Timing reports how long the diagnosis took.
type Timing struct {
	StartedAt   time.Time          `json:"started_at"`
	TotalMS     float64            `json:"total_ms"`
	Stages      map[string]float64 `json:"stages_ms"`
	DeadlineHit bool               `json:"deadline_hit,omitempty"`
}

// ExitCode maps a verdict to the CLI's exit code (INITIAL.md §4.11).
func (d *Diagnosis) ExitCode() int {
	switch d.Verdict {
	case VerdictNoProblem:
		return 0
	case VerdictCause, VerdictLikelyCause:
		return 1
	default:
		return 2
	}
}
