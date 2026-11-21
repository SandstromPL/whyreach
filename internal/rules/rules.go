// Package rules turns evidence into findings. Rules are pure functions of an
// evidence.View: no I/O, no clock, no randomness. Each rule belongs to a
// layer; the engine ranks findings by layer so that the earliest broken layer
// gives the primary finding and its consequences are suppressed (ADR 0002).
//
// Rule IDs are permanent: never renumber or reuse them.
package rules

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Layer is a rule's place in the precedence order: the order in which a
// connection depends on things (INITIAL.md §4.5).
type Layer int

// Layers, earliest first.
const (
	LayerDestination Layer = 1 // is the destination there and running?
	LayerAddressing  Layer = 2 // is the source aiming at the right thing?
	LayerNaming      Layer = 3 // can the source reach the destination by name at all?
	LayerPath        Layer = 4 // can packets get there?
	LayerListener    Layer = 5 // is the right socket listening?
	LayerAdvisory    Layer = 6 // could something break a working connection?
)

func (l Layer) String() string {
	switch l {
	case LayerDestination:
		return "destination"
	case LayerAddressing:
		return "addressing"
	case LayerNaming:
		return "naming"
	case LayerPath:
		return "path"
	case LayerListener:
		return "listener"
	case LayerAdvisory:
		return "advisory"
	default:
		return "layer " + strconv.Itoa(int(l))
	}
}

// Confidence is a rule-defined label, not a number (CLAUDE.md).
type Confidence string

// Confidence levels.
const (
	High   Confidence = "high"   // the evidence settles the cause
	Medium Confidence = "medium" // the cause is inferred; one piece of evidence is missing
	Low    Confidence = "low"    // circumstantial evidence only
)

// Rank orders confidences: high is 3, low is 1.
func (c Confidence) Rank() int {
	switch c {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// Lower is one level down: contradicting evidence lowers confidence by one.
func (c Confidence) Lower() Confidence {
	switch c {
	case High:
		return Medium
	default:
		return Low
	}
}

// Finding is a hypothesis about the cause, with the evidence behind it.
type Finding struct {
	RuleID        string     `json:"rule_id"`
	Title         string     `json:"title"`
	Layer         Layer      `json:"layer"`
	Confidence    Confidence `json:"confidence"`
	Explanation   string     `json:"explanation"`
	Supporting    []string   `json:"supporting"`              // evidence IDs
	Contradicting []string   `json:"contradicting,omitempty"` // evidence IDs
	Fix           string     `json:"fix"`                     // advice only; whyreach never executes it
	DocURL        string     `json:"doc_url"`
}

// Rule is one check from the catalog (INITIAL.md §4.6).
type Rule interface {
	ID() string                         // "WR002": permanent
	Layer() Layer                       // its place in the precedence order
	Requires() []evidence.Kind          // missing → not evaluated → a gap
	Supersedes() []string               // findings it makes redundant
	Evaluate(v evidence.View) []Finding // pure
}

// All returns the rules in evaluation order: by layer, and within a layer in
// the order of the table in INITIAL.md §4.5.
func All() []Rule {
	return []Rule{
		wr008{}, wr010{}, // 1. destination
		wr007{}, wr011{}, wr006{}, wr019{}, wr024{}, // 2. addressing
		wr004{}, wr009{}, wr005{}, wr020{}, // 3. naming
		wr015{}, wr013{}, wr016{}, // 4. path
		wr002{}, wr012{}, wr014{}, wr003{}, wr001{}, // 5. listener
	}
}

// ByID returns the rule with an ID.
func ByID(id string) (Rule, bool) {
	for _, r := range All() {
		if r.ID() == id {
			return r, true
		}
	}
	return nil, false
}

// Missing returns the kinds a rule requires that have no observation.
func Missing(r Rule, v evidence.View) []evidence.Kind {
	var out []evidence.Kind
	for _, k := range r.Requires() {
		if !v.Has(k) {
			out = append(out, k)
		}
	}
	return out
}

// Suppressed is a finding dropped because another finding explains it.
type Suppressed struct {
	Finding
	By string `json:"by"` // the rule whose finding superseded it
}

// Ranked is the outcome of precedence: the primary finding, independent
// findings in fix order, and findings that were only consequences.
type Ranked struct {
	Primary    *Finding
	AlsoFound  []Finding
	Suppressed []Suppressed
}

// Rank applies ADR 0002's precedence. Findings are ordered by layer, then
// confidence, then the rule's evaluation order. A finding whose rule another
// finding's rule supersedes is a consequence and is suppressed; the first
// remaining finding is primary (the highest-confidence finding in the
// earliest layer that has one) and the rest are "also found", in fix order.
func Rank(findings []Finding) Ranked {
	order := map[string]int{}
	supersedes := map[string][]string{}
	for i, r := range All() {
		order[r.ID()] = i
		supersedes[r.ID()] = r.Supersedes()
	}
	rank := func(id string) int {
		if i, ok := order[id]; ok {
			return i
		}
		return len(order)
	}
	sorted := slices.Clone(findings)
	slices.SortStableFunc(sorted, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(a.Layer, b.Layer),
			cmp.Compare(b.Confidence.Rank(), a.Confidence.Rank()),
			cmp.Compare(rank(a.RuleID), rank(b.RuleID)),
			strings.Compare(a.RuleID, b.RuleID),
		)
	})
	var r Ranked
	var kept []Finding
	for _, f := range sorted {
		if by := supersededBy(f.RuleID, sorted, supersedes); by != "" {
			r.Suppressed = append(r.Suppressed, Suppressed{Finding: f, By: by})
			continue
		}
		kept = append(kept, f)
	}
	if len(kept) > 0 {
		r.Primary = &kept[0]
		r.AlsoFound = kept[1:]
	}
	return r
}

// supersededBy returns the first rule among findings that supersedes id.
func supersededBy(id string, findings []Finding, supersedes map[string][]string) string {
	for _, g := range findings {
		if g.RuleID != id && slices.Contains(supersedes[g.RuleID], id) {
			return g.RuleID
		}
	}
	return ""
}

// DocURL is the page that documents a rule.
func DocURL(id string) string { return "docs/rules/" + id + ".md" }
