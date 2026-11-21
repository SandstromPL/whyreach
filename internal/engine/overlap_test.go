package engine

import (
	"slices"
	"testing"

	"github.com/SandstromPL/whyreach/internal/rules"
)

// TestSubnetOverlap: a VPN's route that covers a target address in Docker
// network shop_back's subnet makes WR013 high, from the host and from a
// container, with probe containers or without (Probe? no). On the source's
// own network WR013 supersedes WR024. On Docker Desktop the route record is
// a gap, and WR013 stays quiet.
func TestSubnetOverlap(t *testing.T) {
	for _, probes := range []bool{false, true} {
		for _, from := range []string{"host", "container:shop-worker-1"} {
			d := diagnoseWith(t, overlapWorld(false), from, "10.8.1.5:5432", probes)
			if p := d.Primary(); p == nil || p.RuleID != "WR013" || p.Confidence != rules.High || d.Verdict != VerdictCause {
				t.Errorf("%s, probes=%v: primary %+v, verdict %s; want WR013 at high", from, probes, p, d.Verdict)
			}
		}
	}
	d := diagnoseWith(t, overlapWorld(false), "container:shop-worker-1", "172.22.0.200:8080", false)
	if p := d.Primary(); p == nil || p.RuleID != "WR013" || !slices.ContainsFunc(d.Suppressed, func(s rules.Suppressed) bool { return s.RuleID == "WR024" && s.By == "WR013" }) {
		t.Errorf("own network with a VPN route: primary %+v, suppressed %+v", d.Primary(), d.Suppressed)
	}
	d = diagnoseWith(t, overlapWorld(true), "host", "10.8.1.5:5432", false)
	if slices.ContainsFunc(d.Findings, func(f rules.Finding) bool { return f.RuleID == "WR013" }) || d.Verdict != VerdictInconclusive {
		t.Errorf("Docker Desktop: verdict %s, findings %+v", d.Verdict, d.Findings)
	}
}
