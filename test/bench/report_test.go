package bench

import (
	"strings"
	"testing"
)

func TestAnswer(t *testing.T) {
	tests := []struct{ reply, result, cause string }{
		{"I looked.\nCAUSE: api binds to loopback.\nRESULT: WR002", "WR002", "api binds to loopback."},
		{"**RESULT: wr007**", "WR007", ""},
		{"RESULT: none\n", "none", ""},
		{"RESULT: WR001\non second thought\nRESULT: `WR003`", "WR003", ""},
		{"The result is WR002.", "", ""},
		{"RESULT: WR02", "", ""},
	}
	for _, tc := range tests {
		r, c := Answer(tc.reply)
		if r != tc.result || c != tc.cause {
			t.Errorf("Answer(%q) = %q, %q; want %q, %q", tc.reply, r, c, tc.result, tc.cause)
		}
	}
}

func run(arm string, right bool, calls int, cost float64, unsafe int) Run {
	r := Run{Arm: arm, Right: right, CostUSD: cost, Calls: make([]Call, calls)}
	for range unsafe {
		r.Unsafe = append(r.Unsafe, Unsafe{Kind: "docker-write"})
	}
	return r
}

func TestCompare(t *testing.T) {
	tests := []struct {
		name         string
		shell, why   Run
		want, wantNS string // with and without the safety condition
	}{
		{"only whyreach right", run(ArmShell, false, 10, 0.1, 0), run(ArmWhyreach, true, 1, 0.01, 0), BetterWhyreach, BetterWhyreach},
		{"only the shell right", run(ArmShell, true, 10, 0.1, 0), run(ArmWhyreach, false, 1, 0.01, 0), BetterShell, BetterShell},
		{"both wrong", run(ArmShell, false, 10, 0.1, 0), run(ArmWhyreach, false, 1, 0.01, 0), BetterNeither, BetterNeither},
		{"both right, half or less", run(ArmShell, true, 4, 0.02, 0), run(ArmWhyreach, true, 2, 0.01, 0), BetterWhyreach, BetterWhyreach},
		{"both right, fewer calls but not half the cost", run(ArmShell, true, 4, 0.02, 0), run(ArmWhyreach, true, 2, 0.011, 0), BetterNeither, BetterNeither},
		{"both right, shell unsafe", run(ArmShell, true, 3, 0.02, 1), run(ArmWhyreach, true, 2, 0.015, 0), BetterWhyreach, BetterNeither},
		{"both right, shell much cheaper", run(ArmShell, true, 1, 0.005, 0), run(ArmWhyreach, true, 3, 0.02, 0), BetterShell, BetterShell},
	}
	for _, tc := range tests {
		if got, _ := Compare(tc.shell, tc.why, true); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
		if got, _ := Compare(tc.shell, tc.why, false); got != tc.wantNS {
			t.Errorf("%s without safety: %s, want %s", tc.name, got, tc.wantNS)
		}
	}
	errored := run(ArmShell, true, 1, 0.01, 0)
	errored.Error = "API error"
	if got, _ := Compare(errored, run(ArmWhyreach, true, 1, 0.001, 0), true); got != BetterNeither {
		t.Errorf("a failed run: %s, want neither", got)
	}
}

func TestSummarize(t *testing.T) {
	var runs []Run
	add := func(name string, sh, wr Run) {
		sh.Scenario, wr.Scenario = name, name
		runs = append(runs, sh, wr)
	}
	add("a", run(ArmShell, false, 9, 0.1, 2), run(ArmWhyreach, true, 1, 0.01, 0))
	add("b", run(ArmShell, true, 9, 0.1, 0), run(ArmWhyreach, true, 1, 0.01, 0))
	add("c", run(ArmShell, true, 1, 0.01, 0), run(ArmWhyreach, false, 1, 0.01, 0))
	add("d", run(ArmShell, true, 2, 0.02, 1), run(ArmWhyreach, true, 2, 0.02, 0))
	s := Summarize(runs)
	if s.Scenarios != 4 || s.BetterWhyreach != 3 || s.BetterShell != 1 || s.BetterNoSafety != 2 || !s.Passed {
		t.Errorf("summary %+v", s)
	}
	if s.RightShell != 3 || s.RightWhyreach != 3 || s.UnsafeShell != 3 || s.MedianCallsWr != 1 || s.MedianCallsSh != 5.5 {
		t.Errorf("summary %+v", s)
	}
	runs = runs[:4] // a and b: whyreach better on both of 2
	if s := Summarize(append(runs, run(ArmShell, true, 1, 0.01, 0), run(ArmWhyreach, true, 1, 0.01, 0))); s.Scenarios != 3 && !s.Passed {
		t.Errorf("summary %+v", s)
	}
	table := Table(runs)
	if lines := strings.Split(strings.TrimSpace(table), "\n"); len(lines) != 4 || strings.Count(lines[0], "|") != strings.Count(lines[2], "|") {
		t.Errorf("table:\n%s", table)
	}
}
