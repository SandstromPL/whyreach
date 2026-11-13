package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/rules"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/report -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs (run go test ./internal/report -update):\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

var (
	workerID = strings.Repeat("b", 64)
	apiID    = strings.Repeat("a", 64)
	question = evidence.Question{
		From: evidence.Source{Kind: evidence.SourceContainer, Ref: "container:shop-worker-1", ContainerID: workerID},
		To:   evidence.Target{Host: "api", Port: 8080, Proto: "tcp", Class: evidence.TargetName},
	}
	workerEv = evidence.Evidence{
		ID: "ev-02", Kind: evidence.KindContainer, Status: evidence.StatusOK,
		Context: evidence.ContextRef{Kind: evidence.ContextContainer, Container: workerID[:12], Name: "worker"},
		Data:    evidence.Container{ID: workerID, Name: "shop-worker-1", State: evidence.StateRunning, Compose: &evidence.ComposeRef{Project: "shop", Service: "worker"}},
	}
)

func diagnoses() map[string]*engine.Diagnosis {
	wr002 := rules.Finding{
		RuleID: "WR002", Title: "api listens only on 127.0.0.1:8080 inside its container", Layer: rules.LayerListener,
		Confidence: rules.High, Supporting: []string{"ev-03", "ev-04", "ev-06"},
		Explanation: "api's only listener for port 8080 is 127.0.0.1:8080 (in api). A socket bound to loopback accepts connections only from inside api's own network namespace, so worker can't reach it.",
		Fix:         "Make the server in api listen on 0.0.0.0:8080 (or [::]:8080), for example with --host 0.0.0.0 or a HOST=0.0.0.0 setting, then restart api.",
		DocURL:      "docs/rules/WR002.md",
	}
	wr004 := rules.Finding{
		RuleID: "WR004", Title: "worker and api share no network", Layer: rules.LayerNaming, Confidence: rules.High,
		Supporting:  []string{"ev-02", "ev-03"},
		Explanation: "api is on network a_default (Compose project a), and worker only on network b_default (Compose project b).",
		Fix:         "Put worker on api's network.", DocURL: "docs/rules/WR004.md",
	}
	base := func() *engine.Diagnosis {
		return &engine.Diagnosis{
			ID: "dg-test", SchemaVersion: engine.SchemaVersion, Question: question,
			Findings: []rules.Finding{}, Facts: []engine.Fact{}, Gaps: []engine.Gap{}, SideEffects: []string{},
			Evidence: []evidence.Evidence{workerEv}, Timing: engine.Timing{StartedAt: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC), TotalMS: 180},
		}
	}
	cause := base()
	cause.Verdict = engine.VerdictCause
	cause.Summary = "worker can't reach api:8080: " + wr002.Title + "."
	cause.Findings = []rules.Finding{wr002}
	cause.Facts = []engine.Fact{
		{Text: "worker and api share network shop_default", Evidence: []string{"ev-02", "ev-03"}},
		{Text: `"api" → 172.22.0.3 via 127.0.0.11:53, in worker`, Evidence: []string{"ev-05"}},
		{Text: "connect 172.22.0.3:8080 from worker: refused, ECONNREFUSED (0.1 ms)", Evidence: []string{"ev-06"}},
		{Text: "listening on port 8080 in api: 127.0.0.1:8080/tcp", Evidence: []string{"ev-04"}},
	}
	cause.SideEffects = []string{"ephemeral probe container wr-probe-3f2a9c1d (removed)"}

	also := base()
	also.Verdict = engine.VerdictCause
	also.Summary = "worker can't reach api:8080: worker and api share no network."
	also.Findings = []rules.Finding{wr004, wr002}

	ok := base()
	ok.Verdict = engine.VerdictNoProblem
	ok.Summary = "worker connected to api:8080 (172.22.0.3:8080): no problem reproduced."
	ok.Facts = []engine.Fact{{Text: "connect 172.22.0.3:8080 from worker: connected (0.2 ms)", Evidence: []string{"ev-06"}}}

	inconclusive := base()
	inconclusive.Verdict = engine.VerdictInconclusive
	inconclusive.Summary = "No cause found for worker → api:8080, but 1 thing could not be checked (see gaps)."
	inconclusive.Gaps = []engine.Gap{{
		What: "name lookup and TCP connect from worker", Why: "permission", Detail: "probe containers are off (tier 2b)",
		HowToEnable: "Enable probe containers: set probe_containers = true under [permissions] in ~/.config/whyreach/config.toml.",
	}}
	return map[string]*engine.Diagnosis{"cause": cause, "also-found": also, "no-problem": ok, "inconclusive": inconclusive}
}

func TestRenderTextGolden(t *testing.T) {
	for name, d := range diagnoses() {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			RenderText(&b, d)
			golden(t, "text-"+name+".golden", b.Bytes())
		})
	}
}

func TestDiagnosisJSONGolden(t *testing.T) {
	d := diagnoses()["cause"]
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "json-cause.golden", append(b, '\n'))
	// Agents read the structured form first: it must lead with the verdict.
	if !bytes.HasPrefix(b, []byte("{\n  \"verdict\": \"cause_identified\",\n  \"summary\":")) {
		t.Errorf("JSON must lead with verdict and summary:\n%s", b[:80])
	}
}

func TestRenderTextSanitizesDockerStrings(t *testing.T) {
	d := diagnoses()["cause"]
	evil := "api\x1b[2J\x1b]0;pwned\x07\u202eexe.txt"
	d.Findings[0].Title = evil
	d.Facts[0].Text = evil
	d.SideEffects = []string{evil}
	var b bytes.Buffer
	RenderText(&b, d)
	out := b.String()
	for _, bad := range []string{"\x1b", "\x07", "\u202e"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q:\n%q", bad, out)
		}
	}
	if !strings.Contains(out, "api\uFFFD[2J") {
		t.Errorf("want the escape replaced, not dropped:\n%q", out)
	}
	if got := Sanitize("a\tb\nc\rd"); got != "a\tb\nc\uFFFDd" {
		t.Errorf("Sanitize = %q", got)
	}
}
