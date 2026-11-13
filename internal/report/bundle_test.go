package report

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// identifying builds a diagnosis full of values a report must not leak.
func identifying() *engine.Diagnosis {
	full := strings.Repeat("3f", 32)
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	return &engine.Diagnosis{
		Verdict: engine.VerdictCause, ID: "dg-20261113T100000Z-a1b2c3", SchemaVersion: 1,
		Summary: "worker can't reach api.corp.example:443: api.corp.example resolves to 203.0.113.7.",
		Question: evidence.Question{
			From: evidence.Source{Kind: evidence.SourceContainer, Ref: "container:shop-worker-1", ContainerID: full},
			To:   evidence.Target{Host: "api.corp.example", Port: 443, Proto: "tcp", Class: evidence.TargetName},
		},
		Findings: []rules.Finding{{RuleID: "WR020", Title: "x", Confidence: rules.High, Explanation: "203.0.113.7 and 2001:db8::7 and 10.0.0.5 time out.",
			Fix: "See /home/someone/.config/whyreach/config.toml", Supporting: []string{"ev-01"}, DocURL: "docs/rules/WR020.md"}},
		Facts:       []engine.Fact{{Text: "connect 203.0.113.7:443 from worker: timeout. Also 203.0.113.70.", Evidence: []string{"ev-02"}}},
		Gaps:        []engine.Gap{},
		NextChecks:  []engine.NextCheck{},
		SideEffects: []string{"ephemeral probe container wr-probe-1 (removed)"},
		Timing:      engine.Timing{StartedAt: at},
		Evidence: []evidence.Evidence{
			{ID: "ev-01", Kind: evidence.KindContainer, Context: evidence.ContextRef{Kind: evidence.ContextContainer, Container: full[:12], Name: "worker"},
				Status: evidence.StatusOK, ObservedAt: at, Data: evidence.Container{
					ID: full, Name: "shop-worker-1", Image: "registry.corp.example:5000/team/worker:1.2",
					Networks:   []evidence.NetAttachment{{Network: "shop_default", NetworkID: strings.Repeat("9c", 32), IPv4: netip.MustParseAddr("172.22.0.2")}},
					ExtraHosts: []string{"db.corp.example:198.51.100.4"},
				}},
			{ID: "ev-02", Kind: evidence.KindTCP, Context: evidence.ContextRef{Kind: evidence.ContextContainer, Container: full[:12], Name: "worker"},
				Subject: "api.corp.example:443", Status: evidence.StatusOK, ObservedAt: at, Data: evidence.TCPProbe{
					Target: "api.corp.example:443", Addr: netip.MustParseAddrPort("203.0.113.7:443"), Via: evidence.ViaDNS, Outcome: evidence.OutcomeTimeout}},
			{ID: "ev-03", Kind: evidence.KindDNS, Context: evidence.ContextRef{Kind: evidence.ContextContainer, Container: full[:12], Name: "worker"},
				Subject: "api.corp.example", Status: evidence.StatusOK, ObservedAt: at, Data: evidence.DNSProbe{
					Name: "api.corp.example", Answered: "api.corp.example", Server: "127.0.0.11:53", Upstream: []string{"host(192.0.2.53)"},
					Answers: []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")}}},
		},
	}
}

func TestSaveRedacts(t *testing.T) {
	d := identifying()
	dir := t.TempDir()
	saved, err := Save(d, SaveOptions{Dir: filepath.Join(dir, "reports"), Redact: true, Home: "/home/someone", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Redacted || saved.Replaced[ClassIP] == 0 || saved.Replaced[ClassHost] == 0 || saved.Replaced[ClassContainer] == 0 {
		t.Errorf("saved = %+v", saved)
	}
	st, err := os.Stat(saved.Path)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("bundle dir: %v %v", st, err)
	}
	var all strings.Builder
	for _, f := range saved.Files {
		b, err := os.ReadFile(filepath.Join(saved.Path, f))
		if err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(filepath.Join(saved.Path, f)); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, st.Mode().Perm())
		}
		all.Write(b)
	}
	text := all.String()
	if regexp.MustCompile(`203\.0\.113\.7([^0-9]|$)`).MatchString(text) {
		t.Error("the bundle leaks 203.0.113.7")
	}
	for _, leak := range []string{"2001:db8::7", "corp.example", "3f3f3f3f3f3f", "9c9c9c9c9c9c", "198.51.100.4", "192.0.2.53", "/home/someone"} {
		if strings.Contains(text, leak) {
			t.Errorf("the bundle leaks %q", leak)
		}
	}
	if strings.Contains(text, "203.0.113.70") {
		t.Error("an address only a fact mentions must be redacted too")
	}
	for _, kept := range []string{"172.22.0.2", "shop-worker-1", "10.0.0.5", "WR020", "~/.config/whyreach"} {
		if !strings.Contains(text, kept) {
			t.Errorf("the bundle lost %q", kept)
		}
	}
	// One value, one pseudonym, everywhere in the report.
	b, _ := os.ReadFile(filepath.Join(saved.Path, "diagnosis.json"))
	var dj map[string]any
	if err := json.Unmarshal(b, &dj); err != nil {
		t.Fatal(err)
	}
	if _, ok := dj["evidence"]; ok {
		t.Error("diagnosis.json must leave the evidence to evidence.jsonl")
	}
	summary := dj["summary"].(string)
	q := dj["question"].(map[string]any)["to"].(map[string]any)["host"].(string)
	if !strings.HasPrefix(q, "host-") || !strings.Contains(summary, q) {
		t.Errorf("host pseudonym %q not used consistently: %q", q, summary)
	}
	f, _ := os.Open(filepath.Join(saved.Path, "evidence.jsonl"))
	defer func() { _ = f.Close() }()
	n := 0
	for sc := bufio.NewScanner(f); sc.Scan(); n++ {
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("evidence line %d: %v", n, err)
		}
	}
	if n != 3 {
		t.Errorf("%d evidence lines", n)
	}

	again, err := Save(d, SaveOptions{Dir: filepath.Join(dir, "reports"), Redact: true, Version: "test"})
	if err != nil || again.Path != saved.Path || again.Replaced[ClassIP] != saved.Replaced[ClassIP] {
		t.Errorf("saving again must return the same bundle: %+v %v", again, err)
	}
	plain, err := Save(d, SaveOptions{Dir: filepath.Join(dir, "reports"), Redact: false, Version: "test"})
	if err != nil || plain.Path == saved.Path || plain.Redacted {
		t.Errorf("an unredacted bundle is separate: %+v %v", plain, err)
	}
	if _, err := Save(&engine.Diagnosis{ID: "../../etc"}, SaveOptions{Dir: dir}); err == nil {
		t.Error("a forged diagnosis ID must be refused")
	}
}

func TestRedactPrivate(t *testing.T) {
	r := NewRedactor(true, "")
	r.Learn(identifying())
	if got := r.Apply("172.22.0.2 and 127.0.0.1"); strings.Contains(got, "172.22.0.2") || !strings.Contains(got, "127.0.0.1") {
		t.Errorf("with RedactPrivate: %q", got)
	}
}

func TestRedactorLearnsEverywhere(t *testing.T) {
	d := identifying()
	c := d.Evidence[0].Data.(evidence.Container)
	c.Image = "10.9.8.7:5000/team/worker:1"
	c.Networks[0].Names = []string{"worker", "worker.svc.corp.example", "Bücher.Shop.example"}
	c.Links = []string{"/db.legacy.example:/shop-worker-1/db"}
	d.Evidence[0].Data = c
	d.Evidence = append(d.Evidence, evidence.Evidence{ID: "ev-04", Kind: evidence.KindTCP, Status: evidence.StatusError,
		Err: &evidence.Error{Message: "dial tcp 198.18.7.7:443: i/o timeout"}})
	d.Gaps = append(d.Gaps, engine.Gap{What: "x", Why: "failed", Detail: "upstream 2001:db8:1::53 refused"})
	r := NewRedactor(false, "")
	r.Learn(d)
	text := r.Apply("10.9.8.7 worker.svc.corp.example db.legacy.example 198.18.7.7 2001:db8:1::53 Bücher.Shop.example worker shop-worker-1")
	for _, leak := range []string{"corp.example", "legacy.example", "198.18.7.7", "2001:db8:1::53", "Shop.example"} {
		if strings.Contains(text, leak) {
			t.Errorf("not redacted: %q in %q", leak, text)
		}
	}
	if !strings.Contains(text, "10.9.8.7 ") || !strings.Contains(text, "worker shop-worker-1") {
		t.Errorf("private addresses and names without a dot stay: %q", text)
	}
	// Non-ASCII text that changes length when lowercased must neither
	// panic nor shift a replacement.
	tricky := "İİİ Ⱥ 198.18.7.7 İ"
	if got := r.Apply(tricky); !strings.HasPrefix(got, "İİİ Ⱥ ip-") || strings.Contains(got, "198.18.7.7") {
		t.Errorf("Apply(%q) = %q", tricky, got)
	}
}

// TestRedactorRawSpellings: Docker keeps extra_hosts as written, so a
// non-canonical IPv6 address must be replaced as spelled; a network's
// bridge, br-<short ID>, must not keep the ID that is pseudonymised
// elsewhere (M2 safety review, finding 3).
func TestRedactorRawSpellings(t *testing.T) {
	d := identifying()
	c := d.Evidence[0].Data.(evidence.Container)
	c.ExtraHosts = []string{"db.corp.example:2001:0db8:85a3:0000:0000:8a2e:0370:7334", "up.corp.example=2001:DB8:0:0::1"}
	d.Evidence[0].Data = c
	netID := strings.Repeat("9c", 32)
	d.Evidence = append(d.Evidence, evidence.Evidence{ID: "ev-04", Kind: evidence.KindHostAddrs, Status: evidence.StatusOK,
		Data: evidence.HostAddrs{Interfaces: []evidence.Interface{{Name: "br-" + netID[:12], Addrs: []netip.Prefix{netip.MustParsePrefix("172.22.0.1/16")}}}}})
	r := NewRedactor(false, "")
	r.Learn(d)
	text := r.Apply("2001:0db8:85a3:0000:0000:8a2e:0370:7334 2001:DB8:0:0::1 br-" + netID[:12] + " " + netID)
	for _, leak := range []string{"2001:0db8", "2001:DB8", netID[:12]} {
		if strings.Contains(text, leak) {
			t.Errorf("not redacted: %q in %q", leak, text)
		}
	}
	if !strings.Contains(text, "br-") {
		t.Errorf("the bridge keeps its br- prefix: %q", text)
	}
}

// TestReportMarkdownIsSanitized: report.md carries the summary and the
// evidence lines, which can hold label text.
func TestReportMarkdownIsSanitized(t *testing.T) {
	d := identifying()
	d.Summary = "worker\x1b[2J can't reach api\u202e\U000E0041"
	saved, err := Save(d, SaveOptions{Dir: t.TempDir(), Redact: true, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(saved.Path, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(b), "\x1b\u202e\U000E0041") {
		t.Errorf("report.md keeps control or format characters: %q", b)
	}
}

// TestReportMarkdownRedactsBeforeSanitizing: a name with an invisible
// character (extra_hosts keep what was written) is redacted in report.md
// too, though Sanitize changes how it is spelled.
func TestReportMarkdownRedactsBeforeSanitizing(t *testing.T) {
	d := identifying()
	name := "db\u200b.corp.example"
	c := d.Evidence[0].Data.(evidence.Container)
	c.ExtraHosts = []string{name + ":198.51.100.4"}
	d.Evidence[0].Data = c
	d.Facts = append(d.Facts, engine.Fact{Text: "worker's extra_hosts map " + name + " to 198.51.100.4", Evidence: []string{"ev-01"}})
	saved, err := Save(d, SaveOptions{Dir: t.TempDir(), Redact: true, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(saved.Path, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "corp.example") {
		t.Errorf("report.md leaks the name:\n%s", b)
	}
}

func TestReplaceWhole(t *testing.T) {
	n := 0
	count := func(k int) { n += k }
	tests := []struct{ in, tok, want string }{
		{"a 10.0.0.1:80 b", "10.0.0.1", "a X:80 b"},
		{"110.0.0.12 and 10.0.0.12", "10.0.0.1", "110.0.0.12 and 10.0.0.12"},
		{"ends with 10.0.0.1.", "10.0.0.1", "ends with X."},
		{"[2001:db8::7]:443", "2001:db8::7", "[X]:443"},
		{"2001:db8::7:5", "2001:db8::7", "2001:db8::7:5"},
		{"Api.Corp.Example and api.corp.example.org", "api.corp.example", "X and api.corp.example.org"},
	}
	for _, tt := range tests {
		if got := replaceWhole(tt.in, tt.tok, "X", count); got != tt.want {
			t.Errorf("replaceWhole(%q, %q) = %q, want %q", tt.in, tt.tok, got, tt.want)
		}
	}
}
