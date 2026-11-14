package policy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// fakeDocker: worker and api share shop_default; api listens on 0.0.0.0:8080.
type fakeDocker struct{}

var (
	workerID = strings.Repeat("b", 64)
	apiID    = strings.Repeat("a", 64)
)

func (fakeDocker) Negotiate(context.Context) (docker.Version, error) {
	return docker.Version{Version: "29.9.3", APIVersion: "1.56", Os: "linux", Arch: "amd64"}, nil
}
func (fakeDocker) Endpoint() string   { return "unix:///var/run/docker.sock" }
func (fakeDocker) APIVersion() string { return "1.56" }

func (fakeDocker) containers() []evidence.Container {
	mk := func(id, name, svc, ip string, pid int) evidence.Container {
		return evidence.Container{
			ID: id, Name: name, State: evidence.StateRunning, Pid: pid, NetworkMode: "shop_default",
			StartedAt: time.Now().Add(-time.Hour),
			Compose:   &evidence.ComposeRef{Project: "shop", Service: svc},
			Networks:  []evidence.NetAttachment{{Network: "shop_default", IPv4: netip.MustParseAddr(ip), Names: []string{name, svc}}},
		}
	}
	return []evidence.Container{mk(workerID, "shop-worker-1", "worker", "172.22.0.2", 10), mk(apiID, "shop-api-1", "api", "172.22.0.3", 20)}
}

func (f fakeDocker) ListContainers(_ context.Context, _ bool, labels ...string) ([]docker.Summary, error) {
	var out []docker.Summary
	for _, c := range f.containers() {
		s := docker.Summary{ID: c.ID, Names: []string{"/" + c.Name}, State: c.State, Labels: map[string]string{
			docker.LabelComposeProject: c.Compose.Project, docker.LabelComposeService: c.Compose.Service,
		}}
		match := true
		for _, l := range labels {
			k, v, _ := strings.Cut(l, "=")
			if s.Labels[k] != v {
				match = false
			}
		}
		if match {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f fakeDocker) InspectContainer(_ context.Context, ref string) (evidence.Container, error) {
	for _, c := range f.containers() {
		if c.ID == ref || c.Name == ref {
			return c, nil
		}
	}
	return evidence.Container{}, &docker.APIError{Status: 404, Message: "No such container"}
}

func (fakeDocker) ListNetworks(context.Context) ([]docker.Network, error) {
	return []docker.Network{{ID: "n1", Name: "shop_default", Driver: "bridge", Subnets: []netip.Prefix{netip.MustParsePrefix("172.22.0.0/16")}}}, nil
}

func (fakeDocker) InspectNetwork(context.Context, string) (docker.Network, error) {
	return docker.Network{}, &docker.APIError{Status: 404, Message: "no network"}
}

func (fakeDocker) Host() ([]evidence.Socket, error) { return nil, nil }

func (fakeDocker) Container(pid int, _ string) ([]evidence.Socket, error) {
	if pid == 20 {
		return []evidence.Socket{{Proto: "tcp", Local: netip.MustParseAddrPort("0.0.0.0:8080")}}, nil
	}
	return nil, nil
}

// recorder is an executor that records what it was asked to run and
// connects every TCP spec.
type recorder struct {
	mu    sync.Mutex
	runs  [][]probe.Spec
	lims  []probe.Limits
	where []evidence.ContextRef
}

func (r *recorder) Name() string { return "recorder" }

func (r *recorder) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	r.mu.Lock()
	r.runs = append(r.runs, specs)
	r.lims = append(r.lims, probe.LimitsFrom(ctx))
	r.where = append(r.where, where)
	r.mu.Unlock()
	var out []evidence.Evidence
	for _, s := range specs {
		switch s.Kind {
		case probe.SpecDNS:
			out = append(out, evidence.Evidence{Kind: evidence.KindDNS, Subject: s.Host, Status: evidence.StatusOK,
				Data: evidence.DNSProbe{Name: s.Host, Via: evidence.ViaDNS, Answers: []netip.Addr{netip.MustParseAddr("172.22.0.3")}}})
		case probe.SpecTCP:
			addr := netip.MustParseAddr("172.22.0.3")
			via := evidence.ViaDNS
			if a, err := netip.ParseAddr(s.Host); err == nil {
				addr, via = a, evidence.ViaLiteral
			}
			out = append(out, evidence.Evidence{Kind: evidence.KindTCP, Subject: s.Host, Status: evidence.StatusOK,
				Data: evidence.TCPProbe{Target: s.Host, Addr: netip.AddrPortFrom(addr, s.Port), Via: via, Outcome: evidence.OutcomeConnected}})
		}
	}
	return out, nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.runs)
}

type fixture struct {
	p     *Policy
	host  *recorder
	probe *recorder
	audit string
}

func newFixture(t *testing.T, s Settings, now func() time.Time) fixture {
	t.Helper()
	f := fixture{host: &recorder{}, probe: &recorder{}, audit: filepath.Join(t.TempDir(), "state", "audit.jsonl")}
	if s.RatePerMinute == 0 {
		s.RatePerMinute = 30
	}
	p, err := New(Deps{
		Settings: s, Docker: fakeDocker{}, Listeners: fakeDocker{}, Host: f.host,
		NewProbe: func() (executor.Executor, error) { return f.probe, nil },
		Audit:    NewAudit(f.audit), Client: ClientMCP, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.p = p
	return f
}

func entries(t *testing.T, path string) []Entry {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	var out []Entry
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("audit line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

func TestProbeContainersComeOnlyFromConfigOrConsent(t *testing.T) {
	f := newFixture(t, Settings{Docker: true}, nil)
	d, err := f.p.Diagnose(context.Background(), DiagnoseArgs{From: "container:shop-worker-1", To: "api:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if f.probe.count() != 0 {
		t.Fatal("tier 2b is off: no probe container may run")
	}
	if !NeedsProbeContainers(d.Evidence) {
		t.Error("the diagnosis must show what a probe container would add")
	}
	if f.p.ProbeContainers() {
		t.Error("tier 2b must start off")
	}

	f.p.RecordConsent(false, "decline")
	if f.p.ProbeContainers() {
		t.Error("a declined request must leave tier 2b off")
	}
	f.p.RecordConsent(true, "accept")
	if !f.p.ProbeContainers() {
		t.Fatal("an approval turns tier 2b on for the session")
	}
	d, err = f.p.Diagnose(context.Background(), DiagnoseArgs{From: "container:shop-worker-1", To: "api:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if f.probe.count() != 1 || d.Verdict != "no_problem_reproduced" {
		t.Errorf("with tier 2b: %d probe runs, verdict %s", f.probe.count(), d.Verdict)
	}

	es := entries(t, f.audit)
	var tools []string
	for _, e := range es {
		tools = append(tools, e.Tool+":"+e.Status)
	}
	want := "diagnose_connection:ok probe_containers_consent:declined probe_containers_consent:approved diagnose_connection:ok"
	if got := strings.Join(tools, " "); got != want {
		t.Errorf("audit = %s, want %s", got, want)
	}
	last := es[len(es)-1]
	if !last.ProbeContainers || last.ProbesSent == 0 || last.Client != ClientMCP || last.DiagnosisID == "" || last.Verdict == "" {
		t.Errorf("last entry = %+v", last)
	}
}

func TestDockerOffMeansNoProbeContainers(t *testing.T) {
	f := newFixture(t, Settings{Docker: false, ProbeContainers: true}, nil)
	if f.p.ProbeContainers() || f.p.CanUseProbeContainers() {
		t.Error("probe containers need Docker access")
	}
}

func TestAllowlist(t *testing.T) {
	f := newFixture(t, Settings{Docker: true, Allow: []string{"loopback", "docker"}}, nil)
	res, err := f.p.Probe(context.Background(), ProbeArgs{Kind: "tcp", Target: "192.168.1.50:5432"})
	if err != nil {
		t.Fatal(err)
	}
	if f.host.count() != 0 || len(res.Evidence) != 1 || res.Evidence[0].Status != evidence.StatusSkipped ||
		!strings.Contains(res.Evidence[0].Err.Message, "allowlist") {
		t.Errorf("an address outside the allowlist must not be sent: %+v", res.Evidence)
	}
	if _, err := f.p.Probe(context.Background(), ProbeArgs{Kind: "tcp", Target: "172.22.0.3:8080"}); err != nil {
		t.Fatal(err)
	}
	if f.host.count() != 1 {
		t.Fatal("an address on a Docker subnet must be sent")
	}
	// The probe gets the allowlist for every address a name resolves to.
	lim := f.host.lims[0]
	for addr, want := range map[string]bool{"127.0.0.1": true, "172.22.9.9": true, "8.8.8.8": false} {
		if _, ok := lim.Check(netip.MustParseAddr(addr)); ok != want {
			t.Errorf("dial-time limits: %s allowed = %v, want %v", addr, ok, want)
		}
	}
	// No allowlist: only the block list.
	open := newFixture(t, Settings{Docker: true}, nil)
	if _, err := open.p.Probe(context.Background(), ProbeArgs{Kind: "tcp", Target: "192.168.1.50:5432"}); err != nil {
		t.Fatal(err)
	}
	if open.host.count() != 1 || open.host.lims[0].Restricted {
		t.Error("without an allowlist the probe is sent, unrestricted")
	}
	if _, err := New(Deps{Settings: Settings{Allow: []string{"everywhere"}}}); err == nil {
		t.Error("an unknown allowlist entry must be refused")
	}
}

func TestRateLimit(t *testing.T) {
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	f := newFixture(t, Settings{Docker: true, RatePerMinute: 3}, clock)
	sent := func() int {
		res, err := f.p.Probe(context.Background(), ProbeArgs{Kind: "dns", Target: "api"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Evidence[0].Status == evidence.StatusSkipped {
			if !strings.Contains(res.Evidence[0].Err.Message, "rate limit") {
				t.Errorf("refusal: %+v", res.Evidence[0].Err)
			}
			return 0
		}
		return 1
	}
	got := 0
	for range 5 {
		got += sent()
	}
	if got != 3 {
		t.Errorf("sent %d of 5 at once, want the burst of 3", got)
	}
	now = now.Add(20 * time.Second) // one token per 20 s
	if sent() != 1 || sent() != 0 {
		t.Error("the bucket refills at rate_per_minute")
	}
	// Listener reads are local and free.
	for range 5 {
		if _, err := f.p.Probe(context.Background(), ProbeArgs{Kind: "listeners"}); err != nil {
			t.Fatal(err)
		}
	}
	es := entries(t, f.audit)
	denied := 0
	for _, e := range es {
		denied += e.ProbesDenied
	}
	if denied != 3 {
		t.Errorf("audit counts %d refused probes, want 3", denied)
	}
}

func TestArgumentsAreValidated(t *testing.T) {
	f := newFixture(t, Settings{Docker: true}, nil)
	ctx := context.Background()
	tests := []struct {
		name string
		call func() error
		code string
	}{
		{"bad from", func() error { _, err := f.p.Diagnose(ctx, DiagnoseArgs{From: "pod:x", To: "api:80"}); return err }, evidence.CodeInvalidArgument},
		{"CIDR", func() error { _, err := f.p.Diagnose(ctx, DiagnoseArgs{To: "10.0.0.0/8:80"}); return err }, evidence.CodeInvalidArgument},
		{"metadata", func() error { _, err := f.p.Diagnose(ctx, DiagnoseArgs{To: "169.254.169.254:80"}); return err }, evidence.CodePolicyDenied},
		{"expect", func() error {
			_, err := f.p.Diagnose(ctx, DiagnoseArgs{To: "api:80", Expect: "refuse"})
			return err
		}, evidence.CodeInvalidArgument},
		{"unknown container", func() error {
			_, err := f.p.Diagnose(ctx, DiagnoseArgs{From: "container:nope", To: "api:80"})
			return err
		}, evidence.CodeNotFound},
		{"probe kind", func() error { _, err := f.p.Probe(ctx, ProbeArgs{Kind: "icmp", Target: "api"}); return err }, evidence.CodeInvalidArgument},
		{"dns with a port", func() error { _, err := f.p.Probe(ctx, ProbeArgs{Kind: "dns", Target: "api:53"}); return err }, evidence.CodeInvalidArgument},
		{"tcp without a port", func() error { _, err := f.p.Probe(ctx, ProbeArgs{Kind: "tcp", Target: "api"}); return err }, evidence.CodeInvalidArgument},
		{"listeners with a target", func() error {
			_, err := f.p.Probe(ctx, ProbeArgs{Kind: "listeners", Target: "api"})
			return err
		}, evidence.CodeInvalidArgument},
		{"scope", func() error { _, err := f.p.Inspect(ctx, "volume:x"); return err }, evidence.CodeInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if got := Code(err); got != tt.code {
				t.Errorf("Code(%v) = %q, want %q", err, got, tt.code)
			}
		})
	}
	es := entries(t, f.audit)
	if len(es) != len(tests) {
		t.Fatalf("%d audit entries for %d calls", len(es), len(tests))
	}
	for _, e := range es {
		if e.Status == "ok" || e.Error == "" {
			t.Errorf("a refused call is audited with its error: %+v", e)
		}
	}
}

func TestInspectHostShowsPermissions(t *testing.T) {
	f := newFixture(t, Settings{Docker: true, ProbeContainers: true, Allow: []string{"rfc1918"}}, nil)
	in, err := f.p.Inspect(context.Background(), "host")
	if err != nil {
		t.Fatal(err)
	}
	if in.Host == nil || in.Host.Permissions == nil || in.Host.Permissions.ProbeContainers != "on (config)" || !in.Host.Permissions.Docker {
		t.Errorf("permissions = %+v", in.Host)
	}
}

func TestAuditFile(t *testing.T) {
	dir := t.TempDir()
	a := NewAudit(filepath.Join(dir, "state", "audit.jsonl"))
	a.maxBytes = 400
	evil := "api\x1b[2J\u202e" + strings.Repeat("x", 400)
	for range 3 {
		if err := a.Write(Entry{Tool: ToolProbe, Args: map[string]string{"target": evil, "from": ""}, Status: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	st, err := os.Stat(a.Path())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("audit log mode %v, want 0600", st.Mode().Perm())
	}
	if dst, _ := os.Stat(filepath.Dir(a.Path())); dst.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode %v, want 0700", dst.Mode().Perm())
	}
	if _, err := os.Stat(a.Path() + ".1"); err != nil {
		t.Errorf("the log should have rotated: %v", err)
	}
	b, _ := os.ReadFile(a.Path())
	if strings.ContainsAny(string(b), "\x1b\u202e") {
		t.Errorf("control characters reached the log: %q", b)
	}
	var e Entry
	if err := json.Unmarshal(b[:strings.IndexByte(string(b), '\n')], &e); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Args["from"]; ok || len([]rune(e.Args["target"])) > maxArg+1 {
		t.Errorf("args = %q: empty args dropped, long ones cut", e.Args)
	}
}

func TestCode(t *testing.T) {
	if Code(nil) != "" || Code(errors.New("boom")) != evidence.CodeInternal || Code(context.DeadlineExceeded) != evidence.CodeTimeout {
		t.Error("Code")
	}
	if !IsUsage(&Error{Code: evidence.CodePolicyDenied}) || IsUsage(&Error{Code: evidence.CodeInternal}) {
		t.Error("IsUsage")
	}
}

// TestAuditMasksCredentials: an agent may pass a connection string as it
// is; the refused call's audit line keeps neither its password nor its
// query (M2 safety review, finding 1).
func TestAuditMasksCredentials(t *testing.T) {
	f := newFixture(t, Settings{Docker: true}, nil)
	for _, to := range []string{"postgres://app:s3cr3t@db:5432/app?sslpassword=hunter2", "tcp://admin:hunter2@db:5432", "admin:hunter2@db:5432"} {
		_, err := f.p.Diagnose(context.Background(), DiagnoseArgs{From: "service:worker@shop", To: to})
		if err == nil {
			t.Fatalf("%s was accepted", to)
		}
		if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the error repeats the password: %v", err)
		}
	}
	b, err := os.ReadFile(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "s3cr3t") || strings.Contains(string(b), "hunter2") {
		t.Errorf("the audit log keeps a password:\n%s", b)
	}
	if !strings.Contains(string(b), `"from":"service:worker@shop"`) {
		t.Errorf("a Compose project's @ was masked:\n%s", b)
	}
}

// TestProbeContainerListenerReadsAreRateLimited: on Docker Desktop listener
// reads run in probe containers, so each one costs a token; with tier 2b
// off, withheld probes count as denied in the audit (M2 safety review,
// findings 4 and 6).
func TestProbeContainerListenerReadsAreRateLimited(t *testing.T) {
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, Settings{Docker: true, ProbeContainers: true, RatePerMinute: 3}, func() time.Time { return now })
	g := &guard{p: f.p, name: evidence.ExecutorProbeContainer, tier2b: true, inner: func() (executor.Executor, error) { return f.probe, nil }}
	specs := make([]probe.Spec, 5)
	for i := range specs {
		specs[i] = probe.Spec{Kind: probe.SpecListeners}
	}
	ctx, c := withCounts(context.Background())
	if _, err := g.Run(ctx, evidence.ContextRef{Kind: evidence.ContextContainer, Container: "aaaaaaaaaaaa"}, specs); err != nil {
		t.Fatal(err)
	}
	var e Entry
	c.fill(&e)
	if e.ProbesSent != 3 || e.ProbesDenied != 2 {
		t.Errorf("sent %d, denied %d of 5 listener reads in probe containers; want 3 and 2", e.ProbesSent, e.ProbesDenied)
	}

	off := newFixture(t, Settings{Docker: true}, nil)
	g = &guard{p: off.p, name: evidence.ExecutorProbeContainer, tier2b: true, inner: func() (executor.Executor, error) { return off.probe, nil }}
	ctx, c = withCounts(context.Background())
	if _, err := g.Run(ctx, evidence.ContextRef{Kind: evidence.ContextContainer, Container: "aaaaaaaaaaaa"}, specs[:2]); err != nil {
		t.Fatal(err)
	}
	e = Entry{}
	c.fill(&e)
	if e.ProbesDenied != 2 || off.probe.count() != 0 {
		t.Errorf("tier 2b off: denied %d, runs %d; want 2 and 0", e.ProbesDenied, off.probe.count())
	}
}

// TestOutsideNameLimits: for MCP clients the guard restricts names and
// lists the outside ones allowed ([probe] names, approvals); the CLI looks
// up any name (INITIAL.md §10 Q11). The approval takes the exact name.
func TestOutsideNameLimits(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, Settings{Docker: true, Names: []string{"corp.example"}}, nil)
	if _, err := f.p.Probe(ctx, ProbeArgs{Kind: "dns", Target: "Api.Corp.Example."}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Probe(ctx, ProbeArgs{Kind: "tcp", Target: "data.attacker.example:443"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Probe(ctx, ProbeArgs{Kind: "dns", Target: "api"}); err != nil {
		t.Fatal(err)
	}
	want := []probe.Limits{
		{NamesRestricted: true, Names: []string{"api.corp.example"}},
		{NamesRestricted: true},
		{NamesRestricted: true},
	}
	if diff := cmp.Diff(want, f.host.lims, cmpopts.IgnoreUnexported(probe.Limits{})); diff != "" {
		t.Errorf("limits (-want +got):\n%s", diff)
	}

	f.p.RecordNameConsent("Data.Attacker.Example.", true, "accept")
	if !f.p.NameAllowed("data.attacker.example") || f.p.NameAllowed("other.attacker.example") || f.p.NameAllowed("attacker.example") {
		t.Error("an approval covers exactly the name approved")
	}
	if _, err := f.p.Probe(ctx, ProbeArgs{Kind: "tcp", Target: "data.attacker.example:443"}); err != nil {
		t.Fatal(err)
	}
	if got := f.host.lims[len(f.host.lims)-1]; !got.NamesRestricted || !slices.Equal(got.Names, []string{"data.attacker.example"}) {
		t.Errorf("after approval: %+v", got)
	}
	e := entries(t, f.audit)
	if last := e[len(e)-2]; last.Tool != ToolNameConsent || last.Status != "approved" || last.Args["name"] != "data.attacker.example" {
		t.Errorf("consent audit = %+v", last)
	}

	cli, err := New(Deps{Settings: Settings{Docker: true}, Docker: fakeDocker{}, Listeners: fakeDocker{}, Host: f.host, Client: ClientCLI})
	if err != nil {
		t.Fatal(err)
	}
	if cli.NamesNeedApproval() {
		t.Error("the CLI's user types the names: nothing to approve")
	}
	if _, err := cli.Probe(ctx, ProbeArgs{Kind: "dns", Target: "data.attacker.example"}); err != nil {
		t.Fatal(err)
	}
	if got := f.host.lims[len(f.host.lims)-1]; got.NamesRestricted {
		t.Errorf("CLI limits = %+v", got)
	}
}

func TestNeedsNameApproval(t *testing.T) {
	held := func(kind evidence.Kind, subject string) evidence.Evidence {
		return evidence.Evidence{Kind: kind, Subject: subject, Status: evidence.StatusSkipped,
			Err: &evidence.Error{Code: evidence.CodePolicyDenied, Message: probe.NameNotApproved}}
	}
	evs := []evidence.Evidence{
		held(evidence.KindDNS, "Zeta.Example."), held(evidence.KindTCP, "zeta.example:443"),
		held(evidence.KindDNS, "alpha.example"), held(evidence.KindDNS, "zeta.example"),
		{Kind: evidence.KindDNS, Subject: "other.example", Status: evidence.StatusSkipped,
			Err: &evidence.Error{Code: evidence.CodePolicyDenied, Message: "rate limit"}},
	}
	if got, want := NeedsNameApproval(evs), []string{"alpha.example", "zeta.example"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// holder answers like the probe for a name the limits hold back: the lookup
// and, for a connect, a skipped connect with the same reason.
type holder struct{ recorder }

func (h *holder) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	lim := probe.LimitsFrom(ctx)
	var out []evidence.Evidence
	for _, s := range specs {
		if _, ok := lim.CheckName(s.Host); ok && s.Host != "nsblocked" && s.Host != "nsfailover" {
			evs, _ := h.recorder.Run(ctx, where, []probe.Spec{s})
			out = append(out, evs...)
			continue
		}
		why := &evidence.Error{Code: evidence.CodePolicyDenied, Message: probe.NameNotApproved}
		var data any
		switch s.Host {
		case "nsblocked": // its first nameserver is on the block list
			why.Message = "not looked up: the first nameserver in /etc/resolv.conf, 169.254.169.254, which the app asks first, is on the probe block list"
		case "nsfailover": // the first failed, and the next is on the block list
			why.Message = "not looked up fully: the lookup of nsfailover from 10.8.0.1:53 failed (TIMEOUT), and the app would then ask 169.254.169.254, which is on the probe block list"
			data = evidence.DNSProbe{Name: s.Host, Server: "10.8.0.1:53", Attempts: []evidence.DNSAttempt{{Type: "A", Rcode: evidence.RcodeTimeout}}}
		}
		out = append(out, evidence.Evidence{Kind: evidence.KindDNS, Subject: s.Host, Status: evidence.StatusSkipped, Err: why, Data: data})
		if s.Kind == probe.SpecTCP {
			out = append(out, evidence.Evidence{Kind: evidence.KindTCP, Subject: s.Host + ":443", Status: evidence.StatusSkipped, Err: why})
		}
	}
	return out, nil
}

// Host checks that can't run (whyreach's image without --network host)
// send nothing: no rate tokens, and the audit counts nothing.
func TestUnsupportedHostSendsNothing(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	p, err := New(Deps{
		Settings: Settings{Docker: true, RatePerMinute: 1}, Docker: fakeDocker{}, Listeners: fakeDocker{}, Audit: NewAudit(audit), Client: ClientMCP,
		Host: executor.Unsupported{Executor: evidence.ExecutorHost, Reason: executor.HostHidden},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, a := range []ProbeArgs{{Kind: "tcp", Target: "localhost:5432"}, {Kind: "dns", Target: "example.com"}, {Kind: "tcp", Target: "10.0.0.5:80"}} {
		r, err := p.Probe(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range r.Evidence {
			if e.Status != evidence.StatusUnsupported {
				t.Errorf("%v: %s %s (%+v), want unsupported", a, e.Kind, e.Status, e.Err)
			}
		}
	}
	es := entries(t, audit)
	if len(es) != 3 {
		t.Fatalf("%d audit entries, want 3", len(es))
	}
	for _, e := range es {
		if e.ProbesSent != 0 || e.ProbesDenied != 0 {
			t.Errorf("audit counts sent %d, denied %d for checks that couldn't run", e.ProbesSent, e.ProbesDenied)
		}
	}
}

// A check whose name was held back sent nothing: the audit counts it as
// denied, once per check, though a connect reports its lookup too. One
// refused after its queries went out (the next nameserver blocked) was sent.
func TestHeldBackNamesCountAsDenied(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	h := &holder{}
	p, err := New(Deps{Settings: Settings{Docker: true}, Docker: fakeDocker{}, Listeners: fakeDocker{}, Host: h, Audit: NewAudit(audit), Client: ClientMCP})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, a := range []ProbeArgs{{Kind: "tcp", Target: "example.com:443"}, {Kind: "dns", Target: "example.com"}, {Kind: "dns", Target: "api"}, {Kind: "tcp", Target: "nsblocked:5432"}, {Kind: "dns", Target: "nsfailover"}} {
		if _, err := p.Probe(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	type count struct{ sent, denied int }
	var got []count
	for _, e := range entries(t, audit) {
		got = append(got, count{e.ProbesSent, e.ProbesDenied})
	}
	if want := []count{{0, 1}, {0, 1}, {1, 0}, {0, 1}, {1, 0}}; !slices.Equal(got, want) {
		t.Errorf("sent/denied per call = %v, want %v", got, want)
	}
}

// TestDesktopListenersNeedProbeContainers: on Docker Desktop a container's
// listening sockets can be read only inside a probe container, so a record
// that says so makes the MCP server ask for probe containers, like a probe
// that needed one.
func TestDesktopListenersNeedProbeContainers(t *testing.T) {
	elsewhere := evidence.Evidence{Kind: evidence.KindListeners, Status: evidence.StatusUnsupported,
		Err: &evidence.Error{Code: evidence.CodeUnsupported, Message: executor.PIDsElsewhere}}
	if !NeedsProbeContainers([]evidence.Evidence{elsewhere}) {
		t.Error("a listeners record that only a probe container can make must ask for probe containers")
	}
	hidden := evidence.Evidence{Kind: evidence.KindListeners, Status: evidence.StatusUnsupported,
		Err: &evidence.Error{Code: evidence.CodeUnsupported, Message: executor.PIDsHidden}}
	windows := evidence.Evidence{Kind: evidence.KindListeners, Status: evidence.StatusUnsupported,
		Err: &evidence.Error{Code: evidence.CodeUnsupported, Message: executor.HostNotHere}}
	if NeedsProbeContainers([]evidence.Evidence{hidden, windows}) {
		t.Error("probe containers help neither whyreach's image without --pid host nor the Windows host")
	}
}
