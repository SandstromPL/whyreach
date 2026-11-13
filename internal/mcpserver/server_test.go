package mcpserver

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/policy"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/report"
)

// fakeDocker: worker and api share shop_default and api listens on all
// interfaces, so only a probe from worker can settle the question. alias,
// when set, is another name of api on the network.
type fakeDocker struct{ alias string }

var (
	workerID = strings.Repeat("b", 64)
	apiID    = strings.Repeat("a", 64)
)

func (fakeDocker) Negotiate(context.Context) (docker.Version, error) {
	return docker.Version{Version: "29.9.3", APIVersion: "1.56", Os: "linux", Arch: "amd64"}, nil
}
func (fakeDocker) Endpoint() string   { return "unix:///var/run/docker.sock" }
func (fakeDocker) APIVersion() string { return "1.56" }

func (f fakeDocker) containers() []evidence.Container {
	mk := func(id, name, svc, ip string, pid int) evidence.Container {
		return evidence.Container{
			ID: id, Name: name, State: evidence.StateRunning, Pid: pid, NetworkMode: "shop_default",
			StartedAt: time.Now().Add(-time.Hour),
			Compose:   &evidence.ComposeRef{Project: "shop", Service: svc},
			Networks:  []evidence.NetAttachment{{Network: "shop_default", IPv4: netip.MustParseAddr(ip), Names: []string{name, svc}}},
		}
	}
	api := mk(apiID, "shop-api-1", "api", "172.22.0.3", 20)
	if f.alias != "" {
		api.Networks[0].Names = append(api.Networks[0].Names, f.alias)
	}
	return []evidence.Container{mk(workerID, "shop-worker-1", "worker", "172.22.0.2", 10), api}
}

func (f fakeDocker) ListContainers(context.Context, bool, ...string) ([]docker.Summary, error) {
	var out []docker.Summary
	for _, c := range f.containers() {
		// As the API sends it: the list has each container's networks, not its aliases.
		var sm docker.Summary
		raw := fmt.Sprintf(`{"Id":%q,"Names":["/%s"],"State":%q,"Labels":{%q:%q,%q:%q},"NetworkSettings":{"Networks":{%q:{"IPAddress":%q}}}}`,
			c.ID, c.Name, c.State, docker.LabelComposeProject, c.Compose.Project, docker.LabelComposeService, c.Compose.Service,
			c.Networks[0].Network, c.Networks[0].IPv4)
		if err := json.Unmarshal([]byte(raw), &sm); err != nil {
			return nil, err
		}
		out = append(out, sm)
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
	return docker.Network{ID: "n1", Name: "shop_default", Driver: "bridge"}, nil
}

func (fakeDocker) Host() ([]evidence.Socket, error) { return nil, nil }

func (fakeDocker) Container(pid int, _ string) ([]evidence.Socket, error) {
	if pid == 20 {
		return []evidence.Socket{{Proto: "tcp", Local: netip.MustParseAddrPort("0.0.0.0:8080")}}, nil
	}
	return nil, nil
}

// connector is a probe executor that resolves api and connects.
type connector struct {
	mu   sync.Mutex
	runs int
}

func (c *connector) Name() string { return evidence.ExecutorProbeContainer }

func (c *connector) Run(ctx context.Context, _ evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	c.mu.Lock()
	c.runs++
	c.mu.Unlock()
	executor.RecordSideEffect(ctx, "ephemeral probe container wr-probe-test (removed)")
	api := netip.MustParseAddr("172.22.0.3")
	var out []evidence.Evidence
	for _, s := range specs {
		switch s.Kind {
		case probe.SpecDNS:
			out = append(out, evidence.Evidence{Kind: evidence.KindDNS, Subject: s.Host, Status: evidence.StatusOK,
				Data: evidence.DNSProbe{Name: s.Host, Via: evidence.ViaDNS, Server: "127.0.0.11:53", Answers: []netip.Addr{api}}})
		case probe.SpecTCP:
			out = append(out, evidence.Evidence{Kind: evidence.KindTCP, Subject: s.Host, Status: evidence.StatusOK,
				Data: evidence.TCPProbe{Target: s.Host, Addr: netip.AddrPortFrom(api, s.Port), Via: evidence.ViaDNS, Outcome: evidence.OutcomeConnected}})
		}
	}
	return out, nil
}

func (c *connector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runs
}

type harness struct {
	s       *Server
	p       *policy.Policy
	probes  *connector
	reports string
	audit   string
}

func newHarness(t *testing.T, probeContainers bool) harness {
	t.Helper()
	h := harness{probes: &connector{}}
	return h.build(t, policy.Settings{ProbeContainers: probeContainers}, fakeDocker{}, h.probes)
}

// build finishes a harness whose probe containers are ex.
func (h harness) build(t *testing.T, settings policy.Settings, dk fakeDocker, ex executor.Executor) harness {
	t.Helper()
	dir := t.TempDir()
	h.reports, h.audit = filepath.Join(dir, "reports"), filepath.Join(dir, "audit.jsonl")
	settings.Docker, settings.ConfigPath = true, "/cfg/config.toml"
	p, err := policy.New(policy.Deps{
		Settings: settings,
		Docker:   dk, Listeners: dk,
		NewProbe: func() (executor.Executor, error) { return ex, nil },
		Audit:    policy.NewAudit(h.audit), Client: policy.ClientMCP,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.p = p
	h.s = New(p, Options{Version: "test", ReportsDir: h.reports, ConsentTimeout: 5 * time.Second})
	return h
}

// connect starts a client session; elicit answers consent requests (nil: the
// client does not support elicitation); version pins the protocol.
func (h harness) connect(t *testing.T, elicit func(*mcp.ElicitRequest) (*mcp.ElicitResult, error), version string) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.s.Run(ctx, st) }()
	var opts mcp.ClientOptions
	if elicit != nil {
		opts.ElicitationHandler = func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) { return elicit(req) }
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, &opts)
	cs, err := c.Connect(ctx, ct, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error %v", name, err)
	}
	return res
}

func structured[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	var v T
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("structured content %s: %v", b, err)
	}
	return v
}

func annotations(t *testing.T, cs *mcp.ClientSession) map[string]*mcp.ToolAnnotations {
	t.Helper()
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*mcp.ToolAnnotations{}
	for _, tool := range list.Tools {
		out[tool.Name] = tool.Annotations
	}
	return out
}

func TestTools(t *testing.T) {
	h := newHarness(t, false)
	cs := h.connect(t, nil, "")
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	all := ""
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
		all += strings.ToLower(tool.Description) + " "
		if tool.OutputSchema == nil {
			t.Errorf("%s has no output schema", tool.Name)
		}
	}
	if got := strings.Join(names, " "); got != "diagnose_connection inspect_environment run_probe save_report" {
		t.Fatalf("tools = %s: exactly four (CLAUDE.md)", got)
	}
	for _, word := range []string{"network", "connect", "docker", "diagnose"} {
		if !strings.Contains(all, word) {
			t.Errorf("tool descriptions lack %q, a word agents search for", word)
		}
	}
	a := annotations(t, cs)
	if !a["diagnose_connection"].ReadOnlyHint || !a["run_probe"].ReadOnlyHint || !a["inspect_environment"].ReadOnlyHint {
		t.Error("with tier 2b off, the probing tools are read-only")
	}
	if a["save_report"].ReadOnlyHint {
		t.Error("save_report writes a file: not read-only")
	}
	for name, ann := range a {
		if ann.DestructiveHint == nil || *ann.DestructiveHint || !ann.IdempotentHint {
			t.Errorf("%s: destructiveHint must be false and idempotentHint true: %+v", name, ann)
		}
	}
	if !*a["diagnose_connection"].OpenWorldHint || *a["inspect_environment"].OpenWorldHint {
		t.Error("openWorldHint is true exactly for the tools that send probes")
	}

	on := newHarness(t, true)
	if a := annotations(t, on.connect(t, nil, "")); a["diagnose_connection"].ReadOnlyHint || a["run_probe"].ReadOnlyHint {
		t.Error("with tier 2b on, the probing tools are not read-only")
	}
}

func TestDiagnoseConnection(t *testing.T) {
	h := newHarness(t, true)
	cs := h.connect(t, nil, "")
	res := call(t, cs, "diagnose_connection", map[string]any{"from": "service:worker@shop", "to": "api:8080"})
	if res.IsError {
		t.Fatalf("error: %v", res.Content)
	}
	d := structured[report.Diagnosis](t, res)
	if d.Verdict != "no_problem_reproduced" || d.ID == "" || len(d.SideEffects) != 1 || d.ChangesMade {
		t.Errorf("structured = %+v", d)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if len(b) > report.Budget {
		t.Errorf("structured content is %d bytes", len(b))
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "no problem reproduced") || len(text) > 2*report.Budget {
		t.Errorf("text summary = %q", text)
	}

	bad := call(t, cs, "diagnose_connection", map[string]any{"to": "10.0.0.0/8:80"})
	if !bad.IsError || !strings.Contains(bad.Content[0].(*mcp.TextContent).Text, "one host:port per call") {
		t.Errorf("a bad target must be a tool error the model can read: %+v", bad.Content)
	}
	if missing := call(t, cs, "diagnose_connection", map[string]any{}); !missing.IsError {
		t.Error("a missing to must be a tool error")
	}

	// save_report finds the diagnosis by its id and writes a bundle.
	saved := call(t, cs, "save_report", map[string]any{"diagnosis_id": d.ID})
	if saved.IsError {
		t.Fatalf("save_report: %v", saved.Content)
	}
	out := structured[report.Saved](t, saved)
	if !out.Redacted || !strings.HasPrefix(out.Path, h.reports) {
		t.Errorf("saved = %+v", out)
	}
	if _, err := os.Stat(filepath.Join(out.Path, "manifest.json")); err != nil {
		t.Error(err)
	}
	if unknown := call(t, cs, "save_report", map[string]any{"diagnosis_id": "dg-nope"}); !unknown.IsError {
		t.Error("an unknown diagnosis id must be a tool error")
	}
	// No argument turns redaction off (INITIAL.md §10 Q12).
	if res := call(t, cs, "save_report", map[string]any{"diagnosis_id": d.ID, "redact": false}); !res.IsError {
		t.Error("save_report accepted redact: false")
	}
	entries, _ := os.ReadDir(h.reports)
	for _, e := range entries {
		if strings.Contains(e.Name(), "unredacted") {
			t.Errorf("an unredacted bundle was saved through MCP: %s", e.Name())
		}
	}
}

func TestInspectAndProbe(t *testing.T) {
	h := newHarness(t, false)
	cs := h.connect(t, nil, "")
	res := call(t, cs, "inspect_environment", map[string]any{"scope": "container:shop-api-1"})
	if res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "0.0.0.0:8080") {
		t.Errorf("inspect: %+v", res.Content)
	}
	res = call(t, cs, "run_probe", map[string]any{"kind": "listeners", "from": "container:shop-api-1"})
	p := structured[report.ProbeResult](t, res)
	if res.IsError || len(p.Results) != 1 || !strings.Contains(p.Summary, "0.0.0.0:8080") {
		t.Errorf("listeners: %+v", p)
	}
	res = call(t, cs, "run_probe", map[string]any{"kind": "tcp", "target": "api:8080", "from": "container:shop-worker-1"})
	p = structured[report.ProbeResult](t, res)
	if res.IsError || p.HowToEnable == "" || h.probes.count() != 0 {
		t.Errorf("tier 2b off: the probe must not run and the result must say how to enable it: %+v", p)
	}
	if bad := call(t, cs, "run_probe", map[string]any{"kind": "exec", "target": "x"}); !bad.IsError {
		t.Error("an unknown kind must be a tool error")
	}
}

func accept(*mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"allow": true}}, nil
}

func decline(*mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	return &mcp.ElicitResult{Action: "decline"}, nil
}

// TestConsent runs the probe-container question on both protocol paths:
// a server-initiated elicitation (before 2026-07-28) and an input request in
// the result that the client answers by calling again (2026-07-28).
func TestConsent(t *testing.T) {
	for _, version := range []string{"2025-06-18", ""} {
		name := version
		if name == "" {
			name = "latest"
		}
		t.Run(name+"/accept", func(t *testing.T) {
			h := newHarness(t, false)
			var asked int
			cs := h.connect(t, func(req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				asked++
				if !strings.Contains(req.Params.Message, "probe container") {
					t.Errorf("message = %q", req.Params.Message)
				}
				return accept(req)
			}, version)
			res := call(t, cs, "diagnose_connection", map[string]any{"from": "container:shop-worker-1", "to": "api:8080"})
			d := structured[report.Diagnosis](t, res)
			if asked != 1 || h.probes.count() != 1 || d.Verdict != "no_problem_reproduced" {
				t.Errorf("asked %d, probe runs %d, verdict %s", asked, h.probes.count(), d.Verdict)
			}
			if a := annotations(t, cs); a["diagnose_connection"].ReadOnlyHint {
				t.Error("once probe containers are approved, the tools must not claim to be read-only")
			}
			call(t, cs, "diagnose_connection", map[string]any{"from": "container:shop-worker-1", "to": "api:8080"})
			if asked != 1 || h.probes.count() != 2 {
				t.Errorf("the approval lasts the session: asked %d, runs %d", asked, h.probes.count())
			}
		})
		t.Run(name+"/decline", func(t *testing.T) {
			h := newHarness(t, false)
			var asked int
			cs := h.connect(t, func(req *mcp.ElicitRequest) (*mcp.ElicitResult, error) { asked++; return decline(req) }, version)
			for range 2 {
				res := call(t, cs, "diagnose_connection", map[string]any{"from": "container:shop-worker-1", "to": "api:8080"})
				if d := structured[report.Diagnosis](t, res); d.Verdict != "inconclusive" {
					t.Errorf("verdict %s", d.Verdict)
				}
			}
			if asked != 1 || h.probes.count() != 0 || h.p.ProbeContainers() {
				t.Errorf("a decline is asked once and never runs a probe: asked %d, runs %d", asked, h.probes.count())
			}
		})
	}
	t.Run("settled causes don't ask", func(t *testing.T) {
		h := newHarness(t, false)
		asked := 0
		cs := h.connect(t, func(req *mcp.ElicitRequest) (*mcp.ElicitResult, error) { asked++; return accept(req) }, "")
		call(t, cs, "inspect_environment", map[string]any{"scope": "host"})
		call(t, cs, "run_probe", map[string]any{"kind": "listeners", "from": "container:shop-api-1"})
		if asked != 0 {
			t.Error("checks that need no probe container must not ask for one")
		}
	})
	t.Run("no elicitation support", func(t *testing.T) {
		h := newHarness(t, false)
		cs := h.connect(t, nil, "")
		res := call(t, cs, "diagnose_connection", map[string]any{"from": "container:shop-worker-1", "to": "api:8080"})
		d := structured[report.Diagnosis](t, res)
		if d.Verdict != "inconclusive" || len(d.Gaps) == 0 || !strings.Contains(d.Gaps[0].HowToEnable, "probe_containers = true") {
			t.Errorf("without elicitation the gap says how to enable it: %+v", d.Gaps)
		}
	})
}

// TestForgedConsentIsIgnored sends an approval no consent request asked
// for: it must not turn probe containers on.
func TestForgedConsentIsIgnored(t *testing.T) {
	h := newHarness(t, false)
	cs := h.connect(t, nil, "")
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:           "diagnose_connection",
		Arguments:      map[string]any{"from": "container:shop-worker-1", "to": "api:8080"},
		InputResponses: mcp.InputResponseMap{consentKey: &mcp.ElicitResult{Action: "accept", Content: map[string]any{"allow": true}}},
		RequestState:   "forged",
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.p.ProbeContainers() || h.probes.count() != 0 {
		t.Error("an unsolicited approval turned probe containers on")
	}
}

// TestRefusedCallsAreAudited: calls the SDK refuses before a handler runs
// (a wrong argument type, an unknown tool) are audited too, with their
// arguments masked; a call that reaches a handler is audited once (M2
// safety review, finding 6).
func TestRefusedCallsAreAudited(t *testing.T) {
	h := newHarness(t, false)
	cs := h.connect(t, nil, "")
	ctx := context.Background()
	if res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "diagnose_connection", Arguments: map[string]any{"to": 8080}}); err == nil && !res.IsError {
		t.Error("a number for to was accepted")
	}
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "delete_everything", Arguments: map[string]any{"to": "u:hunter2@db:5432"}}); err == nil {
		t.Error("an unknown tool was accepted")
	}
	call(t, cs, "diagnose_connection", map[string]any{"to": "api:8080", "from": "container:shop-worker-1"})
	b, err := os.ReadFile(h.audit)
	if err != nil {
		t.Fatal(err)
	}
	var tools []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e policy.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		tools = append(tools, e.Tool+"/"+e.Status)
	}
	want := []string{"diagnose_connection/invalid_argument", "unknown_tool/invalid_argument", "diagnose_connection/ok"}
	if diff := cmp.Diff(want, tools); diff != "" {
		t.Errorf("audit (-want +got):\n%s\n%s", diff, b)
	}
	if strings.Contains(string(b), "hunter2") {
		t.Errorf("a refused call's password reached the audit:\n%s", b)
	}
	if !strings.Contains(string(b), `"to":"\u003cnumber\u003e"`) && !strings.Contains(string(b), `"to":"<number>"`) {
		t.Errorf("a refused call's arguments are described by type:\n%s", b)
	}
}

// resolving runs the real probe code with a fake DNS server that answers
// every A query with 127.0.0.1, and records what was sent: it shows whether
// a lookup left the probe (INITIAL.md §10 Q11).
type resolving struct {
	resolv, hosts string
	mu            sync.Mutex
	queries       []string
}

func newResolving(t *testing.T) *resolving {
	t.Helper()
	dir := t.TempDir()
	r := &resolving{resolv: filepath.Join(dir, "resolv.conf"), hosts: filepath.Join(dir, "hosts")}
	if err := os.WriteFile(r.resolv, []byte("nameserver 127.0.0.11\noptions ndots:0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.hosts, []byte("127.0.0.1 localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *resolving) Name() string { return evidence.ExecutorProbeContainer }

func (r *resolving) Run(ctx context.Context, _ evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	env := probe.Env{ProcDir: "/proc", Limits: probe.LimitsFrom(ctx), Resolver: &probe.Resolver{
		HostsPath: r.hosts, ResolvPath: r.resolv,
		Exchange: func(_ context.Context, m *dns.Msg, _, _ string) (*dns.Msg, error) {
			r.mu.Lock()
			r.queries = append(r.queries, m.Question[0].Name)
			r.mu.Unlock()
			resp := new(dns.Msg)
			resp.SetReply(m)
			if m.Question[0].Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(127, 0, 0, 1)})
			}
			return resp, nil
		},
	}}
	return probe.Run(ctx, env, specs), nil
}

// sent reports whether a query for name (without the trailing dot) was sent.
func (r *resolving) sent(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.queries, name+".")
}

func auditEntries(t *testing.T, path, tool string) []policy.Entry {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []policy.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e policy.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Tool == tool {
			out = append(out, e)
		}
	}
	return out
}

// TestOutsideNames: through MCP, a name with a dot that Docker doesn't know
// is looked up only after the user approves that exact name, on either
// protocol path, or under a [probe] names domain (INITIAL.md §10 Q11).
func TestOutsideNames(t *testing.T) {
	diagnose := map[string]any{"from": "container:shop-worker-1", "to": "example.com:1"}
	for _, version := range []string{"2025-06-18", ""} {
		label := version
		if label == "" {
			label = "latest"
		}
		t.Run(label+"/accept", func(t *testing.T) {
			r := newResolving(t)
			h := harness{}.build(t, policy.Settings{ProbeContainers: true}, fakeDocker{}, r)
			var asked []string
			cs := h.connect(t, func(req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				asked = append(asked, req.Params.Message)
				return accept(req)
			}, version)
			d := structured[report.Diagnosis](t, call(t, cs, "diagnose_connection", diagnose))
			if len(asked) != 1 || !strings.Contains(asked[0], "example.com") || !strings.Contains(asked[0], "no other name") {
				t.Fatalf("asked %q", asked)
			}
			if !r.sent("example.com") {
				t.Errorf("an approved name was not looked up: %v (verdict %s, gaps %+v)", r.queries, d.Verdict, d.Gaps)
			}
			for _, g := range d.Gaps {
				if strings.Contains(g.Detail, probe.NameNotApproved) {
					t.Errorf("the approved name is still a gap: %+v", g)
				}
			}
			// The approval holds for the session, for that name only.
			call(t, cs, "diagnose_connection", diagnose)
			call(t, cs, "run_probe", map[string]any{"kind": "dns", "target": "Example.COM.", "from": "container:shop-worker-1"})
			if len(asked) != 1 {
				t.Errorf("asked again about an approved name: %d questions", len(asked))
			}
			call(t, cs, "run_probe", map[string]any{"kind": "dns", "target": "data.example.com", "from": "container:shop-worker-1"})
			if len(asked) != 2 || !strings.Contains(asked[1], "data.example.com") {
				t.Errorf("a subdomain of an approved name is another name: asked %q", asked)
			}
			if e := auditEntries(t, h.audit, policy.ToolNameConsent); len(e) != 2 || e[0].Status != "approved" || e[0].Args["name"] != "example.com" {
				t.Errorf("audit: %+v", e)
			}
		})
		t.Run(label+"/decline", func(t *testing.T) {
			r := newResolving(t)
			h := harness{}.build(t, policy.Settings{ProbeContainers: true}, fakeDocker{}, r)
			asked := 0
			cs := h.connect(t, func(req *mcp.ElicitRequest) (*mcp.ElicitResult, error) { asked++; return decline(req) }, version)
			for range 2 {
				d := structured[report.Diagnosis](t, call(t, cs, "diagnose_connection", diagnose))
				if len(d.Gaps) == 0 || !strings.Contains(d.Gaps[0].HowToEnable, "names in [probe]") {
					t.Errorf("the gap must name the setting: %+v", d.Gaps)
				}
			}
			p := structured[report.ProbeResult](t, call(t, cs, "run_probe", map[string]any{"kind": "dns", "target": "example.com", "from": "container:shop-worker-1"}))
			if !strings.Contains(p.HowToEnable, "names in [probe]") {
				t.Errorf("run_probe must say how to allow the name: %+v", p)
			}
			if asked != 1 || r.sent("example.com") {
				t.Errorf("a declined name is asked about once and never sent: asked %d, sent %v", asked, r.queries)
			}
			if e := auditEntries(t, h.audit, policy.ToolNameConsent); len(e) != 1 || e[0].Status != "declined" {
				t.Errorf("audit: %+v", e)
			}
			if d := auditEntries(t, h.audit, policy.ToolDiagnose); len(d) == 0 || d[0].ProbesDenied == 0 {
				t.Errorf("a held-back lookup counts as denied, not sent: %+v", d)
			}
		})
	}
	t.Run("names covers the domain", func(t *testing.T) {
		r := newResolving(t)
		h := harness{}.build(t, policy.Settings{ProbeContainers: true, Names: []string{"example.com"}}, fakeDocker{}, r)
		asked := 0
		cs := h.connect(t, func(req *mcp.ElicitRequest) (*mcp.ElicitResult, error) { asked++; return accept(req) }, "")
		call(t, cs, "run_probe", map[string]any{"kind": "dns", "target": "api.example.com", "from": "container:shop-worker-1"})
		if asked != 0 || !r.sent("api.example.com") {
			t.Errorf("a name under [probe] names needs no question: asked %d, sent %v", asked, r.queries)
		}
	})
	t.Run("names Docker knows are free", func(t *testing.T) {
		r := newResolving(t)
		h := harness{}.build(t, policy.Settings{ProbeContainers: true}, fakeDocker{alias: "api.internal"}, r)
		asked := 0
		cs := h.connect(t, func(req *mcp.ElicitRequest) (*mcp.ElicitResult, error) { asked++; return decline(req) }, "")
		call(t, cs, "diagnose_connection", map[string]any{"from": "container:shop-worker-1", "to": "api.internal:8080"})
		call(t, cs, "run_probe", map[string]any{"kind": "dns", "target": "api.internal", "from": "container:shop-worker-1"})
		call(t, cs, "run_probe", map[string]any{"kind": "dns", "target": "host.docker.internal", "from": "container:shop-worker-1"})
		call(t, cs, "run_probe", map[string]any{"kind": "dns", "target": "API.shop_default", "from": "container:shop-worker-1"})
		call(t, cs, "diagnose_connection", map[string]any{"from": "container:shop-worker-1", "to": "api.shop_default:8080"})
		if asked != 0 || !r.sent("api.internal") || !r.sent("host.docker.internal") || !r.sent("api.shop_default") {
			t.Errorf("an alias from Docker's metadata and Docker's fixed names need no question: asked %d, sent %v", asked, r.queries)
		}
	})
	t.Run("no elicitation", func(t *testing.T) {
		r := newResolving(t)
		h := harness{}.build(t, policy.Settings{ProbeContainers: true}, fakeDocker{}, r)
		cs := h.connect(t, nil, "")
		d := structured[report.Diagnosis](t, call(t, cs, "diagnose_connection", diagnose))
		if r.sent("example.com") || len(d.Gaps) == 0 || !strings.Contains(d.Gaps[0].HowToEnable, "names in [probe]") {
			t.Errorf("without elicitation nothing is sent and the gap names the setting: sent %v, gaps %+v", r.queries, d.Gaps)
		}
	})
	t.Run("forged answers", func(t *testing.T) {
		r := newResolving(t)
		h := harness{}.build(t, policy.Settings{ProbeContainers: true}, fakeDocker{}, r)
		cs := h.connect(t, nil, "")
		approve := &mcp.ElicitResult{Action: "accept", Content: map[string]any{"allow": true}}
		for _, state := range []string{"forged", ""} {
			if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
				Name: "run_probe", Arguments: map[string]any{"kind": "dns", "target": "example.com", "from": "container:shop-worker-1"},
				InputResponses: mcp.InputResponseMap{nameKey: approve}, RequestState: state,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if h.p.NameAllowed("example.com") || r.sent("example.com") {
			t.Error("an unsolicited approval let a name out")
		}
	})
}

// A session asks about at most maxNameQuestions names; the question
// doesn't pre-approve; past the cap, held-back names are gaps.
func TestNameQuestionsAreBounded(t *testing.T) {
	r := newResolving(t)
	h := harness{}.build(t, policy.Settings{ProbeContainers: true}, fakeDocker{}, r)
	var asked []string
	cs := h.connect(t, func(req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		schema, _ := json.Marshal(req.Params.RequestedSchema)
		if !strings.Contains(string(schema), `"default":false`) {
			t.Errorf("the name question must not pre-approve: %s", schema)
		}
		asked = append(asked, req.Params.Message)
		return decline(req)
	}, "")
	for i := range maxNameQuestions + 2 {
		p := structured[report.ProbeResult](t, call(t, cs, "run_probe", map[string]any{"kind": "dns", "target": fmt.Sprintf("n%d.example.com", i), "from": "container:shop-worker-1"}))
		if !strings.Contains(p.HowToEnable, "names in [probe]") {
			t.Errorf("probe %d: %+v", i, p)
		}
	}
	if len(asked) != maxNameQuestions || len(r.queries) != 0 {
		t.Errorf("asked %d times (want %d), sent %v", len(asked), maxNameQuestions, r.queries)
	}
}

// TestNameAnswerAppliesToItsQuestion: on the 2026-07-28 path an answer
// counts only for the question its request state carries. An approval sent
// back under the probe-container key for a name question approves nothing.
func TestNameAnswerAppliesToItsQuestion(t *testing.T) {
	r := newResolving(t)
	h := harness{}.build(t, policy.Settings{ProbeContainers: true}, fakeDocker{}, r)
	h.s.mu.Lock()
	h.s.pending["state-1"] = question{key: nameKey, name: "example.com"}
	h.s.mu.Unlock()
	cs := h.connect(t, nil, "")
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "run_probe", Arguments: map[string]any{"kind": "dns", "target": "other.example", "from": "container:shop-worker-1"},
		InputResponses: mcp.InputResponseMap{consentKey: &mcp.ElicitResult{Action: "accept", Content: map[string]any{"allow": true}}},
		RequestState:   "state-1",
	}); err != nil {
		t.Fatal(err)
	}
	if h.p.NameAllowed("example.com") || h.p.NameAllowed("other.example") || r.sent("other.example") {
		t.Error("an answer to another question approved a name")
	}
	if e := auditEntries(t, h.audit, policy.ToolNameConsent); len(e) != 1 || e[0].Status != "declined" || e[0].Args["name"] != "example.com" {
		t.Errorf("the unanswered name question counts as declined: %+v", e)
	}
}

var update = flag.Bool("update", false, "rewrite the golden files")

// TestToolsGolden pins what clients see of the four tools: names, input
// schemas and annotations. save_report has no way to turn redaction off
// (INITIAL.md §10 Q12).
func TestToolsGolden(t *testing.T) {
	h := newHarness(t, false)
	cs := h.connect(t, nil, "")
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	type tool struct {
		Name        string               `json:"name"`
		Description string               `json:"description"`
		Input       any                  `json:"input_schema"`
		Annotations *mcp.ToolAnnotations `json:"annotations"`
	}
	var tools []tool
	for _, tl := range list.Tools {
		tools = append(tools, tool{Name: tl.Name, Description: tl.Description, Input: tl.InputSchema, Annotations: tl.Annotations})
		if tl.Name == "save_report" {
			b, _ := json.Marshal(tl.InputSchema)
			if strings.Contains(string(b), "redact") {
				t.Errorf("save_report takes a redact argument: %s", b)
			}
		}
	}
	got, err := json.MarshalIndent(tools, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "tools.golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run make golden)", err)
	}
	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Errorf("tools (-want +got):\n%s", diff)
	}
}
