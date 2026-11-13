package policy

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// resolving is a host executor that runs the real probe, so the policy's
// limits act as they do in production, against a fake DNS server that
// answers every A query and records what it was sent. Only lookups run:
// nothing here connects.
type resolving struct {
	mu      sync.Mutex
	queries []string
	rp, hp  string
}

func newResolving(t *testing.T, resolv, hosts string) *resolving {
	t.Helper()
	dir := t.TempDir()
	r := &resolving{rp: filepath.Join(dir, "resolv.conf"), hp: filepath.Join(dir, "hosts")}
	for path, body := range map[string]string{r.rp: resolv, r.hp: hosts} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func (r *resolving) Name() string { return evidence.ExecutorHost }

func (r *resolving) Run(ctx context.Context, _ evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	env := probe.Env{ProcDir: "/proc", Limits: probe.LimitsFrom(ctx),
		Resolver: &probe.Resolver{HostsPath: r.hp, ResolvPath: r.rp, Exchange: r.exchange}}
	return probe.Run(ctx, env, specs), nil
}

func (r *resolving) exchange(_ context.Context, m *dns.Msg, server, _ string) (*dns.Msg, error) {
	q := m.Question[0]
	r.mu.Lock()
	r.queries = append(r.queries, dns.TypeToString[q.Qtype]+" "+q.Name+" "+server)
	r.mu.Unlock()
	resp := new(dns.Msg)
	resp.SetReply(m)
	if q.Qtype == dns.TypeA {
		resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("10.9.9.9")})
	}
	return resp, nil
}

// lookups counts the lookups of name that reached the DNS server: one A
// query each.
func (r *resolving) lookups(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, q := range r.queries {
		if strings.HasPrefix(q, "A "+name+". ") {
			n++
		}
	}
	return n
}

// An approval of an outside name covers ApprovalBudget lookups; a lookup the
// hosts file answers spends none, and [probe] names has no budget
// (INITIAL.md §10 Q14).
func TestApprovalCoversThreeLookups(t *testing.T) {
	r := newResolving(t, "nameserver 10.0.0.53\noptions ndots:0\n", "10.1.2.3 hosts.example\n")
	p, err := New(Deps{Settings: Settings{Docker: true, Names: []string{"corp.example"}, RatePerMinute: 100},
		Docker: fakeDocker{}, Listeners: fakeDocker{}, Host: r, Client: ClientMCP})
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(name string) evidence.Evidence {
		t.Helper()
		res, err := p.Probe(context.Background(), ProbeArgs{Kind: "dns", Target: name})
		if err != nil {
			t.Fatal(err)
		}
		return res.Evidence[0]
	}
	if e := lookup("data.example.net"); !NameHeldBack(e) {
		t.Fatalf("before any approval: %s %+v", e.Status, e.Err)
	}
	p.RecordNameConsent("data.example.net", true, "accept")
	for i := range ApprovalBudget {
		if e := lookup("data.example.net"); e.Status != evidence.StatusOK {
			t.Fatalf("lookup %d: %s %+v", i+1, e.Status, e.Err)
		}
	}
	if e := lookup("data.example.net"); !NameHeldBack(e) || p.NameAllowed("data.example.net") {
		t.Errorf("a fourth lookup: %s %+v", e.Status, e.Err)
	}
	if n := r.lookups("data.example.net"); n != ApprovalBudget {
		t.Errorf("%d lookups reached the server, want %d", n, ApprovalBudget)
	}
	p.RecordNameConsent("data.example.net", true, "accept") // asked again, and approved
	if e := lookup("data.example.net"); e.Status != evidence.StatusOK {
		t.Errorf("after a second approval: %s %+v", e.Status, e.Err)
	}

	p.RecordNameConsent("hosts.example", true, "accept")
	for range ApprovalBudget + 2 {
		if e := lookup("hosts.example"); e.Status != evidence.StatusOK {
			t.Fatalf("hosts.example: %s %+v", e.Status, e.Err)
		}
	}
	if !p.NameAllowed("hosts.example") || r.lookups("hosts.example") != 0 {
		t.Error("answers from the hosts file spent the approval")
	}
	for range ApprovalBudget + 2 {
		if e := lookup("api.corp.example"); e.Status != evidence.StatusOK {
			t.Fatalf("a name [probe] names covers: %s %+v", e.Status, e.Err)
		}
	}
}

// Batches running at once share one budget: each takes its lookup before it
// sends, so no more than the approval covers go out.
func TestApprovalBudgetHoldsUnderConcurrency(t *testing.T) {
	r := newResolving(t, "nameserver 10.0.0.53\noptions ndots:0\n", "")
	p, err := New(Deps{Settings: Settings{Docker: true, RatePerMinute: 100}, Docker: fakeDocker{}, Listeners: fakeDocker{}, Host: r, Client: ClientMCP})
	if err != nil {
		t.Fatal(err)
	}
	p.RecordNameConsent("data.example.net", true, "accept")
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 10 {
		wg.Go(func() {
			res, err := p.Probe(context.Background(), ProbeArgs{Kind: "dns", Target: "data.example.net"})
			if err == nil && res.Evidence[0].Status == evidence.StatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != ApprovalBudget || r.lookups("data.example.net") != ApprovalBudget {
		t.Errorf("%d lookups answered, %d sent; want %d", ok, r.lookups("data.example.net"), ApprovalBudget)
	}
}

// Through MCP, a TCP probe to a private address that only the rfc1918 class
// admits needs the user's approval of that address and port, which covers
// ApprovalBudget connects. Docker's networks, the host's own addresses,
// loopback and explicit allowlist entries stay free, and the CLI is
// unchanged (INITIAL.md §10 Q15).
func TestPrivateAddressesNeedApproval(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	rec := &recorder{}
	ifaces := func() (evidence.HostAddrs, error) {
		return evidence.HostAddrs{Interfaces: []evidence.Interface{{Name: "eth0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}}}}, nil
	}
	settings := Settings{Docker: true, Allow: []string{"loopback", "rfc1918", "docker", "10.20.0.0/16"}, RatePerMinute: 100}
	p, err := New(Deps{Settings: settings, Docker: fakeDocker{}, Listeners: fakeDocker{}, Host: rec, Interfaces: ifaces, Client: ClientMCP, Audit: NewAudit(audit)})
	if err != nil {
		t.Fatal(err)
	}
	connect := func(p *Policy, target string) evidence.Evidence {
		t.Helper()
		res, err := p.Probe(context.Background(), ProbeArgs{Kind: "tcp", Target: target})
		if err != nil {
			t.Fatal(err)
		}
		return res.Evidence[0]
	}
	for _, free := range []string{"172.22.0.3:8080", "192.168.1.10:8080", "10.20.3.4:80", "127.0.0.1:5432"} {
		if e := connect(p, free); e.Status != evidence.StatusOK {
			t.Errorf("%s: %s %+v", free, e.Status, e.Err)
		}
	}
	runs := rec.count()
	e := connect(p, "10.0.5.7:5432")
	if !AddrHeldBack(e) || rec.count() != runs {
		t.Fatalf("an unapproved private address: %s %+v, sent %v", e.Status, e.Err, rec.count() != runs)
	}
	ap := netip.MustParseAddrPort("10.0.5.7:5432")
	if got := NeedsAddrApproval([]evidence.Evidence{e}); !slices.Equal(got, []netip.AddrPort{ap}) {
		t.Errorf("NeedsAddrApproval = %v", got)
	}
	if e := connect(p, "192.168.1.11:8080"); !AddrHeldBack(e) {
		t.Errorf("the host's neighbour on the LAN: %s %+v", e.Status, e.Err)
	}

	p.RecordAddrConsent(ap, true, "accept")
	for _, other := range []string{"10.0.5.8:5432", "10.0.5.7:80"} {
		if e := connect(p, other); !AddrHeldBack(e) {
			t.Errorf("the approval of %s let %s through", ap, other)
		}
	}
	for i := range ApprovalBudget {
		if e := connect(p, "10.0.5.7:5432"); e.Status != evidence.StatusOK {
			t.Fatalf("connect %d: %s %+v", i+1, e.Status, e.Err)
		}
		if lim := rec.lims[len(rec.lims)-1]; !slices.Equal(lim.Approved, []netip.AddrPort{ap}) {
			t.Errorf("connect %d: the batch was given %v", i+1, lim.Approved)
		}
	}
	if e := connect(p, "10.0.5.7:5432"); !AddrHeldBack(e) || p.AddrAllowed(ap) {
		t.Errorf("a fourth connect: %s %+v", e.Status, e.Err)
	}
	if es := entries(t, audit); !slices.ContainsFunc(es, func(e Entry) bool {
		return e.Tool == ToolAddrConsent && e.Status == "approved" && e.Args["address"] == "10.0.5.7:5432"
	}) {
		t.Errorf("no connect_consent entry: %+v", es)
	}

	cli, err := New(Deps{Settings: settings, Docker: fakeDocker{}, Listeners: fakeDocker{}, Host: rec, Interfaces: ifaces, Client: ClientCLI})
	if err != nil {
		t.Fatal(err)
	}
	if e := connect(cli, "10.0.5.8:5432"); e.Status != evidence.StatusOK || cli.AddrsNeedApproval() {
		t.Errorf("the CLI: %s %+v", e.Status, e.Err)
	}
	// Without the rfc1918 class nothing is asked: the allowlist decides.
	narrow, err := New(Deps{Settings: Settings{Docker: true, Allow: []string{"loopback", "docker"}, RatePerMinute: 100}, Docker: fakeDocker{}, Listeners: fakeDocker{}, Host: rec, Client: ClientMCP})
	if err != nil {
		t.Fatal(err)
	}
	if e := connect(narrow, "10.0.5.8:5432"); AddrHeldBack(e) || e.Err == nil || !strings.Contains(e.Err.Message, "allowlist") {
		t.Errorf("outside the allowlist: %s %+v", e.Status, e.Err)
	}
}

// A batch takes, for each approved address, at most one connect per TCP
// check to its port, and gets back what it didn't use.
func TestAddressLeasesComeBack(t *testing.T) {
	p, err := New(Deps{Settings: Settings{Docker: true, Allow: []string{"rfc1918"}}, Client: ClientMCP})
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort("10.0.5.7:5432")
	p.RecordAddrConsent(ap, true, "accept")
	leased := p.leaseAddrs([]probe.Spec{{Kind: probe.SpecTCP, Host: "a", Port: 5432}, {Kind: probe.SpecTCP, Host: "b", Port: 5432}, {Kind: probe.SpecTCP, Host: "c", Port: 80}})
	if !slices.Equal(leased, []netip.AddrPort{ap, ap}) || p.addrs[ap] != 1 {
		t.Fatalf("leased %v, left %d", leased, p.addrs[ap])
	}
	used := evidence.Evidence{Kind: evidence.KindTCP, Status: evidence.StatusOK, Data: evidence.TCPProbe{Addr: ap, Outcome: evidence.OutcomeRefused}}
	p.settle(nil, leased, []evidence.Evidence{used})
	if p.addrs[ap] != 2 {
		t.Errorf("after one of two used: %d left, want 2", p.addrs[ap])
	}
}

// doctor says a blocked host resolver is asked for DNS only, and warns when
// whyreach can't see the host's resolvers (INITIAL.md §10 Q13).
func TestResolverCheck(t *testing.T) {
	host := []netip.Addr{netip.MustParseAddr("169.254.169.254")}
	if c := resolverCheck("the first nameserver in /etc/resolv.conf", "169.254.169.254", host); c.Status != engine.CheckInfo || !strings.Contains(c.Detail, "DNS only") {
		t.Errorf("the host's own resolver: %+v", c)
	}
	if c := resolverCheck("the first nameserver in /etc/resolv.conf", "169.254.169.254", nil); c.Status != engine.CheckWarn || !strings.Contains(c.Fix, "--network host") {
		t.Errorf("the host's resolvers unseen: %+v", c)
	}
}

// The host's own resolvers reach every batch's limits, for the CLI and MCP
// clients alike, read for each batch.
func TestHostResolversReachTheProbe(t *testing.T) {
	reads := 0
	for _, client := range []string{ClientCLI, ClientMCP} {
		rec := &recorder{}
		p, err := New(Deps{Settings: Settings{Docker: true}, Docker: fakeDocker{}, Listeners: fakeDocker{}, Host: rec, Client: client,
			HostResolvers: func() []netip.Addr { reads++; return []netip.Addr{netip.MustParseAddr("169.254.169.254")} }})
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := p.Probe(context.Background(), ProbeArgs{Kind: "dns", Target: "api"}); err != nil {
				t.Fatal(err)
			}
		}
		if lim := rec.lims[len(rec.lims)-1]; len(lim.HostResolvers) != 1 || lim.HostResolvers[0] != netip.MustParseAddr("169.254.169.254") {
			t.Errorf("%s: the probe got %v", client, lim.HostResolvers)
		}
	}
	if reads != 4 {
		t.Errorf("read the host's resolvers %d times for 4 batches", reads)
	}
}
