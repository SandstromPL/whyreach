package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/miekg/dns"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

var netipOpts = cmpopts.EquateComparable(netip.Addr{}, netip.AddrPort{})

const tcp4Table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 123456 1 0000000000000000 100 0 0 10 0
   1: 00000000:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 123457 1 0000000000000000 100 0 0 10 0
   2: 0400A8C0:C350 0500A8C0:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 123458 1 0000000000000000 20 4 30 10 -1
   3: 0B00007F:96CD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3410468 2 0000000000000000 100 0 0 10 0
`

const tcp6Table = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:2383 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 223456 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 223457 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:1F92 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 223458 1 0000000000000000 100 0 0 10 0
`

func TestParseListeners(t *testing.T) {
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("fixtures were captured on a little-endian machine")
	}
	tests := []struct {
		name, table, proto string
		want               []evidence.Socket
	}{
		{"tcp4", tcp4Table, "tcp", []evidence.Socket{
			{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.1:8080")},
			{Proto: "tcp", Local: netip.MustParseAddrPort("0.0.0.0:9090")},
			{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.11:38605")},
		}},
		{"tcp6", tcp6Table, "tcp6", []evidence.Socket{
			{Proto: "tcp6", Local: netip.MustParseAddrPort("[::]:9091")},
			{Proto: "tcp6", Local: netip.MustParseAddrPort("[::1]:8081")},
			{Proto: "tcp6", Local: netip.MustParseAddrPort("[::ffff:127.0.0.1]:8082")},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseListeners(strings.NewReader(tt.table), tt.proto)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got, netipOpts); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseListenersRejectsGarbage(t *testing.T) {
	for _, row := range []string{
		"   0: ZZZZ:1F90 00000000:0000 0A 0 0 0 0 0 1",
		"   0: 0100007F 00000000:0000 0A 0 0 0 0 0 1",
		"   0: 0100007F:XYZW 00000000:0000 0A 0 0 0 0 0 1",
		"   0: 01007F:1F90 00000000:0000 0A 0 0 0 0 0 1",
	} {
		if _, err := ParseListeners(strings.NewReader("header\n"+row+"\n"), "tcp"); err == nil {
			t.Errorf("want an error for %q", row)
		}
	}
}

func TestReadListenersOwnNetns(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	want := netip.MustParseAddrPort(ln.Addr().String())
	socks, err := ReadListeners("/proc")
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range socks {
		if s.Local == want {
			return
		}
	}
	t.Errorf("own listener %s not among %d sockets", want, len(socks))
}

func TestContainerListenersChecksTheCgroup(t *testing.T) {
	if _, err := ReadListeners("/proc"); errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	// This test process is not in a container with this ID.
	_, err := ContainerListeners(os.Getpid(), strings.Repeat("ab", 32))
	if !errors.Is(err, ErrNotContainer) {
		t.Errorf("err = %v, want ErrNotContainer", err)
	}
	if _, err := ContainerListeners(0, strings.Repeat("ab", 32)); !errors.Is(err, ErrNoProcess) {
		t.Errorf("pid 0: err = %v, want ErrNoProcess", err)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		err  error
		want evidence.Status
	}{
		{ErrUnsupported, evidence.StatusUnsupported},
		{&os.PathError{Op: "open", Path: "/proc/1/net/tcp", Err: os.ErrPermission}, evidence.StatusPermissionDenied},
		{ErrNotContainer, evidence.StatusFailed},
		{&os.PathError{Op: "open", Path: "/proc/1/cgroup", Err: os.ErrNotExist}, evidence.StatusFailed},
		{context.DeadlineExceeded, evidence.StatusTimeout},
		{errors.New("boom"), evidence.StatusError},
	}
	for _, tt := range tests {
		if got, e := Classify(tt.err); got != tt.want || e == nil || e.Message == "" {
			t.Errorf("Classify(%v) = %s %+v, want %s", tt.err, got, e, tt.want)
		}
	}
}

func TestDialOutcomes(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	open := netip.MustParseAddrPort(ln.Addr().String())
	// A port that was just open and is now closed refuses connections.
	ln2, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := netip.MustParseAddrPort(ln2.Addr().String())
	_ = ln2.Close()
	defer func() { _ = ln.Close() }()

	ev := Dial(context.Background(), "x", open, evidence.ViaLiteral)
	if p := ev.Data.(evidence.TCPProbe); ev.Status != evidence.StatusOK || p.Outcome != evidence.OutcomeConnected {
		t.Errorf("open port: %+v", ev)
	}
	ev = Dial(context.Background(), "x", closed, evidence.ViaLiteral)
	if p := ev.Data.(evidence.TCPProbe); ev.Status != evidence.StatusOK || p.Outcome != evidence.OutcomeRefused || p.Errno != "ECONNREFUSED" {
		t.Errorf("closed port: %+v", ev)
	}
	ev = Dial(context.Background(), "x", netip.MustParseAddrPort("169.254.169.254:80"), evidence.ViaLiteral)
	if p := ev.Data.(evidence.TCPProbe); ev.Status != evidence.StatusSkipped || p.Outcome != evidence.OutcomeBlocked || ev.Err.Code != evidence.CodePolicyDenied {
		t.Errorf("metadata address: %+v", ev)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ev := Dial(ctx, "x", open, evidence.ViaLiteral); ev.Status != evidence.StatusTimeout {
		t.Errorf("cancelled context: status %s, want timeout", ev.Status)
	}
}

func TestParseResolvConf(t *testing.T) {
	conf := `# Generated by Docker Engine.
# This file can be edited; Docker Engine will not make further changes once it
# has been modified.

nameserver 127.0.0.11
search corp.example.com lab.example
options ndots:0

# Based on host file: '/run/systemd/resolve/resolv.conf' (internal resolver)
# ExtServers: [host(127.0.0.53)]
# Overrides: []
# Option ndots from: internal
`
	c, err := parseResolvConf(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	want := resolvConf{
		servers:    []string{"127.0.0.11:53"},
		search:     []string{"corp.example.com", "lab.example"},
		ndots:      0,
		extServers: []string{"host(127.0.0.53)"},
	}
	if diff := cmp.Diff(want, c, cmp.AllowUnexported(resolvConf{})); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
	c2, _ := parseResolvConf(strings.NewReader("nameserver ::1\nnameserver 10.0.0.2\n"))
	if diff := cmp.Diff([]string{"[::1]:53", "10.0.0.2:53"}, c2.servers); diff != "" || c2.ndots != 1 {
		t.Errorf("servers (-want +got):\n%s ndots=%d", diff, c2.ndots)
	}
}

func TestCandidates(t *testing.T) {
	c := resolvConf{search: []string{"corp.example.com"}, ndots: 1}
	labels := func(cs []candidate) []string {
		var out []string
		for _, x := range cs {
			out = append(out, x.label+"="+x.fqdn)
		}
		return out
	}
	tests := []struct {
		name  string
		ndots int
		want  []string
	}{
		{"api", 1, []string{"api.<search 1>=api.corp.example.com.", "api=api."}},
		{"api", 0, []string{"api=api.", "api.<search 1>=api.corp.example.com."}},
		{"db.internal", 1, []string{"db.internal=db.internal.", "db.internal.<search 1>=db.internal.corp.example.com."}},
		{"example.com.", 1, []string{"example.com=example.com."}},
		{"API", 0, []string{"api=api.", "api.<search 1>=api.corp.example.com."}},
	}
	for _, tt := range tests {
		c.ndots = tt.ndots
		if diff := cmp.Diff(tt.want, labels(c.candidates(tt.name))); diff != "" {
			t.Errorf("candidates(%q, ndots %d) (-want +got):\n%s", tt.name, tt.ndots, diff)
		}
	}
}

func TestParseHosts(t *testing.T) {
	hosts := "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\nfe00::\tip6-localnet\n# 10.0.0.9 api\n10.9.8.7 spike-extra # comment\n::ffff:10.1.1.1 mapped\n"
	tests := []struct {
		name string
		want []netip.Addr
	}{
		{"localhost", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}},
		{"LOCALHOST.", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}},
		{"spike-extra", []netip.Addr{netip.MustParseAddr("10.9.8.7")}},
		{"mapped", []netip.Addr{netip.MustParseAddr("10.1.1.1")}},
		{"api", nil},
	}
	for _, tt := range tests {
		got, err := parseHosts(strings.NewReader(hosts), tt.name)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(tt.want, got, netipOpts); diff != "" {
			t.Errorf("parseHosts(%q) (-want +got):\n%s", tt.name, diff)
		}
	}
}

// fakeDNS answers from a table keyed by "fqdn TYPE"; a missing key answers
// NXDOMAIN, and the value "timeout" never answers.
type fakeDNS struct {
	mu      sync.Mutex
	answers map[string]string // "api. A" → "172.22.0.3", "SERVFAIL", "timeout", "truncated"
	queries []string
	refuse  string // a server that answers every query with an ICMP refusal
}

func (f *fakeDNS) exchange(ctx context.Context, m *dns.Msg, server, network string) (*dns.Msg, error) {
	q := m.Question[0]
	key := q.Name + " " + dns.TypeToString[q.Qtype]
	f.mu.Lock()
	f.queries = append(f.queries, key+" "+network+" "+server)
	v, ok := f.answers[key]
	f.mu.Unlock()
	if server == f.refuse {
		return nil, &net.OpError{Op: "read", Net: network, Err: syscall.ECONNREFUSED}
	}
	resp := new(dns.Msg)
	resp.SetReply(m)
	switch {
	case !ok:
		resp.Rcode = dns.RcodeNameError
	case v == "timeout":
		<-ctx.Done()
		return nil, ctx.Err()
	case v == "SERVFAIL":
		resp.Rcode = dns.RcodeServerFailure
	case v == "truncated" && network == "udp":
		resp.Truncated = true
	case v == "truncated":
		resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("10.0.0.7")})
	case v == "nodata":
	default:
		ip := net.ParseIP(v)
		if ip.To4() != nil {
			resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: ip})
		} else {
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: ip})
		}
	}
	return resp, nil
}

func writeFiles(t *testing.T, resolv, hosts string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	rp, hp := filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "hosts")
	if err := os.WriteFile(rp, []byte(resolv), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hp, []byte(hosts), 0o600); err != nil {
		t.Fatal(err)
	}
	return rp, hp
}

func TestResolverLookup(t *testing.T) {
	const dockerResolv = "nameserver 127.0.0.11\nsearch corp.example.com\noptions ndots:0\n# ExtServers: [host(127.0.0.53)]\n"
	const dockerHosts = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
	tests := []struct {
		name       string
		lookup     string
		answers    map[string]string
		wantStatus evidence.Status
		want       evidence.DNSProbe
	}{
		{
			name: "answered by Docker DNS", lookup: "api",
			answers:    map[string]string{"api. A": "172.22.0.3", "api. AAAA": "nodata"},
			wantStatus: evidence.StatusOK,
			want: evidence.DNSProbe{
				Name: "api", Answered: "api", Via: evidence.ViaDNS, Server: "127.0.0.11:53", Rcode: "NOERROR",
				Answers:  []netip.Addr{netip.MustParseAddr("172.22.0.3")},
				Upstream: []string{"host(127.0.0.53)"},
				Attempts: []evidence.DNSAttempt{{Query: "api", Type: "A", Rcode: "NOERROR", N: 1}, {Query: "api", Type: "AAAA", Rcode: "NOERROR"}},
			},
		},
		{
			name: "hosts file first", lookup: "localhost",
			wantStatus: evidence.StatusOK,
			want: evidence.DNSProbe{
				Name: "localhost", Answered: "localhost", Via: evidence.ViaHosts,
				Answers: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
			},
		},
		{
			name: "unknown name: SERVFAIL, then NXDOMAIN with the search domain", lookup: "api",
			answers:    map[string]string{"api. A": "SERVFAIL", "api. AAAA": "SERVFAIL"},
			wantStatus: evidence.StatusOK,
			want: evidence.DNSProbe{
				Name: "api", Server: "127.0.0.11:53", Rcode: "SERVFAIL", Upstream: []string{"host(127.0.0.53)"},
				Attempts: []evidence.DNSAttempt{
					{Query: "api", Type: "A", Rcode: "SERVFAIL"}, {Query: "api", Type: "AAAA", Rcode: "SERVFAIL"},
					{Query: "api.<search 1>", Type: "A", Rcode: "NXDOMAIN"}, {Query: "api.<search 1>", Type: "AAAA", Rcode: "NXDOMAIN"},
				},
			},
		},
		{
			name: "search domain answers", lookup: "db",
			answers:    map[string]string{"db.corp.example.com. A": "10.1.2.3"},
			wantStatus: evidence.StatusOK,
			want: evidence.DNSProbe{
				Name: "db", Answered: "db.<search 1>", Via: evidence.ViaDNS, Server: "127.0.0.11:53", Rcode: "NOERROR",
				Answers:  []netip.Addr{netip.MustParseAddr("10.1.2.3")},
				Upstream: []string{"host(127.0.0.53)"},
				Attempts: []evidence.DNSAttempt{
					{Query: "db", Type: "A", Rcode: "NXDOMAIN"}, {Query: "db", Type: "AAAA", Rcode: "NXDOMAIN"},
					{Query: "db.<search 1>", Type: "A", Rcode: "NOERROR", N: 1}, {Query: "db.<search 1>", Type: "AAAA", Rcode: "NXDOMAIN"},
				},
			},
		},
		{
			name: "truncated answer retried over TCP", lookup: "big",
			answers:    map[string]string{"big. A": "truncated", "big. AAAA": "nodata"},
			wantStatus: evidence.StatusOK,
			want: evidence.DNSProbe{
				Name: "big", Answered: "big", Via: evidence.ViaDNS, Server: "127.0.0.11:53", Rcode: "NOERROR",
				Answers:  []netip.Addr{netip.MustParseAddr("10.0.0.7")},
				Upstream: []string{"host(127.0.0.53)"},
				Attempts: []evidence.DNSAttempt{{Query: "big", Type: "A", Rcode: "NOERROR", N: 1}, {Query: "big", Type: "AAAA", Rcode: "NOERROR"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp, hp := writeFiles(t, dockerResolv, dockerHosts)
			f := &fakeDNS{answers: tt.answers}
			r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}
			ev := r.Lookup(context.Background(), tt.lookup)
			if ev.Status != tt.wantStatus {
				t.Fatalf("status = %s (%+v), want %s", ev.Status, ev.Err, tt.wantStatus)
			}
			if diff := cmp.Diff(tt.want, ev.Data, netipOpts); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolverTimeoutIsAnObservation(t *testing.T) {
	rp, hp := writeFiles(t, "nameserver 192.0.2.53\noptions ndots:5\n", "")
	f := &fakeDNS{answers: map[string]string{"example.com. A": "timeout", "example.com. AAAA": "timeout"}}
	r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange, Timeout: 20 * time.Millisecond, Budget: 200 * time.Millisecond}
	start := time.Now()
	ev := r.Lookup(context.Background(), "example.com")
	if took := time.Since(start); took > time.Second {
		t.Errorf("lookup took %s, want it bounded by the budget", took)
	}
	p := ev.Data.(evidence.DNSProbe)
	if ev.Status != evidence.StatusOK || p.Rcode != evidence.RcodeTimeout || len(p.Answers) != 0 {
		t.Errorf("got status %s rcode %q answers %v, want ok/TIMEOUT/none", ev.Status, p.Rcode, p.Answers)
	}
}

func TestResolverMissingConfig(t *testing.T) {
	r := &Resolver{HostsPath: "/nonexistent/hosts", ResolvPath: "/nonexistent/resolv.conf"}
	ev := r.Lookup(context.Background(), "api")
	if ev.Status != evidence.StatusFailed || ev.Err == nil {
		t.Errorf("status = %s err = %+v, want failed", ev.Status, ev.Err)
	}
}

func TestRunSharesLookupsAndConnects(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := netip.MustParseAddrPort(ln.Addr().String()).Port()
	rp, hp := writeFiles(t, "nameserver 127.0.0.11\noptions ndots:0\n", "127.0.0.1 localhost\n")
	f := &fakeDNS{answers: map[string]string{"api. A": "127.0.0.1", "api. AAAA": "nodata"}}
	env := Env{ProcDir: "/proc", Resolver: &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}}
	specs := []Spec{
		{Kind: SpecDNS, Host: "api"},
		{Kind: SpecTCP, Host: "api", Port: port},
		{Kind: SpecTCP, Host: "127.0.0.1", Port: port, Via: evidence.ViaMetadata},
		{Kind: SpecTCP, Host: "nothere", Port: port},
	}
	evs := Run(context.Background(), env, specs)
	var got []string
	for _, ev := range evs {
		s := string(ev.Kind) + " " + ev.Subject + " " + string(ev.Status)
		if p, ok := ev.Data.(evidence.TCPProbe); ok {
			s += " " + p.Via + " " + p.Outcome
		}
		got = append(got, s)
	}
	want := []string{
		"probe.dns api ok",
		"probe.tcp api:" + itoa(port) + " ok dns connected",
		"probe.tcp 127.0.0.1:" + itoa(port) + " ok metadata connected",
		"probe.dns nothere ok",
		"probe.tcp nothere:" + itoa(port) + " skipped",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
	n := 0
	for _, q := range f.queries {
		if strings.HasPrefix(q, "api. A ") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("api was looked up %d times, want once: %v", n, f.queries)
	}
}

func itoa(p uint16) string {
	return netip.AddrPortFrom(netip.IPv4Unspecified(), p).String()[len("0.0.0.0:"):]
}

func TestDecodeSpecs(t *testing.T) {
	good := `[{"kind":"dns","host":"api"},{"kind":"tcp","host":"api","port":8080},{"kind":"tcp","host":"172.22.0.3","port":8080,"via":"metadata"},{"kind":"listeners"}]`
	specs, err := DecodeSpecs(good)
	if err != nil || len(specs) != 4 {
		t.Fatalf("DecodeSpecs(good) = %v, %v", specs, err)
	}
	enc, err := EncodeSpecs(specs)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DecodeSpecs(enc)
	if err != nil || !cmp.Equal(specs, again) {
		t.Errorf("round trip: %v %v", again, err)
	}
	for _, bad := range []string{
		``, `[]`, `{}`, `[{"kind":"exec","host":"x"}]`,
		`[{"kind":"tcp","host":"10.0.0.0/8","port":80}]`,
		`[{"kind":"tcp","host":"api","port":0}]`,
		`[{"kind":"tcp","host":"169.254.169.254","port":80}]`,
		`[{"kind":"tcp","host":"api","port":80,"via":"metadata"}]`,
		`[{"kind":"tcp","host":"api","port":80,"via":"magic"}]`,
		`[{"kind":"dns","host":"api","port":53}]`,
		`[{"kind":"listeners","host":"api"}]`,
		`[{"kind":"dns","host":"api","extra":1}]`,
		`[{"kind":"dns","host":"api"}] [1]`,
		`[{"kind":"dns","host":"a"},{"kind":"dns","host":"b"},{"kind":"dns","host":"c"},{"kind":"dns","host":"d"},{"kind":"dns","host":"e"},{"kind":"dns","host":"f"},{"kind":"dns","host":"g"},{"kind":"dns","host":"h"},{"kind":"dns","host":"i"}]`,
	} {
		if _, err := DecodeSpecs(bad); err == nil {
			t.Errorf("DecodeSpecs(%s) = nil error, want a rejection", bad)
		}
	}
}

func TestMainWritesJSONLines(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), `[{"kind":"listeners"}]`, 0, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %s", code, stderr.String())
	}
	var ev evidence.Evidence
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &ev); err != nil {
		t.Fatalf("stdout is not one evidence line: %v\n%s", err, stdout.String())
	}
	if ev.Kind != evidence.KindListeners {
		t.Errorf("kind = %s", ev.Kind)
	}
	if code := Main(context.Background(), `nonsense`, time.Second, &stdout, &stderr); code != ExitInternal {
		t.Errorf("bad spec: exit %d, want %d", code, ExitInternal)
	}
}

func TestResolverFailsOverOnErrors(t *testing.T) {
	rp, hp := writeFiles(t, "nameserver 10.0.0.53\nnameserver 10.0.0.54\noptions ndots:0\n", "")
	f := &fakeDNS{refuse: "10.0.0.53:53", answers: map[string]string{"db. A": "10.1.2.3", "db. AAAA": "nodata"}}
	r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}
	ev := r.Lookup(context.Background(), "db")
	p := ev.Data.(evidence.DNSProbe)
	if len(p.Answers) != 1 || p.Rcode != "NOERROR" {
		t.Errorf("want the second nameserver's answer after the first refused: %+v\nqueries %v", p, f.queries)
	}
}

func TestResolverRcodeDescribesTheNameAsGiven(t *testing.T) {
	// With ndots:1 a single-label name tries the search domain first.
	rp, hp := writeFiles(t, "nameserver 127.0.0.53\nsearch corp.example.com\n", "")
	f := &fakeDNS{answers: map[string]string{"api. A": "SERVFAIL", "api. AAAA": "SERVFAIL"}}
	r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}
	p := r.Lookup(context.Background(), "api").Data.(evidence.DNSProbe)
	if p.Rcode != "SERVFAIL" || p.Attempts[0].Query != "api.<search 1>" {
		t.Errorf("rcode %q (attempts %+v), want SERVFAIL for api itself", p.Rcode, p.Attempts)
	}
}
