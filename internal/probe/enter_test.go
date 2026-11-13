package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// recordingEnter stands in for the netns executor's setns: it counts what
// runs through it, and refuses everything when fail is set.
type recordingEnter struct {
	mu   sync.Mutex
	n    int
	fail error
}

func (r *recordingEnter) enter(f func()) error {
	r.mu.Lock()
	r.n++
	r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	f()
	return nil
}

func (r *recordingEnter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// TestRunCreatesEverySocketThroughEnter: every query, every connect and the
// listener read go through Enter, or they would run in whyreach's own
// namespace instead of the container's.
func TestRunCreatesEverySocketThroughEnter(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := netip.MustParseAddrPort(ln.Addr().String()).Port()
	rp, hp := writeFiles(t, "nameserver 127.0.0.11\noptions ndots:0\n", "")
	f := &fakeDNS{answers: map[string]string{"api. A": "127.0.0.1", "api. AAAA": "nodata"}}
	rec := &recordingEnter{}
	env := Env{
		ProcDir:  "/proc",
		Resolver: &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange, Enter: rec.enter},
		Enter:    rec.enter,
	}
	evs := Run(context.Background(), env, []Spec{
		{Kind: SpecDNS, Host: "api"},
		{Kind: SpecTCP, Host: "api", Port: port},
		{Kind: SpecTCP, Host: "127.0.0.1", Port: port, Via: evidence.ViaMetadata},
		{Kind: SpecListeners},
	})
	for _, ev := range evs {
		if !ev.OK() {
			t.Errorf("%s %s: %s %+v", ev.Kind, ev.Subject, ev.Status, ev.Err)
		}
	}
	// A and AAAA for api, two connects, one listener read.
	if got := rec.count(); got != 5 {
		t.Errorf("%d calls went through Enter, want 5 (queries %v)", got, f.queries)
	}
}

// TestRunWithoutTheNamespaceObservesNothing: when the thread can't get into
// the namespace, nothing is sent, and the records say why instead of
// reporting an rcode or a TCP outcome that was never observed.
func TestRunWithoutTheNamespaceObservesNothing(t *testing.T) {
	rp, hp := writeFiles(t, "nameserver 127.0.0.11\noptions ndots:0\n", "")
	f := &fakeDNS{answers: map[string]string{"api. A": "10.0.0.7"}}
	rec := &recordingEnter{fail: fmt.Errorf("enter the network namespace: %w", syscall.EPERM)}
	env := Env{
		ProcDir:  "/proc",
		Resolver: &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange, Enter: rec.enter},
		Enter:    rec.enter,
	}
	evs := Run(context.Background(), env, []Spec{
		{Kind: SpecDNS, Host: "api"},
		{Kind: SpecTCP, Host: "127.0.0.1", Port: 9},
		{Kind: SpecListeners},
	})
	var kinds []evidence.Kind
	for _, ev := range evs {
		kinds = append(kinds, ev.Kind)
		if ev.Status != evidence.StatusPermissionDenied || ev.Err == nil || ev.Err.Code != evidence.CodePermissionDenied || ev.Err.Errno != "EPERM" {
			t.Errorf("%s %s: status %s err %+v, want permission_denied with EPERM", ev.Kind, ev.Subject, ev.Status, ev.Err)
		}
		switch p := ev.Data.(type) {
		case evidence.DNSProbe:
			if p.Rcode != "" || len(p.Attempts) != 0 {
				t.Errorf("a lookup that was never sent has rcode %q and attempts %v", p.Rcode, p.Attempts)
			}
		case evidence.TCPProbe:
			t.Errorf("a connect that was never made has an outcome: %+v", p)
		}
	}
	slices.Sort(kinds)
	if want := []evidence.Kind{evidence.KindListeners, evidence.KindDNS, evidence.KindTCP}; !slices.Equal(kinds, want) {
		t.Errorf("records %v, want one per spec %v", kinds, want)
	}
	if len(f.queries) != 0 {
		t.Errorf("queries were sent: %v", f.queries)
	}
}

// TestResolverReadsItsFilesThroughOpen: the netns executor hands the
// resolver the container's own files.
func TestResolverReadsItsFilesThroughOpen(t *testing.T) {
	files := map[string]string{
		"/etc/hosts":       "10.9.8.7 db\n",
		"/etc/resolv.conf": "nameserver 127.0.0.11\noptions ndots:0\n",
	}
	var mu sync.Mutex
	var opened []string
	open := func(_ context.Context, path string) (io.ReadCloser, error) {
		mu.Lock()
		opened = append(opened, path)
		mu.Unlock()
		s, ok := files[path]
		if !ok {
			return nil, fmt.Errorf("open %s: %w", path, syscall.ENOENT)
		}
		return io.NopCloser(strings.NewReader(s)), nil
	}
	f := &fakeDNS{answers: map[string]string{"api. A": "172.22.0.3", "api. AAAA": "nodata"}}
	r := &Resolver{HostsPath: "/etc/hosts", ResolvPath: "/etc/resolv.conf", Exchange: f.exchange, Open: open}

	db := r.Lookup(context.Background(), "db").Data.(evidence.DNSProbe)
	if db.Via != evidence.ViaHosts || len(db.Answers) != 1 || db.Answers[0] != netip.MustParseAddr("10.9.8.7") {
		t.Errorf("db: %+v, want 10.9.8.7 from the hosts file it was given", db)
	}
	api := r.Lookup(context.Background(), "api").Data.(evidence.DNSProbe)
	if api.Server != "127.0.0.11:53" || len(api.Answers) != 1 {
		t.Errorf("api: %+v, want an answer from the nameserver in the resolv.conf it was given", api)
	}
	if want := []string{"/etc/hosts", "/etc/hosts", "/etc/resolv.conf"}; !slices.Equal(opened, want) {
		t.Errorf("opened %v, want %v", opened, want)
	}
}

// TestUnreadableHostsFileFailsTheLookup: the app reads /etc/hosts before any
// DNS, so a hosts file that exists but can't be read makes the lookup fail
// (a gap) rather than fall through to an answer the app wouldn't get. Only
// a missing file means there is none.
func TestUnreadableHostsFileFailsTheLookup(t *testing.T) {
	f := &fakeDNS{answers: map[string]string{"db. A": "10.1.2.3", "db. AAAA": "nodata"}}
	for _, tt := range []struct {
		name       string
		hostsErr   error
		wantStatus evidence.Status
	}{
		{"missing", fmt.Errorf("open /etc/hosts: %w", syscall.ENOENT), evidence.StatusOK},
		{"unreadable", fmt.Errorf("open /etc/hosts: %w", syscall.EACCES), evidence.StatusPermissionDenied},
		{"too large", fmt.Errorf("/etc/hosts is larger than 16777216 bytes"), evidence.StatusError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			open := func(_ context.Context, path string) (io.ReadCloser, error) {
				if path == "/etc/hosts" {
					return nil, tt.hostsErr
				}
				return io.NopCloser(strings.NewReader("nameserver 127.0.0.11\noptions ndots:0\n")), nil
			}
			r := &Resolver{HostsPath: "/etc/hosts", ResolvPath: "/etc/resolv.conf", Exchange: f.exchange, Open: open}
			ev := r.Lookup(context.Background(), "db")
			if ev.Status != tt.wantStatus {
				t.Errorf("status %s (%+v), want %s", ev.Status, ev.Err, tt.wantStatus)
			}
			if p := ev.Data.(evidence.DNSProbe); tt.wantStatus != evidence.StatusOK && (p.Rcode != "" || len(p.Answers) != 0) {
				t.Errorf("a failed lookup reports %+v", p)
			}
		})
	}
}

// TestConnectAfterAFailedLookup: when the lookup itself couldn't be made,
// the TCP record says so instead of claiming the name doesn't resolve.
func TestConnectAfterAFailedLookup(t *testing.T) {
	rp, hp := writeFiles(t, "nameserver 127.0.0.11\noptions ndots:0\n", "")
	f := &fakeDNS{answers: map[string]string{"api. A": "10.0.0.7"}}
	rec := &recordingEnter{fail: fmt.Errorf("enter the network namespace: %w", syscall.EPERM)}
	env := Env{ProcDir: "/proc", Resolver: &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange, Enter: rec.enter}, Enter: rec.enter}
	evs := Run(context.Background(), env, []Spec{{Kind: SpecTCP, Host: "api", Port: 8080}})
	var tcp *evidence.Evidence
	for i := range evs {
		if evs[i].Kind == evidence.KindTCP {
			tcp = &evs[i]
		}
	}
	if tcp == nil || tcp.Status != evidence.StatusSkipped || tcp.Err == nil ||
		tcp.Err.Code != evidence.CodePermissionDenied || strings.Contains(tcp.Err.Message, "did not resolve") ||
		!strings.Contains(tcp.Err.Message, "could not be made") {
		t.Errorf("tcp record %+v, want skipped: the lookup could not be made (permission_denied)", tcp)
	}
}
