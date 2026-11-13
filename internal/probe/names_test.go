package probe

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Through MCP an outside name goes to a nameserver only when the policy
// lists it (INITIAL.md §10 Q11); the hosts file still answers first, and
// names without a dot, loopback names and Docker's fixed names stay free.
func TestRunHoldsBackOutsideNames(t *testing.T) {
	rp, hp := writeFiles(t, "nameserver 127.0.0.11\nsearch corp.example\noptions ndots:0\n",
		"127.0.0.1 localhost\n10.9.8.7 db.mapped.example\n")
	f := &fakeDNS{answers: map[string]string{
		"approved.example. A": "10.0.0.5", "api. A": "172.22.0.3", "host.docker.internal. A": "172.17.0.1",
	}}
	env := Env{
		ProcDir:  "/proc",
		Resolver: &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange},
		Limits:   Limits{NamesRestricted: true, Names: []string{"approved.example"}},
	}
	specs := []Spec{
		{Kind: SpecDNS, Host: "data.attacker.example"},
		{Kind: SpecTCP, Host: "data.attacker.example", Port: 443},
		{Kind: SpecDNS, Host: "Approved.Example."},
		{Kind: SpecDNS, Host: "db.mapped.example"}, // the hosts file answers: nothing is sent
		{Kind: SpecDNS, Host: "api"},
		{Kind: SpecDNS, Host: "host.docker.internal"},
	}
	evs := Run(context.Background(), env, specs)
	var got []string
	for _, ev := range evs {
		s := string(ev.Kind) + " " + ev.Subject + " " + string(ev.Status)
		if ev.Err != nil {
			s += " " + ev.Err.Code + ": " + ev.Err.Message
		}
		got = append(got, s)
	}
	want := []string{
		"probe.dns data.attacker.example skipped policy_denied: " + NameNotApproved,
		"probe.tcp data.attacker.example:443 skipped policy_denied: " + NameNotApproved,
		"probe.dns Approved.Example. ok",
		"probe.dns db.mapped.example ok",
		"probe.dns api ok",
		"probe.dns host.docker.internal ok",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
	for _, q := range f.queries {
		if strings.Contains(q, "attacker") || strings.Contains(q, "mapped") {
			t.Errorf("sent %q", q)
		}
	}
	if len(f.queries) == 0 {
		t.Error("the free names were not looked up")
	}
}

func TestLookupWithoutLimitsSendsAnyName(t *testing.T) {
	rp, hp := writeFiles(t, "nameserver 127.0.0.11\noptions ndots:0\n", "")
	f := &fakeDNS{answers: map[string]string{"example.com. A": "93.184.216.34"}}
	r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}
	if ev := r.Lookup(context.Background(), "example.com"); ev.Status != evidence.StatusOK {
		t.Fatalf("status %s, err %+v", ev.Status, ev.Err)
	}
}

// The container controls its resolv.conf: a blocked nameserver gets no
// query, with any other limits or none (INITIAL.md §10 Q11). When the first
// is blocked, the app's own lookup would go there, so none is made.
func TestLookupSkipsBlockedNameservers(t *testing.T) {
	tests := []struct {
		name       string
		resolv     string
		wantStatus evidence.Status
		wantServer string
		wantNote   string
	}{
		{
			name:       "only cloud metadata",
			resolv:     "nameserver 169.254.169.254\n",
			wantStatus: evidence.StatusSkipped,
		},
		{
			name:       "link-local IPv6 and the AWS metadata address",
			resolv:     "nameserver fe80::1\nnameserver fd00:ec2::254\n",
			wantStatus: evidence.StatusSkipped,
		},
		{
			name:       "a blocked one first: the app asks it, so no lookup is made",
			resolv:     "nameserver 169.254.169.253\nnameserver 10.0.0.2\n",
			wantStatus: evidence.StatusSkipped,
		},
		{
			name:       "a blocked one second",
			resolv:     "nameserver 10.0.0.2\nnameserver 169.254.169.253\n",
			wantStatus: evidence.StatusOK,
			wantServer: "10.0.0.2:53",
			wantNote:   "nameserver 2 of",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp, hp := writeFiles(t, tt.resolv+"options ndots:0\n", "")
			f := &fakeDNS{answers: map[string]string{"api. A": "172.22.0.3"}}
			r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}
			ev := r.Lookup(context.Background(), "api")
			if ev.Status != tt.wantStatus {
				t.Fatalf("status %s, err %+v", ev.Status, ev.Err)
			}
			for _, q := range f.queries {
				if strings.Contains(q, "169.254.") || strings.Contains(q, "fe80") || strings.Contains(q, "fd00:ec2") {
					t.Errorf("queried a blocked nameserver: %q", q)
				}
			}
			if tt.wantStatus == evidence.StatusSkipped {
				if ev.Err == nil || ev.Err.Code != evidence.CodePolicyDenied || !strings.Contains(ev.Err.Message, "block list") {
					t.Errorf("err = %+v, want a policy refusal naming the block list", ev.Err)
				}
				if len(f.queries) != 0 {
					t.Errorf("sent %v", f.queries)
				}
				return
			}
			if p := ev.Data.(evidence.DNSProbe); p.Server != tt.wantServer {
				t.Errorf("server %q, want %q", p.Server, tt.wantServer)
			}
			if !strings.Contains(strings.Join(ev.Limitations, "\n"), tt.wantNote) {
				t.Errorf("limitations %q lack %q", ev.Limitations, tt.wantNote)
			}
		})
	}
}

// Like the app's resolver, a lookup uses only the first three nameservers:
// skipping blocked ones mustn't bring a fourth into play.
func TestLookupUsesThreeNameservers(t *testing.T) {
	rp, hp := writeFiles(t, "nameserver 10.0.0.1\nnameserver 169.254.169.253\nnameserver 169.254.169.252\nnameserver 10.0.0.4\noptions ndots:0\n", "")
	f := &fakeDNS{refuse: "10.0.0.1:53"}
	r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}
	r.Lookup(context.Background(), "api")
	for _, q := range f.queries {
		if strings.HasSuffix(q, "10.0.0.4:53") {
			t.Errorf("asked a fourth nameserver: %v", f.queries)
		}
	}
}

// The C library asks the nameservers in order and moves on when one fails:
// when the next one is blocked, a failed lookup isn't the app's, so it is
// refused (after the queries to the servers before it), and an answer that
// ends the app's lookup stands.
func TestLookupStopsBeforeBlockedNameserver(t *testing.T) {
	tests := []struct {
		name    string
		resolv  string
		answers map[string]string
		refuse  string
		want    evidence.Status
		rcode   string
	}{
		{"the first refuses the connection", "nameserver 10.8.0.1\nnameserver 169.254.169.254\n", nil, "10.8.0.1:53", evidence.StatusSkipped, ""},
		{"the first answers SERVFAIL", "nameserver 10.8.0.1\nnameserver 169.254.169.254\n", map[string]string{"api. A": "SERVFAIL", "api. AAAA": "SERVFAIL"}, "", evidence.StatusSkipped, ""},
		{"the first answers NXDOMAIN: the app stops there", "nameserver 10.8.0.1\nnameserver 169.254.169.254\n", nil, "", evidence.StatusOK, "NXDOMAIN"},
		{"the first answers", "nameserver 10.8.0.1\nnameserver 169.254.169.254\n", map[string]string{"api. A": "172.22.0.3"}, "", evidence.StatusOK, "NOERROR"},
		{"an allowed one after the blocked one isn't used", "nameserver 10.8.0.1\nnameserver 169.254.169.254\nnameserver 10.8.0.3\n", nil, "10.8.0.1:53", evidence.StatusSkipped, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp, hp := writeFiles(t, tt.resolv+"options ndots:0\n", "")
			f := &fakeDNS{answers: tt.answers, refuse: tt.refuse}
			r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}
			ev := r.Lookup(context.Background(), "api")
			if ev.Status != tt.want {
				t.Fatalf("status %s, err %+v", ev.Status, ev.Err)
			}
			for _, q := range f.queries {
				if !strings.HasSuffix(q, " 10.8.0.1:53") {
					t.Errorf("queried %q", q)
				}
			}
			p := ev.Data.(evidence.DNSProbe)
			if tt.want == evidence.StatusSkipped {
				if ev.Err == nil || ev.Err.Code != evidence.CodePolicyDenied || !strings.Contains(ev.Err.Message, "would then ask 169.254.169.254") {
					t.Errorf("err = %+v", ev.Err)
				}
				if len(p.Attempts) == 0 {
					t.Error("the refusal lost the queries it made")
				}
				return
			}
			if p.Rcode != tt.rcode {
				t.Errorf("rcode %s, want %s", p.Rcode, tt.rcode)
			}
		})
	}
}

// glibc and musl read a nameserver address with inet_aton(3): the forms
// Go's parser rejects must still count, in their place.
func TestNameserverFormsOfTheCLibrary(t *testing.T) {
	for _, form := range []string{"0xa9fea9fe", "0251.0376.0251.0376", "169.254.43518", "2852039166", "0xA9.0xFE.0xa9.0376"} {
		rp, hp := writeFiles(t, "nameserver "+form+" # metadata\nnameserver 10.0.0.2\noptions ndots:0\n", "")
		f := &fakeDNS{answers: map[string]string{"api. A": "172.22.0.3"}}
		r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}
		ev := r.Lookup(context.Background(), "api")
		if ev.Status != evidence.StatusSkipped || len(f.queries) != 0 {
			t.Errorf("%s: status %s, sent %v; want the first-nameserver refusal", form, ev.Status, f.queries)
		}
	}
	for s, want := range map[string]string{
		"010.0.0.1": "8.0.0.1", "1.2.3": "1.2.0.3", "1.2": "1.0.0.2", "0x7f.1": "127.0.0.1", "10.0.0.1": "10.0.0.1",
		"fe80::1%eth0": "fe80::1%eth0", "::ffff:10.0.0.1": "::ffff:10.0.0.1",
		"08.1.1.1": "", "0x": "", "1.2.3.4.5": "", "256.1.1.1": "", "1.2.65536": "", "1..2": "", "-1": "", "10.0.0.1#x": "", "4294967296": "",
	} {
		a, ok := parseNameserver(s)
		if got := map[bool]string{true: a.String(), false: ""}[ok]; got != want {
			t.Errorf("parseNameserver(%q) = %q, want %q", s, got, want)
		}
	}
}

// A lookup that couldn't be made because of its nameservers isn't one to
// ask the user about: the refusal names the nameserver, not the name.
func TestBlockedNameserverComesBeforeTheName(t *testing.T) {
	rp, hp := writeFiles(t, "nameserver 169.254.169.254\n", "")
	r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: (&fakeDNS{}).exchange}
	ev := r.lookupWithin(context.Background(), "example.com", Limits{NamesRestricted: true})
	if ev.Err == nil || ev.Err.Message == NameNotApproved || !strings.Contains(ev.Err.Message, "block list") {
		t.Errorf("err = %+v, want the nameserver refusal", ev.Err)
	}
}

func TestNamesFlagRoundTrip(t *testing.T) {
	l := Limits{NamesRestricted: true, Names: []string{"example.com", "api.internal"}}
	got, err := ParseNames(l.NamesFlag())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(l.Names, got); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
	if got, err := ParseNames(""); err != nil || len(got) != 0 {
		t.Errorf("empty flag: %v, %v", got, err)
	}
	if _, err := ParseNames("example.com,a b"); err == nil {
		t.Error("ParseNames accepted a malformed name")
	}
}

func TestCheckName(t *testing.T) {
	l := Limits{NamesRestricted: true, Names: []string{"example.com"}}
	for name, want := range map[string]bool{
		"example.com": true, "EXAMPLE.com.": true, "api.example.com": false, "api": true,
		"localhost": true, "gateway.docker.internal": true, "10.1.2.3": true,
	} {
		if _, ok := l.CheckName(name); ok != want {
			t.Errorf("CheckName(%q) = %v, want %v", name, ok, want)
		}
	}
	if _, ok := (Limits{}).CheckName("anything.example"); !ok {
		t.Error("unrestricted limits refused a name")
	}
}

func TestFirstNameserverBlocked(t *testing.T) {
	for resolv, want := range map[string]bool{
		"nameserver 169.254.169.254\nnameserver 10.0.0.2\n": true,
		"nameserver 10.0.0.2\nnameserver 169.254.169.254\n": false,
		"nameserver 127.0.0.53\n":                           false,
	} {
		rp, _ := writeFiles(t, resolv, "")
		if _, got, err := FirstNameserverBlocked(rp); err != nil || got != want {
			t.Errorf("%q: %v, %v; want %v", resolv, got, err, want)
		}
	}
}

// Docker gives default-bridge containers systemd-resolved's upstreams when
// the host's resolv.conf lists only its stub, as doctor must check.
func TestDockerResolvConf(t *testing.T) {
	for resolv, stub := range map[string]bool{
		"nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n": true,
		"nameserver 127.0.0.53\nnameserver 10.0.0.2\n":              false,
		"nameserver 10.0.0.2\n":                                     false,
	} {
		rp, _ := writeFiles(t, resolv, "")
		want := rp
		if stub {
			want = "/run/systemd/resolve/resolv.conf"
		}
		if got := DockerResolvConf(rp, "/run/systemd/resolve/resolv.conf"); got != want {
			t.Errorf("%q: %s, want %s", resolv, got, want)
		}
	}
	if got := DockerResolvConf("/nonexistent/resolv.conf", "/run/systemd/resolve/resolv.conf"); got != "/nonexistent/resolv.conf" {
		t.Errorf("a missing file: %s", got)
	}
}
