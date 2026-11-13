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
			wantNote:   "skipped nameserver 2 of",
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
