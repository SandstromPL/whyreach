package engine

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// A held-back connect's gap names the setting and what an approval covers;
// a refused nameserver's gap says why the host-resolver exception didn't
// apply (INITIAL.md §10 Q13, Q15).
func TestApprovalAdvice(t *testing.T) {
	r := &run{e: New(Deps{ConfigPath: "/cfg/config.toml"})}
	held := evidence.Evidence{Kind: evidence.KindTCP, Status: evidence.StatusSkipped,
		Err: &evidence.Error{Code: evidence.CodePolicyDenied, Message: probe.AddrNotApproved}}
	got := r.howToEnable(held)
	for _, want := range []string{"allow under [probe] in /cfg/config.toml", fmt.Sprintf("covers %d connects", probe.ApprovalBudget), "not an agent's"} {
		if !strings.Contains(got, want) {
			t.Errorf("held-back connect: %q lacks %q", got, want)
		}
	}
	name := evidence.Evidence{Kind: evidence.KindDNS, Status: evidence.StatusSkipped,
		Err: &evidence.Error{Code: evidence.CodePolicyDenied, Message: probe.NameNotApproved}}
	if got := r.howToEnable(name); !strings.Contains(got, fmt.Sprintf("covers %d lookups", probe.ApprovalBudget)) {
		t.Errorf("held-back name: %q", got)
	}
	ns := evidence.Evidence{Kind: evidence.KindDNS, Status: evidence.StatusSkipped, Err: &evidence.Error{Code: evidence.CodePolicyDenied,
		Message: "not looked up: the first nameserver in /etc/resolv.conf, 169.254.1.1, which the app asks first, is on the probe block list (link-local and cloud-metadata addresses), which whyreach asks only when it is one of the host's own resolvers"}}
	if got := r.howToEnable(ns); !strings.Contains(got, "only when it is one of the host's own resolvers") || !strings.Contains(got, "dns:") {
		t.Errorf("refused nameserver: %q", got)
	}
}

// A lookup through one of the host's resolvers on the block list says so in
// the facts.
func TestHostResolverFact(t *testing.T) {
	q := evidence.Question{From: evidence.Source{Kind: evidence.SourceHost, Ref: "host"}, To: evidence.Target{Host: "api.example", Port: 443, Proto: "tcp", Class: evidence.TargetName}}
	lookup := func(host bool) evidence.Evidence {
		return evidence.Evidence{ID: "ev-01", Kind: evidence.KindDNS, Context: evidence.Host(), Subject: "api.example", Status: evidence.StatusOK,
			Data: evidence.DNSProbe{Name: "api.example", Via: evidence.ViaDNS, Server: "169.254.169.254:53", Answers: []netip.Addr{netip.MustParseAddr("10.9.9.9")}, HostResolver: host}}
	}
	for _, host := range []bool{true, false} {
		var text []string
		for _, f := range facts(evidence.NewView(q, []evidence.Evidence{lookup(host)}), true) {
			text = append(text, f.Text)
		}
		if got := strings.Contains(strings.Join(text, "\n"), "the host's own resolver"); got != host {
			t.Errorf("host_resolver %v: facts %q", host, text)
		}
	}
}
