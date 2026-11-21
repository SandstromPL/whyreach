package probe

import (
	"context"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

func TestDNSSpecTakesIPv6Literals(t *testing.T) {
	if err := (Spec{Kind: SpecDNS, Host: "2001:db8::1"}).Validate(); err != nil {
		t.Errorf("an IPv6 literal for a dns spec: %v", err)
	}
}

// TestInvalidSpecsKeepTheirSubject: a refused spec's record names its check
// the way a valid one's does (a lookup by its name, listeners as
// "listeners"), not as host:port.
func TestInvalidSpecsKeepTheirSubject(t *testing.T) {
	tests := []struct {
		spec        Spec
		wantKind    evidence.Kind
		wantSubject string
	}{
		{Spec{Kind: SpecDNS, Host: "api", Port: 53}, evidence.KindDNS, "api"},
		{Spec{Kind: SpecDNS, Host: "bad name!"}, evidence.KindDNS, "bad name!"},
		{Spec{Kind: SpecListeners, Host: "api"}, evidence.KindListeners, "listeners"},
		{Spec{Kind: SpecTCP, Host: "::1", Port: 0}, evidence.KindTCP, "[::1]:0"},
		{Spec{Kind: SpecTCP, Host: "api", Port: 80, Via: "elsewhere"}, evidence.KindTCP, "api:80"},
	}
	for _, tt := range tests {
		evs := Run(context.Background(), DefaultEnv(), []Spec{tt.spec})
		if len(evs) != 1 {
			t.Fatalf("%+v: %d records, want 1", tt.spec, len(evs))
		}
		ev := evs[0]
		if ev.Kind != tt.wantKind || ev.Subject != tt.wantSubject || ev.Status != evidence.StatusError {
			t.Errorf("%+v: %s %q %s, want an error record %s %q", tt.spec, ev.Kind, ev.Subject, ev.Status, tt.wantKind, tt.wantSubject)
		}
	}
}
