package probe

import "testing"

func TestDNSSpecTakesIPv6Literals(t *testing.T) {
	if err := (Spec{Kind: SpecDNS, Host: "2001:db8::1"}).Validate(); err != nil {
		t.Errorf("an IPv6 literal for a dns spec: %v", err)
	}
}
