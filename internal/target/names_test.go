package target

import (
	"strings"
	"testing"
)

func TestOutsideName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"Example.COM.", true},
		{"api.internal", true},
		{"data.attacker.example", true},
		{"a.b", true},
		{"api", false}, // no dot: the resolver and the user's own search domains only
		{"api.", false},
		{"shop-api-1", false},
		{"localhost", false},
		{"api.localhost", false},
		{"ip6-localhost", false},
		{"host.docker.internal", false},
		{"HOST.DOCKER.INTERNAL.", false},
		{"gateway.docker.internal", false},
		{"other.docker.internal", true},
		{"10.0.0.1", false},
		{"2001:db8::1", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := OutsideName(tt.name); got != tt.want {
			t.Errorf("OutsideName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCoveredBy(t *testing.T) {
	domains := []string{"example.com", "Corp.Example.", ""}
	tests := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"api.example.com", true},
		{"API.Example.Com.", true},
		{"badexample.com", false},
		{"example.com.evil", false},
		{"a.corp.example", true},
		{"example.org", false},
		{"com", false},
	}
	for _, tt := range tests {
		if got := CoveredBy(tt.name, domains); got != tt.want {
			t.Errorf("CoveredBy(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
	if CoveredBy("example.com", nil) {
		t.Error("no domains cover nothing")
	}
}

func TestParseNameCapsLength(t *testing.T) {
	long := strings.Repeat("a.", 127) + "com" // 257 characters
	if _, err := ParseName(long); err == nil {
		t.Fatal("ParseName accepted a 257-character name")
	}
	if _, err := ParseName(strings.Repeat("a", 60) + ".example.com"); err != nil {
		t.Fatal(err)
	}
}
