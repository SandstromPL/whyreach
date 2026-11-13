package target

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

func TestParseFrom(t *testing.T) {
	tests := []struct {
		in      string
		want    From
		wantErr bool
	}{
		{"", From{Kind: FromHost}, false},
		{"host", From{Kind: FromHost}, false},
		{"container:worker", From{Kind: FromContainer, Name: "worker"}, false},
		{"container:/shop-worker-1", From{Kind: FromContainer, Name: "shop-worker-1"}, false},
		{"container:a3d380d0831a", From{Kind: FromContainer, Name: "a3d380d0831a"}, false},
		{"service:worker", From{Kind: FromService, Name: "worker"}, false},
		{"service:worker@shop", From{Kind: FromService, Name: "worker", Project: "shop"}, false},
		{" container:worker ", From{Kind: FromContainer, Name: "worker"}, false},
		{"worker", From{}, true},
		{"container:", From{}, true},
		{"container:../x", From{}, true},
		{"container:a/b", From{}, true},
		{"service:worker@Shop", From{}, true},
		{"pod:worker", From{}, true},
	}
	for _, tt := range tests {
		got, err := ParseFrom(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseFrom(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseFrom(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
		if err == nil {
			again, err := ParseFrom(got.String())
			if err != nil || again != got {
				t.Errorf("ParseFrom(%q.String() = %q) = %+v, %v; want a round trip", tt.in, got.String(), again, err)
			}
		}
	}
}

func TestParseTo(t *testing.T) {
	tests := []struct {
		in    string
		host  string
		port  uint16
		class string
	}{
		{"api:8080", "api", 8080, evidence.TargetName},
		{"API:8080", "api", 8080, evidence.TargetName},
		{"tcp://api:8080", "api", 8080, evidence.TargetName},
		{"TCP://db.internal.example:5432", "db.internal.example", 5432, evidence.TargetName},
		{"shop_api_1:80", "shop_api_1", 80, evidence.TargetName},
		{"host.docker.internal:5432", "host.docker.internal", 5432, evidence.TargetName},
		{"localhost:8080", "localhost", 8080, evidence.TargetLoopback},
		{"127.0.0.1:8080", "127.0.0.1", 8080, evidence.TargetLoopback},
		{"[::1]:8080", "::1", 8080, evidence.TargetLoopback},
		{"172.22.0.3:8080", "172.22.0.3", 8080, evidence.TargetIP},
		{"[fd00::3]:443", "fd00::3", 443, evidence.TargetIP},
		{"[::ffff:10.0.0.1]:80", "10.0.0.1", 80, evidence.TargetIP},
		{"api:65535", "api", 65535, evidence.TargetName},
	}
	for _, tt := range tests {
		got, err := ParseTo(tt.in)
		if err != nil {
			t.Errorf("ParseTo(%q): %v", tt.in, err)
			continue
		}
		if got.Host != tt.host || got.Port != tt.port || got.Class != tt.class || got.Proto != "tcp" {
			t.Errorf("ParseTo(%q) = %+v, want host %q port %d class %s", tt.in, got, tt.host, tt.port, tt.class)
		}
	}
}

func TestParseToRejects(t *testing.T) {
	tests := []struct {
		in     string
		policy bool
	}{
		{"", false},
		{"api", false},
		{"api:", false},
		{"api:0", false},
		{"api:65536", false},
		{"api:http", false},
		{"api:8080-8090", false},
		{"10.0.0.0/24:80", false},
		{"10.0.0.1:80,10.0.0.2:80", false},
		{"api:80 db:80", false},
		{"*:80", false},
		{"api?:80", false},
		{"user:pass@api:80", false},
		{"udp://api:53", false},
		{"http://api:80", false},
		{"tcp://api:80/path", false},
		{"::1:80", false},
		{"[fe80::1%eth0]:80", false},
		{"-api:80", false},
		{"a..b:80", false},
		{"169.254.169.254:80", true},
		{"169.254.1.1:443", true},
		{"[fe80::1]:80", true},
		{"[fd00:ec2::254]:80", true},
		{"100.100.100.200:80", true},
		{"[::ffff:169.254.169.254]:80", true},
		{"224.0.0.1:80", true},
		{"255.255.255.255:80", true},
	}
	for _, tt := range tests {
		_, err := ParseTo(tt.in)
		var te *Error
		if !errors.As(err, &te) {
			t.Errorf("ParseTo(%q) error = %v, want a *target.Error", tt.in, err)
			continue
		}
		if te.Policy != tt.policy {
			t.Errorf("ParseTo(%q) policy = %v, want %v (%v)", tt.in, te.Policy, tt.policy, err)
		}
	}
}

func TestBlocked(t *testing.T) {
	for _, s := range []string{"169.254.169.254", "fe80::1", "fd00:ec2::254", "100.100.100.200", "::ffff:169.254.0.1"} {
		if _, blocked := Blocked(netip.MustParseAddr(s)); !blocked {
			t.Errorf("Blocked(%s) = false, want true", s)
		}
	}
	for _, s := range []string{"127.0.0.1", "::1", "172.22.0.3", "10.1.2.3", "192.168.1.1", "1.1.1.1", "100.100.100.201"} {
		if reason, blocked := Blocked(netip.MustParseAddr(s)); blocked {
			t.Errorf("Blocked(%s) = true (%s), want false", s, reason)
		}
	}
}

func TestParseScope(t *testing.T) {
	good := map[string]string{
		"host":                  "host",
		" container:api ":       "container:api",
		"service:worker@shop":   "service:worker@shop",
		"network:shop_default":  "network:shop_default",
		"network:c8b1ea434516":  "network:c8b1ea434516",
		"container:/shop-api-1": "container:shop-api-1",
	}
	for in, want := range good {
		s, err := ParseScope(in)
		if err != nil || s.String() != want {
			t.Errorf("ParseScope(%q) = %v, %v; want %s", in, s, err, want)
		}
	}
	for _, in := range []string{"", "pod:x", "network:", "network:a b", "container:", "volume:x"} {
		if _, err := ParseScope(in); err == nil {
			t.Errorf("ParseScope(%q) succeeded", in)
		}
	}
}

func TestParseName(t *testing.T) {
	good := map[string]string{"api": "api", "Example.COM.": "example.com", "::ffff:10.0.0.1": "10.0.0.1", "host.docker.internal": "host.docker.internal"}
	for in, want := range good {
		if got, err := ParseName(in); err != nil || got != want {
			t.Errorf("ParseName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "api:8080", "http://api", "*.example.com", "a b"} {
		if _, err := ParseName(in); err == nil {
			t.Errorf("ParseName(%q) succeeded", in)
		}
	}
}

func TestAddressRanges(t *testing.T) {
	ranges := []string{"10.0.0.1-5", "10.0.0-3.1", "10.0.0.1-10.0.0.5", "192.168.1.1-254.", "[fd00::1-5]"}
	for _, in := range ranges {
		var te *Error
		if _, err := ParseTo(in + ":80"); !errors.As(err, &te) || !strings.Contains(te.Reason, "address ranges") {
			t.Errorf("ParseTo(%q) error = %v, want an address-range refusal", in+":80", err)
		}
		name := strings.Trim(in, "[]")
		if _, err := ParseName(name); !errors.As(err, &te) || !strings.Contains(te.Reason, "address ranges") {
			t.Errorf("ParseName(%q) error = %v, want an address-range refusal", name, err)
		}
	}
	// Hyphens in names that aren't address-shaped stay names.
	for _, in := range []string{"shop-api-1", "api-1.example.com", "10-0-0-1.nip.io", "1-2"} {
		if _, err := ParseTo(in + ":80"); err != nil {
			t.Errorf("ParseTo(%q): %v", in+":80", err)
		}
		if _, err := ParseName(in); err != nil {
			t.Errorf("ParseName(%q): %v", in, err)
		}
	}
	// Malformed hosts keep their own message.
	for _, in := range []string{"-10.0.0.1:80", "10.0.0.1-:80"} {
		var te *Error
		if _, err := ParseTo(in); !errors.As(err, &te) || strings.Contains(te.Reason, "address ranges") {
			t.Errorf("ParseTo(%q) error = %v, want a refusal that isn't about ranges", in, err)
		}
	}
}

func TestMaskArg(t *testing.T) {
	tests := []struct{ arg, in, want string }{
		{"to", "postgres://app:s3cr3t@db:5432/app?sslpassword=x", "postgres://***@db:5432/app?***"},
		{"to", "tcp://admin:hunter2@db:5432", "tcp://***@db:5432"},
		{"to", "admin:hunter2@db:5432", "***@db:5432"},
		{"to", "api:8080", "api:8080"},
		{"target", "u:p@api", "***@api"},
		{"from", "service:api@shop", "service:api@shop"},
		{"from", "container:u:pw@x", "***@x"},
		{"scope", "service:api@shop", "service:api@shop"},
		{"error", "want host:port?", "want host:port?"},
		{"from", "http://u:p@x", "http://***@x"},
		{"scope", "network:shop_default", "network:shop_default"},
	}
	for _, tt := range tests {
		if got := MaskArg(tt.arg, tt.in); got != tt.want {
			t.Errorf("MaskArg(%q, %q) = %q, want %q", tt.arg, tt.in, got, tt.want)
		}
	}
	_, err := ParseTo("tcp://admin:hunter2@db:5432")
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("ParseTo's error repeats the password: %v", err)
	}
}

func TestParseToCapsNames(t *testing.T) {
	long := strings.Repeat("a.", 127) + "ab" // 256 characters
	if _, err := ParseTo(long + ":80"); err == nil {
		t.Error("a 256-character name was accepted")
	}
}
