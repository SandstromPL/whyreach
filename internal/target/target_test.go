package target

import (
	"errors"
	"net/netip"
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
