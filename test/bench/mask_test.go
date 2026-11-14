package bench

import (
	"net/netip"
	"strings"
	"testing"
)

func TestMasker(t *testing.T) {
	m := NewMasker()
	m.Literal("/home/jdoe", "home")
	m.Literal("jdoe", "user")
	m.Literal("jdoe-Laptop-X1", "hostname")
	m.Literal("corp.example.edu", "search")
	m.Literal("CorpVPN", "if")
	m.Literal("eth9", "if")
	m.Literal("shop_network_demo", "docker")
	m.DNSServer(netip.MustParseAddr("198.51.100.53"))
	m.DNSServer(netip.MustParseAddr("127.0.9.9"))
	m.Keep(netip.MustParsePrefix("172.18.0.0/16"))

	in := strings.Join([]string{
		"cwd /home/jdoe/Desktop/x, user jdoe on jdoe-Laptop-X1",
		"search corp.example.edu CORP.EXAMPLE.EDU",
		"nameserver 198.51.100.53 and 127.0.9.9 and ::ffff:127.0.9.9 and 127.0.0.53",
		"3: CorpVPN: <UP> mtu 1280; 2: eth9: link/ether 02:00:00:aa:bb:cc",
		"inet 203.0.113.42/24 and 172.18.0.3:8080 and 10.1.2.3 and 8.8.8.8 and 192.0.2.53",
		"inet6 2001:db8:abcd::1234/64 and fe80::1%eth0 and ::1 and [::]:8080",
		"network shop_network_demo; mail jdoe@corp.example.edu",
		"version 29.9.3 and 1.27.4, at 06:05:37, sha256:0123abcd",
	}, "\n")
	got := m.String(in)
	for _, private := range []string{"jdoe/", "jdoe on", "Laptop", "corp.example.edu", "CORP.EXAMPLE.EDU", "198.51.100.53", "127.0.9.9", "CorpVPN", "eth9", "02:00:00", "203.0.113.42", "10.1.2.3", "2001:db8", "fe80::1", "shop_network_demo", "@corp"} {
		if strings.Contains(got, private) {
			t.Errorf("%q still shows:\n%s", private, got)
		}
	}
	for _, kept := range []string{"127.0.0.53", "172.18.0.3:8080", "8.8.8.8", "192.0.2.53", "::1", "[::]:8080", "29.9.3", "1.27.4", "06:05:37", "sha256:0123abcd", "<home-1>/Desktop/x", "<user-1> on <hostname-1>", "<dns-1>", "<dns-2>", "::ffff:<dns-2>"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q should show:\n%s", kept, got)
		}
	}
	// The same value gets the same placeholder every time.
	if a, b := m.String("10.1.2.3"), m.String("x 10.1.2.3 y"); !strings.Contains(b, a) {
		t.Errorf("unstable placeholder: %q then %q", a, b)
	}
	if leaks := m.Leaks(got); len(leaks) != 0 {
		t.Errorf("Leaks after masking: %v\n%s", leaks, got)
	}
	if leaks := m.Leaks("contact JDOE-laptop-x1 now"); len(leaks) == 0 {
		t.Error("Leaks missed the host name")
	}
	// A longer word that holds a private value isn't masked, since it may
	// be another word; Leaks still reports it, so nothing is written.
	if got := m.String("jdoex"); got != "jdoex" {
		t.Errorf("masked inside a longer word: %q", got)
	}
	if leaks := m.Leaks("jdoex"); len(leaks) == 0 {
		t.Error("Leaks missed the user name inside a longer word")
	}
}
