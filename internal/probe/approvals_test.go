package probe

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// A nameserver on the block list is asked when it is one of the host's own
// resolvers, for DNS only; one that only the container's resolv.conf names
// stays refused (INITIAL.md §10 Q13).
func TestHostResolverOnTheBlockList(t *testing.T) {
	tests := []struct {
		name     string
		resolv   string
		host     []string
		refuse   string
		want     evidence.Status
		answered string // the blocked host resolver whose answer was used
	}{
		{"GCE's resolver, the host's own", "nameserver 169.254.169.254\n", []string{"169.254.169.254"}, "", evidence.StatusOK, "169.254.169.254:53"},
		{"GCE's IPv6 one, the host's own", "nameserver fd20:ce::254\n", []string{"fd20:ce::254"}, "", evidence.StatusOK, "[fd20:ce::254]:53"},
		{"in an inet_aton form", "nameserver 0xa9fea9fe\n", []string{"169.254.169.254"}, "", evidence.StatusOK, "169.254.169.254:53"},
		{"only the container names it", "nameserver 169.254.169.254\n", []string{"10.0.0.2"}, "", evidence.StatusSkipped, ""},
		{"the host's resolvers unknown", "nameserver 169.254.169.254\n", nil, "", evidence.StatusSkipped, ""},
		{"the host's, after one that fails", "nameserver 10.0.0.2\nnameserver 169.254.169.254\n", []string{"169.254.169.254"}, "10.0.0.2:53", evidence.StatusOK, "169.254.169.254:53"},
		{"the host's, listed second, unused", "nameserver 10.0.0.2\nnameserver 169.254.169.254\n", []string{"169.254.169.254"}, "", evidence.StatusOK, ""},
		{"a link-local one on the container's own link", "nameserver fe80::1%eth0\n", []string{"fe80::1%wlan0"}, "", evidence.StatusSkipped, ""},
		{"a link-local one, the host's own link", "nameserver fe80::1%eth0\n", []string{"fe80::1%eth0"}, "", evidence.StatusOK, "[fe80::1%eth0]:53"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp, hp := writeFiles(t, tt.resolv+"options ndots:0\n", "")
			f := &fakeDNS{answers: map[string]string{"api. A": "172.22.0.3"}, refuse: tt.refuse}
			r := &Resolver{HostsPath: hp, ResolvPath: rp, Exchange: f.exchange}
			var lim Limits
			for _, h := range tt.host {
				lim.HostResolvers = append(lim.HostResolvers, netip.MustParseAddr(h))
			}
			ev := r.lookupWithin(context.Background(), nil, "api", lim)
			if ev.Status != tt.want {
				t.Fatalf("status %s, err %+v", ev.Status, ev.Err)
			}
			p := ev.Data.(evidence.DNSProbe)
			if tt.want == evidence.StatusSkipped {
				if ev.Err == nil || ev.Err.Code != evidence.CodePolicyDenied || !strings.Contains(ev.Err.Message, "block list") || len(f.queries) != 0 {
					t.Errorf("err %+v, sent %v; want a refusal that sends nothing", ev.Err, f.queries)
				}
				if p.HostResolver != "" {
					t.Error("a refused lookup says it used the host's resolver")
				}
				return
			}
			if p.HostResolver != tt.answered || !strings.Contains(strings.Join(ev.Limitations, "\n"), "one of the host's own resolvers") {
				t.Errorf("host_resolver %q, want %q; limitations %q", p.HostResolver, tt.answered, ev.Limitations)
			}
		})
	}
}

// The exception is for DNS: a connect to the host's resolver stays blocked.
func TestHostResolverIsNoConnectTarget(t *testing.T) {
	lim := Limits{HostResolvers: []netip.Addr{netip.MustParseAddr("169.254.169.254")}}
	for _, ap := range []string{"169.254.169.254:53", "169.254.169.254:80"} {
		if _, ok := lim.CheckConnect(netip.MustParseAddrPort(ap)); ok {
			t.Errorf("a connect to %s was allowed", ap)
		}
		ev := Dial(context.Background(), ap, netip.MustParseAddrPort(ap), evidence.ViaLiteral, lim)
		if ev.Status != evidence.StatusSkipped || ev.Err == nil || ev.Err.Code != evidence.CodePolicyDenied {
			t.Errorf("dial %s: %s %+v", ap, ev.Status, ev.Err)
		}
	}
}

// Through MCP, a private address that only the rfc1918 class admits needs
// the user's approval of that address and port; Docker's networks, the
// host's own addresses and explicit allowlist entries don't (INITIAL.md
// §10 Q15).
func TestPrivateAddressesNeedApproval(t *testing.T) {
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	rfc1918 := pfx("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	lim := Limits{
		Restricted: true, Allow: append(pfx("127.0.0.0/8", "::1/128", "10.20.0.0/16", "172.17.0.0/16"), rfc1918...),
		AddrsRestricted: true, Private: rfc1918,
		Free:     pfx("172.17.0.0/16", "192.168.1.10/32", "10.20.0.0/16"),
		Approved: []netip.AddrPort{netip.MustParseAddrPort("10.0.5.7:5432")},
	}
	for ap, want := range map[string]string{
		"10.0.5.7:5432":       "",              // approved
		"10.0.5.7:80":         AddrNotApproved, // another port
		"10.0.5.8:5432":       AddrNotApproved, // another address
		"172.17.0.3:80":       "",              // Docker's network
		"192.168.1.10:8080":   "",              // the host's own address
		"192.168.1.11:8080":   AddrNotApproved, // its neighbour on the LAN
		"10.20.3.4:80":        "",              // an explicit allowlist entry
		"127.0.0.1:80":        "",              // loopback isn't private
		"[::ffff:10.0.5.8]:1": AddrNotApproved, // mapped forms count as the address
		"8.8.8.8:53":          "outside the probe allowlist",
	} {
		reason, ok := lim.CheckConnect(netip.MustParseAddrPort(ap))
		switch {
		case want == "" && !ok:
			t.Errorf("%s refused: %s", ap, reason)
		case want != "" && (ok || !strings.Contains(reason, want)):
			t.Errorf("%s: %q, %v; want %q", ap, reason, ok, want)
		}
	}
	lim.AddrsRestricted = false // the CLI
	if _, ok := lim.CheckConnect(netip.MustParseAddrPort("10.0.5.8:5432")); !ok {
		t.Error("without the restriction a private address needs approval")
	}
}

// limitsFromArgs decodes ProbeArgs's output as `whyreach __probe` does: a
// flag is changed when it is given, even with an empty value.
func limitsFromArgs(t *testing.T, args []string) (Limits, error) {
	t.Helper()
	if len(args)%2 != 0 {
		t.Fatalf("arguments %q are not flag and value pairs", args)
	}
	given := map[string]string{}
	for i := 0; i < len(args); i += 2 {
		name, ok := strings.CutPrefix(args[i], "--")
		if !ok {
			t.Fatalf("argument %q is not a flag", args[i])
		}
		given[name] = args[i+1]
	}
	changed := func(name string) bool { _, ok := given[name]; return ok }
	return LimitsFromFlags(changed, func(name string) string { return given[name] })
}

// TestProbeArgsRoundTrip: the limits reach the probe container whole, and a
// restriction that doesn't apply gives no flag, which means none there.
func TestProbeArgsRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		lim      Limits
		wantArgs int
	}{
		{"every limit", Limits{
			Restricted:      true,
			Allow:           []netip.Prefix{netip.MustParsePrefix("172.22.0.0/16"), netip.MustParsePrefix("fd00::/8")},
			NamesRestricted: true,
			Names:           []string{"example.com", "api.internal"},
			HostResolvers:   []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd20:ce::254")},
			AddrsRestricted: true,
			Private:         []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			Free:            []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16"), netip.MustParsePrefix("10.0.0.1/32")},
			Approved:        []netip.AddrPort{netip.MustParseAddrPort("10.0.5.7:5432"), netip.MustParseAddrPort("[fd00::7]:443")},
		}, 12},
		{"none", Limits{}, 0},
		{"restricted to nothing", Limits{Restricted: true, NamesRestricted: true, AddrsRestricted: true}, 10},
		{"only the host's resolvers", Limits{HostResolvers: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.lim.ProbeArgs()
			if len(args) != tt.wantArgs {
				t.Errorf("args %q, want %d", args, tt.wantArgs)
			}
			got, err := limitsFromArgs(t, args)
			if err != nil {
				t.Fatalf("%q: %v", args, err)
			}
			if diff := cmp.Diff(tt.lim, got, cmpopts.IgnoreUnexported(Limits{}), cmpopts.EquateComparable(netip.Addr{}, netip.Prefix{}, netip.AddrPort{})); diff != "" {
				t.Errorf("%q (-want +got):\n%s", args, diff)
			}
		})
	}
	for _, bad := range [][]string{
		{"--allow", "10.0.0.0/33"},
		{"--names", "example.com,a b"},
		{"--host-resolvers", "10.0.0.300"},
		{"--private", "10.0.0.0/8", "--free", "", "--approved", "10.0.0.1"},
	} {
		if _, err := limitsFromArgs(t, bad); err == nil {
			t.Errorf("%q: decoded without an error", bad)
		}
	}
}

func TestNameserversOfTheHost(t *testing.T) {
	a, _ := writeFiles(t, "nameserver 127.0.0.53\noptions edns0\n", "")
	b, _ := writeFiles(t, "nameserver 169.254.169.254\nnameserver 0x0a000002\nnameserver 127.0.0.53\n", "")
	got := Nameservers(a, b, "/nonexistent/resolv.conf")
	want := []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("10.0.0.2")}
	if diff := cmp.Diff(want, got, cmp.Comparer(func(x, y netip.Addr) bool { return x == y })); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
}

// A batch makes no more connects to an approved address than the policy set
// aside for it: each takes one. Loopback stands in for a private address.
func TestApprovedConnectsAreCounted(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	env := Env{ProcDir: "/proc", Limits: Limits{
		AddrsRestricted: true, Private: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Approved: []netip.AddrPort{ap}, // one connect
	}}
	spec := Spec{Kind: SpecTCP, Host: ap.Addr().String(), Port: ap.Port()}
	evs := Run(context.Background(), env, []Spec{spec, spec, spec})
	var made, refused int
	for _, e := range evs {
		switch {
		case e.Status == evidence.StatusOK:
			made++
		case e.Err != nil && e.Err.Message == AddrNotApproved:
			refused++
		}
	}
	if made != 1 || refused != 2 {
		t.Errorf("made %d connects and refused %d; want 1 and 2: %+v", made, refused, evs)
	}
	// Without the batch's count (a Dial outside Run), an approved address
	// isn't dialed.
	if ev := Dial(context.Background(), spec.Host, ap, evidence.ViaLiteral, env.Limits); ev.Err == nil || ev.Err.Message != AddrNotApproved {
		t.Errorf("Dial outside a batch: %s %+v", ev.Status, ev.Err)
	}
}
