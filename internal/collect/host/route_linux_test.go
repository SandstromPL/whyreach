//go:build linux

package host

import (
	"encoding/binary"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// samePrefix lets go-cmp compare netip values, which have unexported fields.
var samePrefix = cmp.Comparer(func(a, b netip.Prefix) bool { return a == b })

func TestGetRouteRequest(t *testing.T) {
	b := getRouteRequest(netip.MustParseAddr("10.8.1.5"), 7)
	ne := binary.NativeEndian
	if got := int(ne.Uint32(b[0:4])); got != len(b) || got != syscall.NLMSG_HDRLEN+syscall.SizeofRtMsg+8 {
		t.Fatalf("length %d (buffer %d)", got, len(b))
	}
	if ne.Uint16(b[4:6]) != syscall.RTM_GETROUTE || ne.Uint16(b[6:8]) != syscall.NLM_F_REQUEST || ne.Uint32(b[8:12]) != 7 {
		t.Errorf("header %x", b[:16])
	}
	rt := b[syscall.NLMSG_HDRLEN:]
	if rt[0] != syscall.AF_INET || rt[1] != 32 || ne.Uint32(rt[8:12]) != unix.RTM_F_FIB_MATCH|unix.RTM_F_LOOKUP_TABLE {
		t.Errorf("rtmsg %x", rt[:syscall.SizeofRtMsg])
	}
	at := rt[syscall.SizeofRtMsg:]
	if ne.Uint16(at[0:2]) != 8 || ne.Uint16(at[2:4]) != syscall.RTA_DST || string(at[4:8]) != string([]byte{10, 8, 1, 5}) {
		t.Errorf("attribute %x", at)
	}
}

// routeMsg builds an RTM_NEWROUTE message as the kernel sends one.
func routeMsg(family, dstLen, table, typ uint8, attrs ...[]byte) syscall.NetlinkMessage {
	data := make([]byte, syscall.SizeofRtMsg)
	data[0], data[1], data[4], data[7] = family, dstLen, table, typ
	for _, a := range attrs {
		data = append(data, a...)
	}
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWROUTE, Len: uint32(syscall.NLMSG_HDRLEN + len(data))}, Data: data}
}

func attr(typ uint16, v []byte) []byte {
	b := make([]byte, (syscall.SizeofRtAttr+len(v)+syscall.RTA_ALIGNTO-1)&^(syscall.RTA_ALIGNTO-1))
	binary.NativeEndian.PutUint16(b[0:2], uint16(syscall.SizeofRtAttr+len(v)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], v)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func TestParseRoute(t *testing.T) {
	tests := []struct {
		name string
		m    syscall.NetlinkMessage
		want evidence.Route
		typ  uint8
		oif  int
	}{
		{"main table, on loopback's index", routeMsg(syscall.AF_INET, 16, evidence.MainTable, unix.RTN_UNICAST,
			attr(syscall.RTA_DST, []byte{10, 8, 0, 0}), attr(syscall.RTA_OIF, u32(1))),
			evidence.Route{Prefix: netip.MustParsePrefix("10.8.0.0/16")}, unix.RTN_UNICAST, 1},
		{"a table above 255 travels in RTA_TABLE", routeMsg(syscall.AF_INET, 24, unix.RT_TABLE_COMPAT, unix.RTN_UNICAST,
			attr(syscall.RTA_DST, []byte{192, 168, 200, 0}), attr(unix.RTA_TABLE, u32(51820))),
			evidence.Route{Prefix: netip.MustParsePrefix("192.168.200.0/24"), Table: 51820}, unix.RTN_UNICAST, 0},
		{"a default route has no RTA_DST", routeMsg(syscall.AF_INET6, 0, evidence.MainTable, unix.RTN_UNICAST),
			evidence.Route{Prefix: netip.MustParsePrefix("::/0")}, unix.RTN_UNICAST, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, typ, oif, ok := parseRoute(&tt.m)
			if !ok || typ != tt.typ || oif != tt.oif {
				t.Fatalf("ok %v type %d interface %d", ok, typ, oif)
			}
			if diff := cmp.Diff(tt.want, got, samePrefix); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestDevName(t *testing.T) {
	for oif, want := range map[int]string{0: "", 1: "lo", 1 << 30: "if1073741824"} {
		if got := devName(oif); got != want {
			t.Errorf("devName(%d) = %q, want %q", oif, got, want)
		}
	}
}

// TestRouteLoopback asks this machine's kernel about 127.0.0.1, which any
// Linux host routes through lo: it needs no privilege and no setup.
func TestRouteLoopback(t *testing.T) {
	r, err := Route(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Chosen == nil || r.Chosen.Dev != "lo" {
		t.Errorf("chosen %+v, want a route through lo", r.Chosen)
	}
}

// TestRouteInNamespace runs Route against routes made up for the test in a
// new user and network namespace (unshare -Urn, no privilege): a bridge
// plays a Docker network and a veth plays a VPN tunnel. Nothing in the
// test's own namespace changes. It is skipped where unprivileged user
// namespaces aren't allowed.
func TestRouteInNamespace(t *testing.T) {
	if os.Getenv("WHYREACH_ROUTE_NETNS") == "" {
		if _, err := exec.LookPath("ip"); err != nil {
			t.Skip("no ip command")
		}
		if err := exec.CommandContext(t.Context(), "unshare", "-Urn", "true").Run(); err != nil {
			t.Skipf("no unprivileged network namespace here: %v", err)
		}
		cmd := exec.CommandContext(t.Context(), "unshare", "-Urn", os.Args[0], "-test.run=^TestRouteInNamespace$", "-test.v")
		cmd.Env = append(os.Environ(), "WHYREACH_ROUTE_NETNS=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("in the namespace: %v\n%s", err, out)
		}
		return
	}
	for _, args := range []string{
		"link set lo up",
		"link add br-test type bridge", "link set br-test up",
		"link add tun-test type veth peer name tun-peer", "link set tun-test up", "link set tun-peer up",
		"addr add 10.8.1.1/24 dev br-test", // a Docker network inside the VPN's range
		"addr add 10.99.0.2/30 dev tun-test",
		"route add 10.8.0.0/16 dev tun-test",
		"route add default dev tun-test",
		"addr add 192.168.200.1/24 dev br-test", // another, which a policy rule sends to the VPN's table
		"route add 192.168.200.0/24 dev tun-test table 51820",
		"rule add to 192.168.200.0/24 lookup 51820 pref 100",
	} {
		if out, err := exec.CommandContext(t.Context(), "ip", strings.Fields(args)...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v\n%s", args, err, out)
		}
	}
	route := func(p, dev string, table uint32) evidence.Route {
		return evidence.Route{Prefix: netip.MustParsePrefix(p), Dev: dev, Table: table}
	}
	tests := []struct {
		dst      string
		chosen   evidence.Route
		covering []evidence.Route
	}{
		// The more specific route wins: the Docker network's.
		{"10.8.1.5", route("10.8.1.0/24", "br-test", 0),
			[]evidence.Route{route("10.8.1.0/24", "br-test", 0), route("10.8.0.0/16", "tun-test", 0), route("0.0.0.0/0", "tun-test", 0)}},
		// Outside the Docker network, the VPN's.
		{"10.8.2.5", route("10.8.0.0/16", "tun-test", 0),
			[]evidence.Route{route("10.8.0.0/16", "tun-test", 0), route("0.0.0.0/0", "tun-test", 0)}},
		// A rule ahead of the main table wins over the bridge's own route.
		{"192.168.200.7", route("192.168.200.0/24", "tun-test", 51820),
			[]evidence.Route{route("192.168.200.0/24", "br-test", 0), route("192.168.200.0/24", "tun-test", 51820), route("0.0.0.0/0", "tun-test", 0)}},
	}
	for _, tt := range tests {
		r, err := Route(netip.MustParseAddr(tt.dst))
		if err != nil {
			t.Fatalf("%s: %v", tt.dst, err)
		}
		if r.Chosen == nil {
			t.Fatalf("%s: no route chosen", tt.dst)
		}
		if diff := cmp.Diff(tt.chosen, *r.Chosen, samePrefix); diff != "" {
			t.Errorf("%s: chosen (-want +got):\n%s", tt.dst, diff)
		}
		if diff := cmp.Diff(tt.covering, r.Covering, samePrefix); diff != "" {
			t.Errorf("%s: covering (-want +got):\n%s", tt.dst, diff)
		}
	}
	if r, err := Route(netip.MustParseAddr("203.0.113.9")); err != nil || r.Chosen == nil || r.Chosen.Dev != "tun-test" {
		t.Errorf("an address only the default route covers: %+v, %v", r, err)
	}
}
