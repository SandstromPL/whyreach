//go:build linux

package host

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Route asks the kernel how whyreach's own network namespace (the host's
// when whyreach runs natively) routes dst: the routing table entry it picks
// (RTM_GETROUTE with RTM_F_FIB_MATCH, as `ip route get fibmatch` asks), and
// the unicast routes in any table whose prefix covers dst. The rest of the
// routing table is read to find those, and dropped. It sends no packet and
// needs no privilege.
func Route(dst netip.Addr) (evidence.HostRoute, error) {
	dst = dst.Unmap()
	out := evidence.HostRoute{Dst: dst}
	if !dst.IsValid() {
		return out, errors.New("no address to look up")
	}
	family := syscall.AF_INET
	if dst.Is6() {
		family = syscall.AF_INET6
	}
	chosen, err := routeGet(dst)
	switch {
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		// no route at all: Chosen stays nil
	case err != nil:
		return out, fmt.Errorf("route lookup for %s: %w", dst, err)
	default:
		out.Chosen = &chosen
	}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, family)
	if err != nil {
		return out, fmt.Errorf("read the routing tables: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return out, fmt.Errorf("read the routing tables: %w", err)
	}
	for i := range msgs {
		r, typ, oif, ok := parseRoute(&msgs[i])
		if ok && typ == unix.RTN_UNICAST && r.Prefix.Contains(dst) {
			r.Dev = devName(oif)
			out.Covering = append(out.Covering, r)
		}
	}
	sortRoutes(out.Covering)
	return out, nil
}

// sortRoutes orders routes the most specific first, then by table and
// interface, so a record doesn't depend on the kernel's dump order.
func sortRoutes(rs []evidence.Route) {
	slices.SortFunc(rs, func(a, b evidence.Route) int {
		if c := b.Prefix.Bits() - a.Prefix.Bits(); c != 0 {
			return c
		}
		if c := int(a.Table) - int(b.Table); c != 0 {
			return c
		}
		if c := strings.Compare(a.Dev, b.Dev); c != 0 {
			return c
		}
		return a.Prefix.Addr().Compare(b.Prefix.Addr())
	})
}

// routeGet sends one RTM_GETROUTE request for dst and reads the reply.
func routeGet(dst netip.Addr) (evidence.Route, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return evidence.Route{}, fmt.Errorf("netlink socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	tv := syscall.Timeval{Sec: 2}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return evidence.Route{}, fmt.Errorf("netlink socket: %w", err)
	}
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return evidence.Route{}, fmt.Errorf("netlink bind: %w", err)
	}
	const seq = 1
	if err := syscall.Sendto(fd, getRouteRequest(dst, seq), 0, sa); err != nil {
		return evidence.Route{}, fmt.Errorf("netlink send: %w", err)
	}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return evidence.Route{}, fmt.Errorf("netlink receive: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return evidence.Route{}, fmt.Errorf("netlink reply: %w", err)
		}
		for i := range msgs {
			m := &msgs[i]
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return evidence.Route{}, errors.New("netlink: short error message")
				}
				var code int32 // the reply's error: 0, or a negative errno
				if err := binary.Read(bytes.NewReader(m.Data[:4]), binary.NativeEndian, &code); err != nil {
					return evidence.Route{}, fmt.Errorf("netlink reply: %w", err)
				}
				if code < 0 {
					return evidence.Route{}, syscall.Errno(uint32(-code))
				}
			case syscall.RTM_NEWROUTE:
				if r, _, oif, ok := parseRoute(m); ok {
					r.Dev = devName(oif)
					return r, nil
				}
				return evidence.Route{}, errors.New("netlink: unreadable route in the reply")
			}
		}
	}
}

// getRouteRequest builds an RTM_GETROUTE request for dst that asks for the
// matching table entry (RTM_F_FIB_MATCH), with its table (RTM_F_LOOKUP_TABLE),
// rather than a cached route to dst alone. Kernels before 4.13 ignore the
// flag and answer with dst/32; Route's covering routes still show the entry.
func getRouteRequest(dst netip.Addr, seq uint32) []byte {
	// An IPv4 address takes 4 bytes, an IPv6 one 16: the attribute's
	// length (header included) is a multiple of 4 either way, so needs no
	// padding.
	family, dstLen, attrLen := uint8(syscall.AF_INET), uint8(32), uint16(syscall.SizeofRtAttr+4)
	if dst.Is6() {
		family, dstLen, attrLen = syscall.AF_INET6, 128, syscall.SizeofRtAttr+16
	}
	n := uint32(syscall.NLMSG_HDRLEN+syscall.SizeofRtMsg) + uint32(attrLen)
	b := make([]byte, n)
	ne := binary.NativeEndian
	ne.PutUint32(b[0:4], n)
	ne.PutUint16(b[4:6], syscall.RTM_GETROUTE)
	ne.PutUint16(b[6:8], syscall.NLM_F_REQUEST)
	ne.PutUint32(b[8:12], seq)
	rt := b[syscall.NLMSG_HDRLEN:]
	rt[0], rt[1] = family, dstLen // dst_len: the whole address
	ne.PutUint32(rt[8:12], unix.RTM_F_FIB_MATCH|unix.RTM_F_LOOKUP_TABLE)
	at := rt[syscall.SizeofRtMsg:]
	ne.PutUint16(at[0:2], attrLen)
	ne.PutUint16(at[2:4], syscall.RTA_DST)
	copy(at[syscall.SizeofRtAttr:], dst.AsSlice())
	return b
}

// parseRoute reads an RTM_NEWROUTE message: the route's prefix and table,
// its type (unicast, local, …), and the index of its interface (0 for
// none). Naming the interface (devName) costs a dump of every link, so
// callers name it only for the routes they keep.
func parseRoute(m *syscall.NetlinkMessage) (evidence.Route, uint8, int, bool) {
	if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < syscall.SizeofRtMsg {
		return evidence.Route{}, 0, 0, false
	}
	family, dstLen, table, typ := m.Data[0], int(m.Data[1]), uint32(m.Data[4]), m.Data[7]
	attrs, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return evidence.Route{}, 0, 0, false
	}
	var dst netip.Addr
	oif := 0
	for _, a := range attrs {
		switch a.Attr.Type {
		case syscall.RTA_DST:
			if ip, ok := netip.AddrFromSlice(a.Value); ok {
				dst = ip.Unmap()
			}
		case syscall.RTA_OIF:
			if len(a.Value) >= 4 {
				oif = int(binary.NativeEndian.Uint32(a.Value[:4]))
			}
		case unix.RTA_TABLE:
			if len(a.Value) >= 4 {
				table = binary.NativeEndian.Uint32(a.Value[:4])
			}
		}
	}
	if !dst.IsValid() { // a default route carries no RTA_DST
		switch family {
		case syscall.AF_INET:
			dst = netip.IPv4Unspecified()
		case syscall.AF_INET6:
			dst = netip.IPv6Unspecified()
		default:
			return evidence.Route{}, 0, 0, false
		}
	}
	p, err := dst.Prefix(dstLen)
	if err != nil {
		return evidence.Route{}, 0, 0, false
	}
	r := evidence.Route{Prefix: p}
	if table != evidence.MainTable {
		r.Table = table
	}
	return r, typ, oif, true
}

// devName names the interface with index oif: "" for none, "if<index>"
// when it can't be found.
func devName(oif int) string {
	if oif <= 0 {
		return ""
	}
	if ifc, err := net.InterfaceByIndex(oif); err == nil {
		return ifc.Name
	}
	return fmt.Sprintf("if%d", oif)
}
