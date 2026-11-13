// Package host reads the host's own network state: its interfaces and
// addresses (tier 0, INITIAL.md §4.9). It knows nothing about rules.
//
// Interfaces come from the standard library's net.Interfaces, which asks
// the kernel over netlink on Linux (RTM_GETLINK, RTM_GETADDR) and never
// runs a command. Route lookups (netlink RouteGet) arrive with WR013 in
// v0.2. Listening sockets are read by package probe from /proc/net.
package host

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Addrs returns the interfaces of whyreach's own network namespace that
// have a usable address: the host's when whyreach runs natively. Loopback,
// and IPv6 link-local addresses, are left out: loopback targets are their
// own class, and link-local addresses are never probed.
func Addrs() (evidence.HostAddrs, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return evidence.HostAddrs{}, fmt.Errorf("list network interfaces: %w", err)
	}
	var out evidence.HostAddrs
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			return evidence.HostAddrs{}, fmt.Errorf("addresses of %s: %w", ifc.Name, err)
		}
		i := evidence.Interface{Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0, MTU: ifc.MTU}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLinkLocalUnicast() {
				continue
			}
			bits, _ := ipn.Mask.Size()
			i.Addrs = append(i.Addrs, netip.PrefixFrom(ip, bits))
		}
		if len(i.Addrs) == 0 {
			continue
		}
		slices.SortFunc(i.Addrs, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
		out.Interfaces = append(out.Interfaces, i)
	}
	slices.SortFunc(out.Interfaces, func(a, b evidence.Interface) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
