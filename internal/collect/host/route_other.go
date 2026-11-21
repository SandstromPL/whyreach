//go:build !linux

package host

import (
	"fmt"
	"net/netip"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// Route needs Linux's netlink: elsewhere the record says unsupported.
func Route(dst netip.Addr) (evidence.HostRoute, error) {
	return evidence.HostRoute{Dst: dst}, fmt.Errorf("route lookups: %w", probe.ErrUnsupported)
}
