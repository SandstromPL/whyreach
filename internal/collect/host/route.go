package host

import (
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// SortRoutes orders routes the most specific first, then by table and
// interface, so a record doesn't depend on the kernel's dump order.
func SortRoutes(rs []evidence.Route) {
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
