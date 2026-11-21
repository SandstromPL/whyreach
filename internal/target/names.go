package target

import (
	"net/netip"
	"slices"
	"strings"
)

// Names whose lookups stay free through MCP besides the names Docker knows
// (INITIAL.md §4.9, §10 Q11): Docker's fixed names for the host.
var dockerFixedNames = []string{"host.docker.internal", "gateway.docker.internal"}

// NormalizeName folds a name for comparison: lowercase, without surrounding
// space or a trailing dot.
func NormalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// OutsideName reports whether looking name up could deliver it to a DNS
// server that whoever picked the name controls: a name with a dot, other
// than a loopback name (localhost, *.localhost) or one of Docker's fixed
// names (host.docker.internal, gateway.docker.internal). Through MCP such a
// name is looked up only with the user's approval, unless Docker's metadata
// or the source's hosts file answers it (INITIAL.md §10 Q11). A name
// without a dot reaches only the resolver and the search domains the
// user's own configuration names; an address is not a name.
func OutsideName(name string) bool {
	h := NormalizeName(name)
	if !strings.Contains(h, ".") {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false
	}
	return !slices.Contains(dockerFixedNames, h)
}

// CoveredBy reports whether name is one of domains or a subdomain of one:
// "example.com" covers example.com and api.example.com, not badexample.com.
// Both sides are compared as NormalizeName folds them.
func CoveredBy(name string, domains []string) bool {
	h := NormalizeName(name)
	for _, d := range domains {
		d = NormalizeName(d)
		if d != "" && (h == d || strings.HasSuffix(h, "."+d)) {
			return true
		}
	}
	return false
}
