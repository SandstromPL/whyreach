package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR005: the name matches no container, Compose service or alias on the
// source's networks. It is decided from Docker metadata, never from the DNS
// rcode, which depends on the host's resolver (rule experiments, E1 and E2);
// a failed lookup from the source only confirms it (Probe? partly). The
// closest name on the source's networks is suggested. Frequency rank 8.
type wr005 struct{}

func (wr005) ID() string                { return "WR005" }
func (wr005) Layer() Layer              { return LayerNaming }
func (wr005) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }
func (wr005) Supersedes() []string      { return []string{"WR016"} }

func (r wr005) Evaluate(v evidence.View) []Finding {
	q := v.Question()
	if q.To.Class != evidence.TargetName || evidence.IsHostDockerInternal(q.To.Host) {
		return nil
	}
	src, ok := v.Source()
	if !ok {
		return nil
	}
	owner, ok := v.NetnsOwner()
	if !ok || owner.C.HostNetwork() {
		return nil
	}
	nets := owner.C.UserDefinedNetworks()
	if len(nets) == 0 {
		return nil // on the default bridge no name resolves at all
	}
	d := v.Destinations()
	if d.Host != nil || d.HostsEntry != "" {
		return nil
	}
	if len(d.OnSourceNets) > 0 {
		return r.aliasElsewhere(v, src, owner, d.OnSourceNets)
	}
	if len(d.All()) > 0 {
		return nil // only on other networks: WR004
	}
	name := strings.TrimSuffix(strings.ToLower(q.To.Host), ".")
	known := namesOn(v, owner.C, nets)
	best, dist := closest(name, known)
	dotted := strings.Contains(name, ".")
	if dotted && dist > maxEdits(name) {
		return nil // an external name, not a container's (WR020 covers its DNS)
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: Medium,
		Supporting: []string{src.ID, owner.ID},
	}
	looked, resolved := confirmLookup(v, &f, src, owner)
	if resolved {
		return nil // it resolves to something after all
	}
	if v.Incomplete() {
		f.Confidence = f.Confidence.Lower() // some containers' metadata is missing
		looked += " Some containers' metadata could not be read or was skipped, so one of them might answer to it."
	}
	for _, c := range v.Containers() {
		if c.C.ID != owner.C.ID && len(sharedNetworks(owner.C, c.C)) > 0 {
			f.Supporting = append(f.Supporting, c.ID)
		}
	}
	f.Supporting = ids(f.Supporting...)
	where := fmt.Sprintf("%s %s", plural(len(nets), "network", "networks"), quoteList(nets))
	f.Title = fmt.Sprintf("no container on %s's networks is called %s", src.C.DisplayName(), q.To.Host)
	f.Explanation = fmt.Sprintf("No container name, Compose service or alias on %s's %s is %s.%s", owner.C.DisplayName(), where, q.To.Host, looked)
	target := hostPort(best, q.To.Port)
	switch {
	case best != "" && dist <= maxEdits(name):
		f.Explanation = fmt.Sprintf("No container name, Compose service or alias on %s's %s is %s; the closest is %s.%s",
			owner.C.DisplayName(), where, q.To.Host, best, looked)
		f.Title = fmt.Sprintf("no container on %s's networks is called %s (did you mean %s?)", src.C.DisplayName(), q.To.Host, best)
		f.Fix = fmt.Sprintf("Use %s. If %s is meant to be another service, start it on %s, or give the service that alias (networks: {%s: {aliases: [%s]}} in Compose).",
			target, q.To.Host, nets[0], composeKey(owner.C, nets[0]), q.To.Host)
	default:
		shown := known
		if len(shown) > 6 {
			shown = append(slices.Clone(shown[:6]), "…")
		}
		f.Fix = fmt.Sprintf("Use the name of a service on %s (%s), or start the service called %s there.", nets[0], strings.Join(shown, ", "), q.To.Host)
	}
	return []Finding{f}
}

// confirmLookup adds the source's own lookup of the target, which raises a
// finding to high when it failed, unless it timed out: a timeout says the
// upstream resolver didn't answer (WR020), not that Docker doesn't know the
// name. It returns the sentence to add, and whether the name resolved.
func confirmLookup(v evidence.View, f *Finding, src, owner evidence.ContainerEv) (string, bool) {
	q := v.Question()
	dns, ok := v.SourceDNS(q.To.Host)
	if !ok {
		return "", false
	}
	if len(dns.P.Answers) > 0 {
		return "", true
	}
	f.Supporting = append(f.Supporting, dns.ID)
	if dns.P.Rcode == evidence.RcodeTimeout {
		return fmt.Sprintf(" The lookup in %s timed out (from %s), which points at the upstream DNS rather than at the name.", src.C.DisplayName(), dns.P.Server), false
	}
	f.Confidence = High
	looked := fmt.Sprintf(" The lookup in %s failed too (%s from %s).", src.C.DisplayName(), dns.P.Rcode, dns.P.Server)
	if ctl, ok := v.SourceDNS(owner.C.Name); ok && ctl.ID != dns.ID && len(ctl.P.Answers) > 0 {
		f.Supporting = append(f.Supporting, ctl.ID)
		looked = fmt.Sprintf(" The lookup in %s failed too (%s from %s), while %s's own name resolved there: Docker's DNS works and doesn't know %s.",
			src.C.DisplayName(), dns.P.Rcode, dns.P.Server, owner.C.Name, q.To.Host)
	}
	return looked, false
}

// aliasElsewhere is the case of a name that a container on a shared network
// answers to only on another network: an alias is per network, so Docker's
// DNS doesn't know it on the networks the source shares with it.
func (r wr005) aliasElsewhere(v evidence.View, src, owner evidence.ContainerEv, matches []evidence.Match) []Finding {
	q := v.Question()
	var m *evidence.Match
	var shared []string
	for i, c := range matches {
		if len(intersect(c.Networks, c.Shared)) > 0 {
			return nil // the name resolves on a network they share
		}
		var user []string
		for _, n := range c.Shared {
			if evidence.UserDefined(n) {
				user = append(user, n)
			}
		}
		if len(user) > 0 && len(c.Networks) > 0 && m == nil {
			m, shared = &matches[i], user
		}
	}
	if m == nil || connectedByName(v) {
		return nil // only the default bridge in common: WR009's case
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: Medium,
		Supporting: []string{src.ID, owner.ID, m.ID},
	}
	looked, resolved := confirmLookup(v, &f, src, owner)
	if resolved {
		return nil
	}
	f.Supporting = ids(f.Supporting...)
	name := m.C.DisplayName()
	here := m.C.Name
	if m.C.Compose != nil && m.C.Compose.Service != "" {
		here = m.C.Compose.Service
	}
	f.Title = fmt.Sprintf("%s answers to %s only on %s, which %s isn't on", name, q.To.Host, quoteList(m.Networks), src.C.DisplayName())
	f.Explanation = fmt.Sprintf("%s has %s as an alias on %s %s only. Aliases are per network: on %s, which %s shares with it, Docker's DNS knows it as %s, not %s.%s",
		containerLabel(m.C), q.To.Host, plural(len(m.Networks), "network", "networks"), quoteList(m.Networks), shared[0], src.C.DisplayName(), here, q.To.Host, looked)
	// The container is on that network already, so without Compose the
	// alias needs a reconnect: Docker refuses a second connect.
	f.Fix = fmt.Sprintf("Use %s, or give %s the alias on %s too: networks: {%s: {aliases: [%s]}} for %s in Compose (without Compose: docker network disconnect %s %s, then docker network connect --alias %s %s %s).",
		hostPort(here, q.To.Port), name, shared[0], composeKey(m.C, shared[0]), q.To.Host, name, shared[0], m.C.Name, q.To.Host, shared[0], m.C.Name)
	return []Finding{f}
}

// namesOn lists the names Docker's DNS answers on the source's user-defined
// networks, other than the source's own: Compose services first.
func namesOn(v evidence.View, owner evidence.Container, nets []string) []string {
	var services, others []string
	for _, c := range v.Containers() {
		if c.C.ID == owner.ID || c.C.NetnsOwner() == owner.ID {
			continue
		}
		for _, n := range nets {
			a, ok := c.C.Attachment(n)
			if !ok {
				continue
			}
			if c.C.Compose != nil && c.C.Compose.Service != "" {
				services = append(services, strings.ToLower(c.C.Compose.Service))
			}
			others = append(others, strings.ToLower(c.C.Name))
			for _, name := range a.Names {
				if len(name) == 12 && strings.Trim(name, "0123456789abcdef") == "" {
					continue // the short container ID
				}
				others = append(others, name)
			}
		}
	}
	slices.Sort(services)
	slices.Sort(others)
	out := slices.Compact(services)
	for _, o := range slices.Compact(others) {
		if !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}

// closest returns the known name with the smallest edit distance to name,
// preferring the earlier one (services first) on a tie.
func closest(name string, known []string) (string, int) {
	best, dist := "", 1<<30
	for _, k := range known {
		if d := editDistance(name, k); d < dist {
			best, dist = k, d
		}
	}
	return best, dist
}

// maxEdits is how far a name may be from a suggestion: one edit for short
// names, two for most, three for long ones.
func maxEdits(name string) int {
	switch {
	case len(name) <= 3:
		return 1
	case len(name) <= 8:
		return 2
	default:
		return 3
	}
}

// editDistance is the Levenshtein distance between two strings.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
