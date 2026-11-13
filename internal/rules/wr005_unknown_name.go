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
	if len(d.All()) > 0 || d.Host != nil || d.HostsEntry != "" {
		return nil
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
	looked := ""
	if dns, ok := v.SourceDNS(q.To.Host); ok {
		if len(dns.P.Answers) > 0 {
			return nil // it resolves to something after all
		}
		f.Confidence = High
		f.Supporting = append(f.Supporting, dns.ID)
		looked = fmt.Sprintf(" The lookup in %s failed too (%s from %s).", src.C.DisplayName(), dns.P.Rcode, dns.P.Server)
		if ctl, ok := v.SourceDNS(owner.C.Name); ok && ctl.ID != dns.ID && len(ctl.P.Answers) > 0 {
			f.Supporting = append(f.Supporting, ctl.ID)
			looked = fmt.Sprintf(" The lookup in %s failed too (%s from %s), while %s's own name resolved there: Docker's DNS works and doesn't know %s.",
				src.C.DisplayName(), dns.P.Rcode, dns.P.Server, owner.C.Name, q.To.Host)
		}
	}
	if v.Incomplete() {
		f.Confidence = f.Confidence.Lower() // some containers' metadata is missing
		looked += " Some containers' metadata could not be read, so one of them might answer to it."
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
		f.Fix = fmt.Sprintf("Use %s. If %s is meant to be another service, start it on %s, or give the service that alias (networks: {%s: {aliases: [%s]}}).",
			target, q.To.Host, nets[0], nets[0], q.To.Host)
	default:
		shown := known
		if len(shown) > 6 {
			shown = append(slices.Clone(shown[:6]), "…")
		}
		f.Fix = fmt.Sprintf("Use the name of a service on %s (%s), or start the service called %s there.", nets[0], strings.Join(shown, ", "), q.To.Host)
	}
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
