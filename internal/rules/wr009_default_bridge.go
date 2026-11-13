package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR009: the source and the destination share only Docker's default bridge
// network, which has no embedded DNS: container names and Compose services
// don't resolve on it. The network name settles it (rule experiments, E7).
// Frequency rank 12.
type wr009 struct{}

func (wr009) ID() string                { return "WR009" }
func (wr009) Layer() Layer              { return LayerNaming }
func (wr009) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }
func (wr009) Supersedes() []string      { return []string{"WR005", "WR016"} }

func (r wr009) Evaluate(v evidence.View) []Finding {
	q := v.Question()
	if q.To.Class != evidence.TargetName {
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
	d := v.Destinations()
	if d.HostsEntry != "" || d.Host != nil || len(d.OnSourceNets) == 0 {
		return nil
	}
	var m *evidence.Match
	for i, c := range d.OnSourceNets {
		if len(intersect(c.Networks, c.Shared)) > 0 {
			return nil // the name resolves on a network they share
		}
		if slices.ContainsFunc(c.Shared, evidence.UserDefined) {
			// They share a user-defined network too, where Docker's DNS
			// works but doesn't know the name: an alias on another
			// network, WR005's case, not the default bridge's. Another
			// container that answers to the name may still share only
			// the bridge.
			continue
		}
		if slices.Contains(c.Shared, evidence.NetworkBridge) && m == nil {
			m = &d.OnSourceNets[i]
		}
	}
	if m == nil || linked(owner.C, q.To.Host) {
		return nil // a legacy --link puts the name in /etc/hosts
	}
	if connectedByName(v) {
		return nil
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: High,
		Supporting: []string{src.ID, owner.ID, m.ID},
	}
	if dns, ok := v.SourceDNS(q.To.Host); ok {
		if len(dns.P.Answers) > 0 {
			return nil
		}
		f.Supporting = append(f.Supporting, dns.ID)
	}
	f.Supporting = ids(f.Supporting...)
	srcName, dstName := owner.C.DisplayName(), m.C.DisplayName()
	f.Title = fmt.Sprintf("%s and %s share only Docker's default bridge, where names don't resolve", srcName, dstName)
	f.Explanation = fmt.Sprintf("%s and %s are both on Docker's default bridge network (\"bridge\"), which has no embedded DNS: container names and Compose service names resolve only on user-defined networks, so %s is unknown in %s.",
		srcName, containerLabel(m.C), q.To.Host, srcName)
	if a, ok := m.C.Attachment(evidence.NetworkBridge); ok && a.IPv4.IsValid() {
		f.Explanation += fmt.Sprintf(" %s's address there, %s, works but changes when it restarts.", dstName, a.IPv4)
	}
	compose := ""
	if m.C.Compose != nil || owner.C.Compose != nil {
		compose = " In Compose, remove network_mode: bridge so both services use the project's own network."
	}
	f.Fix = fmt.Sprintf("Put both on a user-defined network: docker network create app; docker network connect app %s; docker network connect app %s. Then %s resolves.%s",
		m.C.Name, owner.C.Name, hostPort(q.To.Host, q.To.Port), compose)
	return []Finding{f}
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// linked reports a legacy --link that names the target: "/api:/worker/api".
func linked(c evidence.Container, name string) bool {
	for _, l := range c.Links {
		_, alias, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		if i := strings.LastIndex(alias, "/"); i >= 0 {
			alias = alias[i+1:]
		}
		if strings.EqualFold(alias, name) || strings.EqualFold(strings.TrimPrefix(strings.Split(l, ":")[0], "/"), name) {
			return true
		}
	}
	return false
}
