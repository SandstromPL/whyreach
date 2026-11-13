package rules

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR003: the destination listens, but on a different port. Its listeners
// settle it, and the port it does listen on is the suggestion.
type wr003 struct{}

func (wr003) ID() string                { return "WR003" }
func (wr003) Layer() Layer              { return LayerListener }
func (wr003) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindListeners} }
func (wr003) Supersedes() []string      { return []string{"WR001"} }

// maxSuggested is how many other ports the fix may choose from before the
// guess gets too weak to name one; maxShown bounds the ports listed.
const (
	maxSuggested = 3
	maxShown     = 5
)

func (r wr003) Evaluate(v evidence.View) []Finding {
	if connectedByName(v) {
		return nil
	}
	matches := v.Destinations().All()
	for _, m := range matches {
		if m.C.HostNetwork() || !m.C.Running() {
			continue
		}
		l, ok := v.ListenersIn(m.C.ID)
		if !ok || len(l.L.OnPort(m.Port)) > 0 {
			continue
		}
		ports := otherPorts(l.L, m.Port)
		if len(ports) == 0 {
			continue // nothing else listens: WR001
		}
		f := Finding{
			RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: High,
			Supporting: refusedFrom(v, []string{m.ID, l.ID}),
		}
		if len(ports) > 1 {
			f.Confidence = Medium
		}
		name := replicaName(matches, m)
		shown, more := ports, 0
		if len(ports) > maxShown {
			shown, more = ports[:maxShown-1], len(ports)-(maxShown-1)
		}
		var where []string
		for _, p := range shown {
			where = append(where, socketList(l.L.OnPort(p)))
		}
		if more > 0 {
			where = append(where, fmt.Sprintf("%d more ports", more))
		}
		listed := portList(shown)
		if more > 0 {
			listed = strings.Join(append(portStrings(shown), fmt.Sprintf("%d more", more)), ", ")
		}
		f.Title = fmt.Sprintf("%s listens on %s, not %d", name, listed, m.Port)
		f.Explanation = fmt.Sprintf("Nothing in %s listens on port %d; it listens on %s.", containerLabel(m.C), m.Port, quoteList(where))
		q := v.Question()
		switch {
		case m.Published != nil:
			f.Explanation = fmt.Sprintf("%s publishes %s → its port %d, but nothing in it listens on %d; it listens on %s.",
				containerLabel(m.C), m.Published.HostAddr(), m.Port, m.Port, quoteList(where))
			f.Fix = fmt.Sprintf("Publish the port it uses: ports: [\"%d:%d\"] for %s, or make its server listen on %d.",
				m.Published.HostPort, ports[0], name, m.Port)
			if len(ports) > maxSuggested {
				f.Fix = fmt.Sprintf("Publish the port that serves this (ports: [\"%d:<that port>\"] for %s; it listens on %s), or make its server listen on %d.",
					m.Published.HostPort, name, listed, m.Port)
			}
		case len(ports) > maxSuggested:
			f.Fix = fmt.Sprintf("Find which of %s's ports serves this (%s) and connect to that instead of %s, or make the server in %s listen on %d (check its port setting).",
				name, listed, q.To.String(), name, m.Port)
		default:
			f.Fix = fmt.Sprintf("Connect to %s instead of %s, or make the server in %s listen on %d (check its port setting).",
				hostPort(q.To.Host, ports[0]), q.To.String(), name, m.Port)
		}
		if m.C.Health == "starting" {
			f.Confidence = f.Confidence.Lower()
			f.Explanation += fmt.Sprintf(" %s is still starting (health: starting), so it may open port %d later.", name, m.Port)
		}
		partOfReplicas(&f, servingReplicas(v, matches, m), m.C.Name)
		return []Finding{f}
	}
	return nil
}

// otherPorts lists the ports with a listener reachable from other network
// namespaces, other than port and Docker's DNS listener.
func otherPorts(l evidence.Listeners, port uint16) []uint16 {
	var out []uint16
	for _, s := range l.Sockets {
		p := s.Local.Port()
		if p == port || s.IsDockerDNS() || s.IsLoopback() || slices.Contains(out, p) {
			continue
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func portList(ports []uint16) string { return quoteList(portStrings(ports)) }

func portStrings(ports []uint16) []string {
	var s []string
	for _, p := range ports {
		s = append(s, strconv.Itoa(int(p)))
	}
	return s
}
