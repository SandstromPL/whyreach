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

// maxSuggested is how many other ports a suggestion may list before the
// guess gets too weak to be worth making.
const maxSuggested = 3

func (r wr003) Evaluate(v evidence.View) []Finding {
	if connectedByName(v) {
		return nil
	}
	for _, m := range v.Destinations().All() {
		if m.C.HostNetwork() || !m.C.Running() {
			continue
		}
		l, ok := v.ListenersIn(m.C.ID)
		if !ok || len(l.L.OnPort(m.Port)) > 0 {
			continue
		}
		ports := otherPorts(l.L, m.Port)
		if len(ports) == 0 || len(ports) > maxSuggested {
			continue // nothing else (WR001), or too many to guess from
		}
		f := Finding{
			RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: High,
			Supporting: refusedFrom(v, []string{m.ID, l.ID}),
		}
		if len(ports) > 1 {
			f.Confidence = Medium
		}
		name := m.C.DisplayName()
		var where []string
		for _, p := range ports {
			where = append(where, socketList(l.L.OnPort(p)))
		}
		f.Title = fmt.Sprintf("%s listens on %s, not %d", name, portList(ports), m.Port)
		f.Explanation = fmt.Sprintf("Nothing in %s listens on port %d; it listens on %s.", containerLabel(m.C), m.Port, strings.Join(where, " and "))
		q := v.Question()
		switch {
		case m.Published != nil:
			f.Explanation = fmt.Sprintf("%s publishes %s → its port %d, but nothing in it listens on %d; it listens on %s.",
				containerLabel(m.C), m.Published.HostAddr(), m.Port, m.Port, strings.Join(where, " and "))
			f.Fix = fmt.Sprintf("Publish the port it uses: ports: [\"%d:%d\"] for %s, or make its server listen on %d.",
				m.Published.HostPort, ports[0], name, m.Port)
		default:
			f.Fix = fmt.Sprintf("Connect to %s instead of %s, or make the server in %s listen on %d (check its port setting).",
				hostPort(q.To.Host, ports[0]), q.To.String(), name, m.Port)
		}
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

func portList(ports []uint16) string {
	var s []string
	for _, p := range ports {
		s = append(s, strconv.Itoa(int(p)))
	}
	return quoteList(s)
}
