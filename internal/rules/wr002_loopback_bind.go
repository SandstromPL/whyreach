package rules

import (
	"fmt"
	"slices"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR002: the destination's service is bound to loopback only (127.0.0.1 or
// ::1) inside its own container, so no other network namespace can reach it.
// The destination's listeners, read without root and without a probe, settle
// it; a refused connect from the source confirms it.
type wr002 struct{}

func (wr002) ID() string                { return "WR002" }
func (wr002) Layer() Layer              { return LayerListener }
func (wr002) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindListeners} }
func (wr002) Supersedes() []string      { return []string{"WR001"} }

func (r wr002) Evaluate(v evidence.View) []Finding {
	q := v.Question()
	if q.To.Class == evidence.TargetLoopback && !v.HostSource() {
		return nil // reaching loopback from inside the same netns works; WR007 covers the rest
	}
	probes := fromSource(v)
	// The connection goes to the destination's network address (or, through
	// a published port, to the container port behind it). A loopback-bound
	// socket refuses that even from inside its own network namespace, so the
	// source's netns doesn't matter.
	matches := v.Destinations().All()
	for _, m := range matches {
		if m.C.HostNetwork() {
			continue // its listeners are the host's: WR012's case
		}
		port := m.Port
		l, ok := v.ListenersIn(m.C.ID)
		if !ok {
			continue
		}
		socks := l.L.OnPort(port)
		if len(socks) == 0 || l.L.AcceptsRemote(port) {
			continue // nothing listens (WR001), or something reachable does
		}
		addrs := m.C.Addrs()
		f := Finding{
			RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()),
			Confidence: High,
			Supporting: []string{m.ID, l.ID},
		}
		stale := false
		for _, t := range probes {
			reaches := slices.Contains(addrs, t.P.Addr.Addr()) && t.P.Addr.Port() == port
			if m.Published != nil {
				reaches = t.P.ByName() && t.P.Addr.Port() == m.Published.HostPort
			}
			if !reaches {
				continue
			}
			switch t.P.Outcome {
			case evidence.OutcomeRefused, evidence.OutcomeClosed:
				f.Supporting = append(f.Supporting, t.ID)
			case evidence.OutcomeConnected:
				stale = true // something accepted after all: the listener evidence is out of date
			}
		}
		if stale {
			continue
		}
		f.Supporting = ids(f.Supporting...)
		name := replicaName(matches, m)
		f.Title = fmt.Sprintf("%s listens only on %s inside its container", name, socketList(socks))
		f.Explanation = fmt.Sprintf("%s's only %s for port %d %s %s (in %s). A socket bound to loopback accepts connections only from inside %s's own network namespace, so %s can't reach it.",
			name, plural(len(socks), "listener", "listeners"), port, plural(len(socks), "is", "are"), socketList(socks), name, name, sourceName(v))
		if m.Published != nil {
			f.Explanation = fmt.Sprintf("%s publishes %s → its port %d, but its only %s for port %d %s %s (in %s). The published port forwards connections into the container from outside its loopback, so the socket never sees them: the host's connection is refused, or accepted and closed at once by docker-proxy.",
				name, m.Published.HostAddr(), port, plural(len(socks), "listener", "listeners"), port, plural(len(socks), "is", "are"), socketList(socks), name)
		}
		partOfReplicas(&f, servingReplicas(v, matches, m), m.C.Name)
		f.Fix = fmt.Sprintf("Make the server in %s listen on 0.0.0.0:%d (or [::]:%d), for example with --host 0.0.0.0 or a HOST=0.0.0.0 setting, then restart %s.", name, port, port, name)
		return []Finding{f}
	}
	return nil
}

// sourceName names the source for prose.
func sourceName(v evidence.View) string {
	if src, ok := v.Source(); ok {
		return src.C.DisplayName()
	}
	return "the host"
}
