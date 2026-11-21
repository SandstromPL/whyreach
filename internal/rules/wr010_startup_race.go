package rules

import (
	"fmt"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR010: a startup race. The destination is running but not ready yet: its
// healthcheck hasn't passed (health "starting"), or it has no healthcheck,
// started moments ago and listens on nothing yet. A client that connects
// once at startup fails. Frequency rank 4.
type wr010 struct{}

func (wr010) ID() string                { return "WR010" }
func (wr010) Layer() Layer              { return LayerDestination }
func (wr010) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }

// Supersedes: not listening yet, on the port or at all, is what starting
// up looks like.
func (wr010) Supersedes() []string { return []string{"WR001", "WR003"} }

// justStarted is how recently a container without a healthcheck must have
// started for "listens on nothing yet" to read as still starting.
const justStarted = 60 * time.Second

func (r wr010) Evaluate(v evidence.View) []Finding {
	matches := v.Destinations().All()
	if len(matches) == 0 || connectedByName(v) {
		return nil
	}
	// The first replica that is still starting is the finding; another one
	// that serves only lowers it, so the order of the replicas doesn't
	// change the answer.
	var f *Finding
	var starting evidence.Match
	for _, m := range matches {
		c := m.C
		at := observedAt(v, m.ID)
		if !c.Running() || c.Health == "unhealthy" || crashLooping(c, at) {
			continue // WR008's cases
		}
		l, haveL := v.ListenersIn(c.ID)
		if haveL && (len(l.L.OnPort(m.Port)) > 0 || len(otherPorts(l.L, m.Port)) > 0) {
			continue // it listens: started, whatever its health says (on another port: WR003)
		}
		uptime := ""
		if !c.StartedAt.IsZero() && !at.IsZero() {
			uptime = fmt.Sprintf(" %s ago", at.Sub(c.StartedAt).Round(time.Second))
		}
		name := containerLabel(c)
		var g Finding
		switch {
		case c.Health == "starting":
			g = Finding{Confidence: Medium, Supporting: []string{m.ID}}
			g.Explanation = fmt.Sprintf("%s started%s and its healthcheck has not passed yet (health: starting)", name, uptime)
			if haveL {
				g.Confidence = High
				g.Supporting = append(g.Supporting, l.ID)
				g.Explanation += fmt.Sprintf(", and nothing in it listens on port %d yet", m.Port)
			}
			g.Explanation += ". Connections fail until it is ready."
		case c.Health == "" && haveL && !listensAtAll(l.L) && uptime != "" && at.Sub(c.StartedAt) < justStarted:
			g = Finding{Confidence: Medium, Supporting: []string{m.ID, l.ID}}
			g.Explanation = fmt.Sprintf("%s started only%s and listens on nothing yet: it is probably still starting up. It has no healthcheck, so whyreach can't tell for sure.", name, uptime)
		default:
			continue
		}
		g.RuleID, g.Layer, g.DocURL = r.ID(), r.Layer(), DocURL(r.ID())
		g.Title = fmt.Sprintf("%s is still starting", replicaName(matches, m))
		g.Fix = wr010Fix(v, c)
		f, starting = &g, m
		break
	}
	if f == nil {
		return nil
	}
	partOfReplicas(f, servingReplicas(v, matches, starting), starting.C.Name)
	f.Supporting = ids(append(f.Supporting, sourceConnects(v, evidence.OutcomeRefused)...)...)
	return []Finding{*f}
}

// listensAtAll reports a socket other than Docker's DNS listener.
func listensAtAll(l evidence.Listeners) bool {
	for _, s := range l.Sockets {
		if !s.IsDockerDNS() {
			return true
		}
	}
	return false
}

func wr010Fix(v evidence.View, dst evidence.Container) string {
	name := dst.DisplayName()
	client := "the client"
	if src, ok := v.Source(); ok {
		client = src.C.DisplayName()
	}
	if dst.Health == "" {
		return fmt.Sprintf("Wait until %s listens, and make %s wait for it: give %s a healthcheck and, in Compose, depends_on: {%s: {condition: service_healthy}} on %s. A client that connects once at startup should also retry.",
			name, client, name, name, client)
	}
	return fmt.Sprintf("Wait until %s is healthy, and make %s wait for it: in Compose, depends_on: {%s: {condition: service_healthy}} on %s. A client that connects once at startup should also retry.",
		name, client, name, client)
}
