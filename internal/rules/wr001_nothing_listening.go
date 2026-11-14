package rules

import (
	"fmt"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR001: nothing listens on the port in the destination's network
// namespace: a container's, or the host's when the target is the host.
// Its listeners settle it; a refused connect confirms it. Many rules
// explain the same refusal better and supersede it: the destination is
// down or starting (WR008, WR010), the client aims at the wrong place
// (WR007, WR019), or the service listens elsewhere (WR002, WR003, WR012).
type wr001 struct{}

func (wr001) ID() string                { return "WR001" }
func (wr001) Layer() Layer              { return LayerListener }
func (wr001) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindListeners} }
func (wr001) Supersedes() []string      { return nil }

func (r wr001) Evaluate(v evidence.View) []Finding {
	if connectedByName(v) {
		return nil
	}
	d := v.Destinations()
	matches := d.All()
	for _, m := range matches {
		if m.C.HostNetwork() || !m.C.Running() {
			continue
		}
		l, ok := v.ListenersIn(m.C.ID)
		if !ok {
			continue
		}
		// A target port that is a host port the container publishes for
		// another container port (WR006) points at that container port: the
		// server would listen there, if anywhere.
		port := m.Port
		var behind *evidence.PortMap
		if m.Published == nil && len(l.L.OnPort(port)) == 0 {
			if b := m.C.PublishedAs(port); len(b) > 0 && b[0].ContainerPort != port {
				behind, port = &b[0], b[0].ContainerPort
			}
		}
		if len(l.L.OnPort(port)) > 0 || len(otherPorts(l.L, port)) > 0 {
			continue // it listens (WR002 if on loopback), or elsewhere (WR003)
		}
		f := Finding{
			RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: High,
			Supporting: refusedFrom(v, []string{m.ID, l.ID}),
		}
		name := replicaName(matches, m)
		f.Title = fmt.Sprintf("nothing in %s listens on port %d", name, port)
		f.Explanation = fmt.Sprintf("Nothing in %s listens on TCP port %d", containerLabel(m.C), port)
		switch {
		case m.Published != nil:
			f.Explanation = fmt.Sprintf("%s publishes %s → its port %d, but nothing in it listens on TCP port %d", containerLabel(m.C), m.Published.HostAddr(), port, port)
		case behind != nil:
			f.Explanation = fmt.Sprintf("Nothing in %s listens on TCP port %d, the container port it publishes as %s, nor on %d itself", containerLabel(m.C), port, behind.HostAddr(), m.Port)
		}
		if loop := loopbackElsewhere(l.L, port); loop != "" {
			f.Explanation += fmt.Sprintf(", and it listens only on loopback otherwise (%s)", loop)
		} else {
			f.Explanation += ", nor on any other port reachable from outside it"
		}
		f.Explanation += ": its server isn't listening."
		partOfReplicas(&f, servingReplicas(v, matches, m), m.C.Name)
		contradictedByPath(v, &f)
		f.Fix = fmt.Sprintf("Check that the server in %s started and listens on port %d: docker logs %s, and its port setting. If it serves UDP only, a TCP client can't reach it.", name, port, m.C.Name)
		return []Finding{f}
	}
	if d.Host == nil || len(d.Published) > 0 {
		return nil
	}
	hl, ok := v.HostListeners()
	port := v.Question().To.Port
	if !ok || len(hl.L.OnPort(port)) > 0 {
		return nil
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: High,
		Supporting: refusedFrom(v, append([]string{hl.ID}, d.Host.Evidence...)),
		Title:      fmt.Sprintf("nothing on %s listens on port %d", v.HostLabel(), port),
	}
	f.Explanation = fmt.Sprintf("The target is %s itself, and nothing on it listens on TCP port %d.", v.HostLabel(), port)
	if v.HostSource() && v.UnreadContainerListeners() {
		// A container may serve the port without publishing it (WR019),
		// and whyreach couldn't read every container's sockets to rule
		// that out.
		f.Confidence = Medium
		f.Explanation += " whyreach couldn't read every running container's listening sockets, so one of them may serve the port without publishing it."
	}
	contradictedByPath(v, &f)
	f.Fix = fmt.Sprintf("Start the service on %s, or check its port. If the service runs in a container, publish its port (ports: [\"%d:<container port>\"]) or connect to the container directly.", v.HostLabel(), port)
	return []Finding{f}
}

// loopbackElsewhere lists loopback-only listeners on other ports.
func loopbackElsewhere(l evidence.Listeners, port uint16) string {
	var socks []evidence.Socket
	for _, s := range l.Sockets {
		if s.Local.Port() != port && s.IsLoopback() && !s.IsDockerDNS() {
			socks = append(socks, s)
		}
	}
	return socketList(socks)
}
