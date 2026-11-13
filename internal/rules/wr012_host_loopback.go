package rules

import (
	"fmt"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR012: a service on the host listens only on 127.0.0.1 (or ::1), so
// containers can't reach it: their connections to the host arrive on a
// bridge address such as docker0's, where nothing listens. The host's
// listeners settle it (Linux Docker Engine; Docker Desktop forwards
// host.docker.internal differently). Frequency rank 5.
type wr012 struct{}

func (wr012) ID() string                { return "WR012" }
func (wr012) Layer() Layer              { return LayerListener }
func (wr012) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindListeners} }
func (wr012) Supersedes() []string      { return []string{"WR001"} }

func (r wr012) Evaluate(v evidence.View) []Finding {
	if v.HostSource() {
		return nil // from the host itself, loopback works
	}
	src, ok := v.Source()
	if !ok {
		return nil
	}
	d := v.Destinations()
	if d.Host == nil || d.Host.Via == evidence.HostViaLoopback {
		return nil
	}
	if ver, ok := dockerVersion(v); ok && !ver.LinuxEngine {
		return nil // Docker Desktop reaches host services its own way (INITIAL.md §3.7)
	}
	port := v.Question().To.Port
	hl, ok := v.HostListeners()
	if !ok {
		return nil
	}
	socks := hl.L.OnPort(port)
	if len(socks) == 0 || hl.L.AcceptsRemote(port) {
		return nil // nothing listens (WR001), or something reachable does
	}
	for _, c := range v.Containers() {
		if len(c.C.PublishedAs(port)) > 0 {
			return nil // the loopback listener is a published port: WR006's case
		}
	}
	if connectedByName(v) {
		return nil
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: High,
		Supporting: append([]string{src.ID, hl.ID}, d.Host.Evidence...),
	}
	for _, t := range fromSource(v) {
		if t.P.Outcome == evidence.OutcomeRefused {
			f.Supporting = append(f.Supporting, t.ID)
		}
	}
	f.Supporting = ids(f.Supporting...)
	srcName := src.C.DisplayName()
	arrives := "the host's address"
	reachable := "an address containers can reach"
	if d.Host.Addr.IsValid() {
		arrives = "the host's " + d.Host.Addr.String()
		reachable = d.Host.Addr.String()
		if d.Host.Iface != "" {
			arrives += " (" + d.Host.Iface + ")"
		}
	}
	f.Title = fmt.Sprintf("the host service on port %d listens only on %s", port, socketList(socks))
	f.Explanation = fmt.Sprintf("On the host, port %d is served only on %s, which accepts connections from the host itself. %s's connection to %s arrives at %s, where nothing listens, so it is refused.",
		port, socketList(socks), srcName, v.Question().To.String(), arrives)
	f.Fix = fmt.Sprintf("Make the host service listen on %s too, or on 0.0.0.0 (then mind the host firewall), and restart it. For PostgreSQL, for example: listen_addresses = 'localhost,%s' and a host line for the containers' subnet in pg_hba.conf.",
		reachable, reachable)
	return []Finding{f}
}

// dockerVersion returns the daemon's identity, when it was observed.
func dockerVersion(v evidence.View) (evidence.DockerVersion, bool) {
	for _, e := range v.Of(evidence.KindDockerVersion) {
		if dv, ok := e.Data.(evidence.DockerVersion); ok && e.OK() {
			return dv, true
		}
	}
	return evidence.DockerVersion{}, false
}
