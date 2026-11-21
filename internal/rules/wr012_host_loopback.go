package rules

import (
	"fmt"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR012: a service on the host listens only on 127.0.0.1 (or ::1), so
// containers can't reach it: their connections to the host arrive on a
// bridge address such as docker0's, where nothing listens. The host's
// listeners settle it, where Docker Engine runs on whyreach's machine (a
// Linux host, or a WSL2 distro, whose host is the WSL2 VM). Docker Desktop
// forwards host.docker.internal its own way, and on its WSL integration the
// host the containers reach is Windows, whose listeners whyreach can't read
// (the engine records that gap). Frequency rank 5.
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
	if p, _, ok := platformOf(v); ok && !p.EngineHere() {
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
	refused := false
	for _, t := range v.SourceTCP() {
		if t.P.Outcome == evidence.OutcomeRefused {
			f.Supporting = append(f.Supporting, t.ID)
			refused = true
		}
	}
	f.Supporting = ids(f.Supporting...)
	srcName := src.C.DisplayName()
	host := v.HostLabel()
	arrives := host + "'s address"
	reachable := "an address containers can reach"
	if d.Host.Addr.IsValid() {
		arrives = host + "'s " + d.Host.Addr.String()
		reachable = d.Host.Addr.String()
		if d.Host.Iface != "" {
			arrives += " (" + d.Host.Iface + ")"
		}
	}
	service := "the host service"
	if host != "the host" {
		service = "the service in " + host
	}
	f.Title = fmt.Sprintf("%s on port %d listens only on %s", service, port, socketList(socks))
	f.Explanation = fmt.Sprintf("On %s, port %d is served only on %s, which accepts connections from %s itself. %s's connection to %s arrives at %s, where nothing listens.",
		host, port, socketList(socks), host, srcName, v.Question().To.String(), arrives)
	switch {
	case d.Host.Via == evidence.HostViaName:
		// host.docker.internal without a mapping doesn't resolve on Docker
		// Engine (WR011): this is what happens once it does.
		f.Explanation = fmt.Sprintf("On %s, port %d is served only on %s, which accepts connections from %s itself. Once %s resolves in %s (WR011), its connections will arrive at %s's address, where nothing listens.",
			host, port, socketList(socks), host, v.Question().To.Host, srcName, host)
	case refused:
		f.Explanation = strings.TrimSuffix(f.Explanation, ".") + ", so it is refused."
	}
	contradictedByPath(v, &f)
	f.Fix = fmt.Sprintf("Make %s listen on %s too, or on 0.0.0.0 (then mind the firewall), and restart it. For PostgreSQL, for example: listen_addresses = 'localhost,%s' and a host line for the containers' subnet in pg_hba.conf.",
		service, reachable, reachable)
	return []Finding{f}
}

// platformOf returns where whyreach and Docker's containers run, and the
// records that show it: the platform record (INITIAL.md §3.7), or, in
// evidence made before it existed, what the daemon's identity implies.
func platformOf(v evidence.View) (evidence.Platform, []string, bool) {
	if p, ok := v.Platform(); ok {
		return p.P, []string{p.ID}, true
	}
	for _, e := range v.Of(evidence.KindDockerVersion) {
		if dv, ok := e.Data.(evidence.DockerVersion); ok && e.OK() {
			p := evidence.Platform{Name: "other", Desktop: strings.Contains(dv.PlatformName, "Desktop")}
			if dv.LinuxEngine {
				p.Name = evidence.PlatformLinuxEngine
			}
			return p, []string{e.ID}, true
		}
	}
	return evidence.Platform{}, nil, false
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
