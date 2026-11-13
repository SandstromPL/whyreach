package rules

import (
	"fmt"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR011: host.docker.internal doesn't resolve on Docker Engine. Docker
// Desktop provides the name; on Docker Engine a container has it only with
// extra_hosts: ["host.docker.internal:host-gateway"]. Metadata settles it,
// and a failed lookup from the source confirms it (Probe? partly). It never
// fires on Docker Desktop (INITIAL.md §3.7). Frequency rank 7.
type wr011 struct{}

func (wr011) ID() string   { return "WR011" }
func (wr011) Layer() Layer { return LayerAddressing }
func (wr011) Requires() []evidence.Kind {
	return []evidence.Kind{evidence.KindContainer, evidence.KindDockerVersion}
}
func (wr011) Supersedes() []string { return []string{"WR005", "WR016"} }

func (r wr011) Evaluate(v evidence.View) []Finding {
	q := v.Question()
	if !evidence.IsHostDockerInternal(q.To.Host) {
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
	if _, mapped := owner.C.HostsEntry(q.To.Host); mapped {
		return nil
	}
	ver, ok := dockerVersion(v)
	if !ok || !ver.LinuxEngine {
		return nil // Docker Desktop answers the name itself
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: Medium,
		Supporting: []string{src.ID, owner.ID},
	}
	for _, e := range v.Of(evidence.KindDockerVersion) {
		f.Supporting = append(f.Supporting, e.ID)
	}
	confirmed := ""
	if dns, ok := v.SourceDNS(q.To.Host); ok {
		if len(dns.P.Answers) > 0 {
			return nil // something resolves it (a custom DNS server?)
		}
		f.Confidence = High
		f.Supporting = append(f.Supporting, dns.ID)
		confirmed = fmt.Sprintf(" The lookup in %s failed (%s from %s).", src.C.DisplayName(), dns.P.Rcode, dns.P.Server)
	}
	f.Supporting = ids(f.Supporting...)
	name := src.C.DisplayName()
	f.Title = fmt.Sprintf("%s doesn't exist in %s: Docker Engine needs a host-gateway mapping", evidence.HostDockerInternal, name)
	f.Explanation = fmt.Sprintf("Docker Desktop provides the name %s, but Docker Engine (this host, %s) adds it to a container only with extra_hosts: [\"host.docker.internal:host-gateway\"], and %s has no such entry.%s",
		evidence.HostDockerInternal, ver.Version, owner.C.DisplayName(), confirmed)
	gw := "the host's docker0 address"
	if ha, ok := v.HostAddrs(); ok {
		if i, ok := ha.H.Interface(evidence.DefaultBridge); ok {
			if a, ok := i.IPv4(); ok {
				gw = fmt.Sprintf("the host's docker0 address, %s", a)
				f.Supporting = ids(append(f.Supporting, ha.ID)...)
			}
		}
	}
	f.Fix = fmt.Sprintf("Give %s extra_hosts: [\"host.docker.internal:host-gateway\"] in Compose (docker run: --add-host=host.docker.internal:host-gateway), then recreate it: docker compose up -d %s. The name then points at %s, so the host service must listen there or on 0.0.0.0.",
		owner.C.DisplayName(), owner.C.DisplayName(), gw)
	return []Finding{f}
}
