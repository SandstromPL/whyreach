package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR020: the container's upstream DNS fails. Docker's embedded DNS answers
// the names it knows (containers, services, aliases) itself and forwards the
// rest to upstream servers (ExtServers in the container's resolv.conf). When
// those don't answer, internal names resolve and external ones time out.
// Only a lookup from the source shows it (Probe? yes). Frequency rank 3.
type wr020 struct{}

func (wr020) ID() string   { return "WR020" }
func (wr020) Layer() Layer { return LayerNaming }
func (wr020) Requires() []evidence.Kind {
	return []evidence.Kind{evidence.KindContainer, evidence.KindDNS}
}
func (wr020) Supersedes() []string { return nil }

func (r wr020) Evaluate(v evidence.View) []Finding {
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
		return nil // its resolver is the host's: not a container's upstream
	}
	d := v.Destinations()
	if len(d.All()) > 0 || d.Host != nil || d.HostsEntry != "" {
		return nil // an internal name, or the host
	}
	if onlyInternal(owner.C) {
		return nil // internal: true networks have no way out, and Docker's DNS doesn't forward from them (WR015, v0.2)
	}
	dns, ok := v.SourceDNS(q.To.Host)
	if !ok || len(dns.P.Answers) > 0 {
		return nil
	}
	failure := upstreamFailure(dns.P, q.To.Host)
	if failure == "" {
		return nil // NXDOMAIN and the like: the upstream answered
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()),
		Supporting: []string{src.ID, owner.ID, dns.ID},
	}
	srcName := src.C.DisplayName()
	embedded := strings.HasPrefix(dns.P.Server, evidence.DockerDNSAddr.String()+":")
	control, haveControl := v.SourceDNS(owner.C.Name)
	if haveControl && control.ID == dns.ID {
		haveControl = false
	}
	var expl strings.Builder
	fmt.Fprintf(&expl, "Looking up %s from %s %s at %s", q.To.Host, srcName, failure, dns.P.Server)
	switch {
	case embedded && haveControl && len(control.P.Answers) > 0:
		f.Confidence = High
		f.Supporting = append(f.Supporting, control.ID)
		fmt.Fprintf(&expl, " (Docker's embedded DNS), while %s's own name resolved there at once. Docker's DNS answers the names it knows itself and forwards the rest to its upstream servers%s, and those don't answer.",
			owner.C.Name, upstreamList(dns.P.Upstream))
	case embedded && haveControl:
		f.Confidence = Medium
		f.Contradicting = append(f.Contradicting, control.ID)
		fmt.Fprintf(&expl, " (Docker's embedded DNS), and even %s's own name did not resolve: Docker's DNS itself may be failing, not only its upstream servers%s.",
			owner.C.Name, upstreamList(dns.P.Upstream))
	case embedded:
		f.Confidence = Medium
		fmt.Fprintf(&expl, " (Docker's embedded DNS), which forwards names it doesn't know to its upstream servers%s; they don't answer.", upstreamList(dns.P.Upstream))
	default:
		f.Confidence = Medium
		fmt.Fprintf(&expl, ", the DNS server %s uses directly (it is on no network with Docker's embedded DNS), and that server doesn't answer.", srcName)
	}
	if failure == "failed (SERVFAIL)" {
		f.Confidence = f.Confidence.Lower() // SERVFAIL can also be that domain's own servers
	}
	f.Supporting = ids(f.Supporting...)
	f.Contradicting = ids(f.Contradicting...)
	f.Title = fmt.Sprintf("%s's upstream DNS doesn't answer: %s does not resolve", srcName, q.To.Host)
	f.Explanation = expl.String()
	f.Fix = wr020Fix(src.C, owner.C, dns.P)
	return []Finding{f}
}

// upstreamFailure says how the lookup failed when the upstream did not
// answer: every query timed out, or the resolver reported a failure.
//
// A single-label name says nothing about the upstream servers: none of them
// resolves one, and what each does with it varies. systemd-resolved's stub
// answers SERVFAIL at once; Docker Desktop's DNS on Windows didn't answer
// within the probe's timeout (WSL2 lab, 2026-11-21). For one, only the
// search-domain names the resolver tried count, since they have dots: when
// every one of those timed out, the upstream doesn't answer. A resolver
// that couldn't be reached at all fails any name.
func upstreamFailure(p evidence.DNSProbe, name string) string {
	if singleLabel(name) && p.Rcode != "ERROR" {
		searched := searchQueries(p)
		if len(searched) > 0 && allTimedOut(searched) {
			return "timed out"
		}
		return ""
	}
	switch {
	case p.Rcode == evidence.RcodeTimeout || (len(p.Attempts) > 0 && allTimedOut(p.Attempts)):
		return "timed out"
	case p.Rcode == "SERVFAIL":
		return "failed (SERVFAIL)"
	case p.Rcode == "ERROR":
		return "failed (the resolver could not be reached)"
	default:
		return ""
	}
}

// singleLabel reports a name without a dot, such as a container's.
func singleLabel(name string) bool {
	return !strings.Contains(strings.TrimSuffix(name, "."), ".")
}

// searchQueries returns the queries of the search-domain names a lookup
// tried ("api.<search 1>"), which have dots, unlike a single-label name.
func searchQueries(p evidence.DNSProbe) []evidence.DNSAttempt {
	var out []evidence.DNSAttempt
	for _, a := range p.Attempts {
		if strings.Contains(a.Query, ".") {
			out = append(out, a)
		}
	}
	return out
}

func allTimedOut(attempts []evidence.DNSAttempt) bool {
	for _, a := range attempts {
		if a.Rcode != evidence.RcodeTimeout {
			return false
		}
	}
	return true
}

func upstreamList(up []string) string {
	if len(up) == 0 {
		return ""
	}
	return " (" + strings.Join(up, ", ") + ")"
}

func wr020Fix(src, owner evidence.Container, p evidence.DNSProbe) string {
	name := src.DisplayName()
	recreate := fmt.Sprintf("then recreate it (docker compose up -d %s)", name)
	switch {
	case len(owner.DNS) > 0:
		return fmt.Sprintf("%s's DNS server is set to %s (dns: in Compose, or --dns), and it doesn't answer. Point dns: at a resolver that works from containers, or remove the setting to use the host's, %s.",
			owner.DisplayName(), strings.Join(owner.DNS, ", "), recreate)
	case slices.ContainsFunc(p.Upstream, func(u string) bool { return strings.Contains(u, "127.0.0.53") }):
		return fmt.Sprintf("Docker forwards to the host's systemd-resolved stub (127.0.0.53), whose upstream doesn't answer: check the host's DNS (resolvectl status), for example after a VPN connected or disconnected, then restart Docker. Or set dns: [<a resolver that works>] for %s, %s.", name, recreate)
	default:
		return fmt.Sprintf("Set dns: [<a resolver that works from containers>] for %s in Compose (or \"dns\" in /etc/docker/daemon.json for every container), %s; or fix the resolvers Docker copied from the host's resolv.conf.", name, recreate)
	}
}

// onlyInternal reports a container whose user-defined networks are all
// internal: true.
func onlyInternal(c evidence.Container) bool {
	n := 0
	for _, a := range c.Networks {
		if !evidence.UserDefined(a.Network) {
			if a.Network == evidence.NetworkBridge {
				return false // the default bridge has a way out
			}
			continue
		}
		if !a.Internal {
			return false
		}
		n++
	}
	return n > 0
}
