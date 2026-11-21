package rules

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR015: the source is only on internal: true networks, and the target lies
// outside them. Docker gives a container on internal networks no route out:
// it reaches the containers on those networks, and the host only through a
// network's own gateway address, which is on the network's subnet. A
// connect to anything else fails at once with "network is unreachable"
// (ENETUNREACH), and Docker's DNS doesn't forward outside names from there:
// it answers SERVFAIL at once (both measured on Engine 29.9.3). Docker
// metadata settles it (Probe? no): the networks' internal flags and
// subnets, and what the target is. It supersedes WR016: a path that doesn't
// exist explains a failed connect.
type wr015 struct{}

func (wr015) ID() string                { return "WR015" }
func (wr015) Layer() Layer              { return LayerPath }
func (wr015) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }
func (wr015) Supersedes() []string      { return []string{"WR016"} }

func (r wr015) Evaluate(v evidence.View) []Finding {
	q := v.Question()
	if q.To.Class == evidence.TargetLoopback {
		return nil
	}
	src, ok := v.Source()
	if !ok {
		return nil
	}
	owner, ok := v.NetnsOwner()
	if !ok || owner.C.HostNetwork() || !onlyInternal(owner.C) {
		return nil
	}
	nets := internalNets(owner.C)
	out, ok := outsideOf(v, owner, "outside "+quoteList(nets))
	if !ok {
		return nil
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()),
		Confidence: High,
		Supporting: append([]string{src.ID, owner.ID}, out.ids...),
	}
	// A connect through the name or address the app uses. Accepted or
	// refused, it found a route after all. "Network is unreachable" is the
	// internal network's signature; a timeout or "no route to host" means
	// the kernel had a route, so something else stopped it.
	unreachable, other := false, ""
	for _, t := range v.SourceTCP() {
		if !t.P.ByName() {
			continue
		}
		switch t.P.Outcome {
		case evidence.OutcomeConnected, evidence.OutcomeRefused, evidence.OutcomeClosed, evidence.OutcomeReset:
			return nil
		case evidence.OutcomeUnreachable:
			if t.P.Errno == "ENETUNREACH" {
				unreachable = true
				f.Supporting = append(f.Supporting, t.ID)
				continue
			}
			other = cmp.Or(other, `"no route to host"`)
			f.Contradicting = append(f.Contradicting, t.ID)
		case evidence.OutcomeTimeout:
			other = cmp.Or(other, "a timeout")
			f.Contradicting = append(f.Contradicting, t.ID)
		}
	}
	srcName := src.C.DisplayName()
	var expl strings.Builder
	if owner.C.ID != src.C.ID {
		fmt.Fprintf(&expl, "%s uses %s's network namespace (network_mode: container:%s), and %s", srcName, owner.C.Name, owner.C.Name, owner.C.Name)
	} else {
		expl.WriteString(srcName)
	}
	fmt.Fprintf(&expl, " is only on %s. Docker gives containers on internal networks no route out: they reach the other containers there, but nothing outside those networks. %s.", netPhrase(nets), out.what)
	if unreachable {
		fmt.Fprintf(&expl, " %s's connect failed at once with \"network is unreachable\" (ENETUNREACH).", srcName)
	}
	if out.dns != "" {
		expl.WriteString(" " + out.dns)
	}
	if other != "" {
		f.Confidence = f.Confidence.Lower()
		fmt.Fprintf(&expl, " But a connect from %s ended in %s, not \"network is unreachable\", so the kernel had a route: something else may stop it as well.", srcName, other)
	}
	if out.name && v.Incomplete() {
		f.Confidence = f.Confidence.Lower()
		expl.WriteString(" Some containers' metadata could not be read or was skipped, so one of them on those networks might answer to the name.")
	}
	f.Supporting = ids(f.Supporting...)
	f.Contradicting = ids(f.Contradicting...)
	f.Title = fmt.Sprintf("%s is only on %s, which can't reach %s", srcName, netPhrase(nets), q.To.String())
	f.Explanation = expl.String()
	f.Fix = wr015Fix(src.C, owner.C, nets, out.host)
	return []Finding{f}
}

// outside describes how the target lies outside the source's networks.
type outside struct {
	what string   // for the explanation: what the target is
	dns  string   // what the source's lookup of a name showed, if it ran
	ids  []string // the records that show it
	name bool     // a name no container answers to
	host bool     // the host
}

// outsideOf decides whether the target lies outside the networks of the
// source's netns owner; beyond says where ("outside shop_backend"). A
// container is not outside: on the owner's networks it is reachable, and
// elsewhere WR004 explains it. Neither is anything on the owner's subnets:
// the host through a network's own gateway address (measured: reachable),
// or an address no container holds (a stale address: WR024's). A
// single-label name no container answers to is more likely mistyped
// (WR005).
func outsideOf(v evidence.View, owner evidence.ContainerEv, beyond string) (outside, bool) {
	q := v.Question()
	d := v.Destinations()
	if len(d.OnSourceNets) > 0 || len(d.Elsewhere) > 0 {
		return outside{}, false
	}
	onSubnet := func(addrs ...netip.Addr) bool {
		return slices.ContainsFunc(addrs, func(a netip.Addr) bool {
			_, ok := owner.C.SubnetHolding(a)
			return ok
		})
	}
	if h := d.Host; h != nil {
		if onSubnet(h.Addresses()...) {
			return outside{}, false
		}
		return outside{what: hostWhat(v, owner.C, *h) + ", " + beyond, ids: h.Evidence, host: true}, true
	}
	switch q.To.Class {
	case evidence.TargetIP:
		if onSubnet(q.To.Addr) {
			return outside{}, false
		}
		return outside{what: q.To.Host + " is an address " + beyond}, true
	case evidence.TargetName:
		if d.HostsEntry != "" {
			a, err := netip.ParseAddr(d.HostsEntry)
			if err != nil || onSubnet(a.Unmap()) {
				return outside{}, false // host-gateway is the host, which the view reports above
			}
			return outside{
				what: fmt.Sprintf("%s's extra_hosts map %s to %s, an address %s", owner.C.DisplayName(), q.To.Host, a.Unmap(), beyond),
				ids:  []string{owner.ID},
			}, true
		}
		if singleLabel(q.To.Host) {
			return outside{}, false
		}
		out := outside{what: q.To.Host + " is a name outside Docker: no container on any network answers to it", name: true}
		if dns, ok := v.SourceDNS(q.To.Host); ok {
			if onSubnet(dns.P.Answers...) {
				return outside{}, false // it resolves to an address on the source's networks after all
			}
			out.ids = append(out.ids, dns.ID)
			if len(dns.P.Answers) == 0 && dns.P.Rcode == "SERVFAIL" && dns.P.AtDockerDNS() {
				out.dns = "Looking it up, Docker's DNS answered SERVFAIL: it doesn't forward lookups from internal networks."
			}
		}
		return out, true
	}
	return outside{}, false
}

// hostWhat says how the target stands for the host.
func hostWhat(v evidence.View, owner evidence.Container, h evidence.HostTarget) string {
	t := v.Question().To.Host
	var at []string
	if h.Addr.IsValid() && h.Addr.Unmap().String() != t {
		at = append(at, h.Addr.Unmap().String())
	}
	if h.Iface != "" {
		at = append(at, "on "+h.Iface)
	}
	detail := ""
	if len(at) > 0 {
		detail = " (" + strings.Join(at, " ") + ")"
	}
	switch h.Via {
	case evidence.HostViaGateway:
		return fmt.Sprintf("%s is the host: %s's extra_hosts map it to host-gateway%s", t, owner.DisplayName(), detail)
	case evidence.HostViaAddress:
		return fmt.Sprintf("%s is one of %s's own addresses%s", t, v.HostLabel(), detail)
	default:
		return fmt.Sprintf("%s is the host", t)
	}
}

// internalNets lists a container's internal networks.
func internalNets(c evidence.Container) []string {
	var out []string
	for _, a := range c.Networks {
		if a.Internal {
			out = append(out, a.Network)
		}
	}
	return out
}

// netPhrase names internal networks for prose: "the internal network
// shop_backend", "the internal networks a and b".
func netPhrase(nets []string) string {
	return fmt.Sprintf("the internal %s %s", plural(len(nets), "network", "networks"), quoteList(nets))
}

// wr015Fix gives the netns owner a way out, and keeps the internal networks
// for what must stay cut off.
func wr015Fix(src, owner evidence.Container, nets []string, host bool) string {
	var keys []string
	for _, n := range nets {
		keys = append(keys, stripProject(projectOf(owner), n))
	}
	name := owner.DisplayName()
	var fix string
	if owner.Compose != nil {
		// Compose's default network is the usual way out, unless it is
		// the internal one; then a network of its own.
		out, declare := "default", ""
		if slices.Contains(keys, "default") {
			out, declare = "outside", " (declared under the top-level networks: without internal: true)"
		}
		fix = fmt.Sprintf("Give %s a way out: in Compose, also attach the %s service to a network without internal: true, for example networks: [%s, %s]%s, and keep %s internal: true for the services that must stay cut off. Then recreate it (docker compose up -d %s).",
			name, name, strings.Join(keys, ", "), out, declare, quoteList(keys), name)
	} else {
		fix = fmt.Sprintf("Give %s a way out: also connect it to a network without internal: true (docker network connect <network> %s; the default bridge works too), and keep %s internal: true for the containers that must stay cut off.",
			name, owner.Name, quoteList(nets))
	}
	if owner.ID != src.ID {
		fix = fmt.Sprintf("%s uses %s's network namespace, so the change is %s's. %s", src.DisplayName(), owner.Name, owner.Name, fix)
	}
	if host {
		fix += fmt.Sprintf(" If %s must stay cut off from the outside, run the host service it needs as a container on %s instead.", name, quoteList(keys))
	}
	return fix
}
