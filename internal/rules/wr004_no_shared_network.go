package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR004: the source and the destination share no network, typically because
// they are in separate Compose projects. Docker metadata settles it: the
// target matches a container, but only on networks the source is not on.
// Between networks, names don't resolve and traffic is silently dropped, so a
// connect by address times out; that timeout is a consequence (it supersedes
// WR016). Frequency rank 2.
type wr004 struct{}

func (wr004) ID() string                { return "WR004" }
func (wr004) Layer() Layer              { return LayerNaming }
func (wr004) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }
func (wr004) Supersedes() []string      { return []string{"WR005", "WR016"} }

func (r wr004) Evaluate(v evidence.View) []Finding {
	q := v.Question()
	if q.To.Class == evidence.TargetLoopback {
		return nil
	}
	src, ok := v.Source()
	if !ok {
		return nil
	}
	owner, ok := v.NetnsOwner()
	if !ok || owner.C.HostNetwork() || owner.C.NetworkMode == "none" || len(owner.C.Networks) == 0 {
		return nil
	}
	d := v.Destinations()
	if len(d.OnSourceNets) > 0 || len(d.Elsewhere) == 0 {
		return nil
	}
	if connectedByName(v) {
		return nil // the name reaches something after all
	}
	// A destination in network_mode host or container:X shares another
	// network namespace: "join its network" is the wrong advice there, and
	// M1 has no rule for those cases yet.
	var cands []evidence.Match
	for _, m := range d.Elsewhere {
		if !m.C.HostNetwork() && m.C.NetnsOwner() == "" {
			cands = append(cands, m)
		}
	}
	if len(cands) == 0 {
		return nil
	}
	dst := cands[0]
	srcName, dstName := src.C.DisplayName(), dst.C.DisplayName()
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()),
		Confidence: High,
		Title:      fmt.Sprintf("%s and %s share no network", srcName, dstName),
		Supporting: []string{src.ID, owner.ID},
	}
	for _, m := range cands {
		f.Supporting = append(f.Supporting, m.ID)
	}

	// The probe confirms: the name does not resolve from the source, and the
	// destination's own address is unreachable from it.
	dstAddrs := dst.C.Addrs()
	if q.To.Class == evidence.TargetName {
		if dns, ok := dnsFromSource(v, q.To.Host); ok {
			foreign := false
			for _, a := range dns.P.Answers {
				if !slices.Contains(dstAddrs, a) {
					foreign = true
				}
			}
			switch {
			case len(dns.P.Answers) == 0:
				f.Supporting = append(f.Supporting, dns.ID)
			case foreign:
				// The name resolves, but to something that is not the
				// destination: maybe the user meant that other host.
				f.Contradicting = append(f.Contradicting, dns.ID)
				f.Confidence = f.Confidence.Lower()
			}
		}
	}
	for _, t := range fromSource(v) {
		if slices.Contains(dstAddrs, t.P.Addr.Addr()) && t.P.Outcome != evidence.OutcomeConnected {
			f.Supporting = append(f.Supporting, t.ID)
		}
	}
	f.Supporting = ids(f.Supporting...)
	f.Contradicting = ids(f.Contradicting...)

	where := func(c evidence.Container) string {
		nets := c.NetworkNames()
		s := "no network"
		if len(nets) > 0 {
			s = fmt.Sprintf("%s %s", plural(len(nets), "network", "networks"), quoteList(nets))
		}
		if p := projectOf(c); p != "" {
			s += fmt.Sprintf(" (Compose project %s)", p)
		}
		return s
	}
	var expl strings.Builder
	fmt.Fprintf(&expl, "%s is on %s, and %s only on %s. ", containerLabel(dst.C), where(dst.C), srcName, where(owner.C))
	expl.WriteString("Containers reach each other only over a shared network: across networks names don't resolve and traffic is dropped, so connections time out.")
	if len(cands) > 1 {
		var others []string
		for _, m := range cands[1:] {
			others = append(others, fmt.Sprintf("%s (%s)", m.C.Name, quoteList(m.C.NetworkNames())))
		}
		fmt.Fprintf(&expl, " %s also matches %s, also on no network %s is on.", q.To.Host, quoteList(others), srcName)
	}
	f.Explanation = expl.String()
	f.Fix = wr004Fix(src.C, owner.C, dst.C)
	return []Finding{f}
}

// wr004Fix picks the network to share. Joining the destination's network
// works only for a user-defined one: the default bridge has no name
// resolution, and a network_mode: none container can't join anything.
func wr004Fix(src, owner, dst evidence.Container) string {
	srcName, dstName := src.DisplayName(), dst.DisplayName()
	srcNets := owner.UserDefinedNetworks()
	switch {
	case dst.NetworkMode == evidence.NetworkNone:
		if len(srcNets) > 0 {
			return fmt.Sprintf("%s runs with network_mode: none, so nothing can reach it. Remove network_mode: none and attach it to %s's network %s (in Compose, list %s under its networks).",
				dstName, srcName, srcNets[0], srcNets[0])
		}
		return fmt.Sprintf("%s runs with network_mode: none, so nothing can reach it. Remove network_mode: none and attach both containers to one user-defined network.", dstName)
	case len(dst.UserDefinedNetworks()) > 0:
		net := dst.UserDefinedNetworks()[0]
		return fmt.Sprintf("Put %s on %s's network: in %s's Compose file, declare networks: {%s: {external: true}} and list %s under the %s service's networks (keep default too if it needs its own services). Or run both services in one Compose project. To test without editing files: docker network connect %s %s.",
			srcName, dstName, srcName, net, net, srcName, net, src.Name)
	case len(srcNets) > 0:
		return fmt.Sprintf("%s is only on Docker's default bridge network, where names don't resolve. Attach it to %s's network instead: docker network connect %s %s (or run it as a service in %s's Compose project), then use the name %s.",
			dstName, srcName, srcNets[0], dst.Name, srcName, dst.Name)
	default:
		return fmt.Sprintf("Create a user-defined network (docker network create app) and attach both containers to it (docker network connect app %s; docker network connect app %s): the default bridge network has no name resolution.",
			src.Name, dst.Name)
	}
}
