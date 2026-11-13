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
	dst := d.Elsewhere[0]
	srcName, dstName := src.C.DisplayName(), dst.C.DisplayName()
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()),
		Confidence: High,
		Title:      fmt.Sprintf("%s and %s share no network", srcName, dstName),
		Supporting: []string{src.ID, owner.ID},
	}
	for _, m := range d.Elsewhere {
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

	srcNets := owner.C.NetworkNames()
	dstNets := dst.Networks
	where := func(c evidence.Container, nets []string) string {
		s := fmt.Sprintf("%s %s", plural(len(nets), "network", "networks"), quoteList(nets))
		if p := projectOf(c); p != "" {
			s += fmt.Sprintf(" (Compose project %s)", p)
		}
		return s
	}
	var expl strings.Builder
	fmt.Fprintf(&expl, "%s is on %s, and %s only on %s. ", containerLabel(dst.C), where(dst.C, dstNets), srcName, where(owner.C, srcNets))
	expl.WriteString("Containers reach each other only over a shared network: across networks names don't resolve and traffic is dropped, so connections time out.")
	if len(d.Elsewhere) > 1 {
		var others []string
		for _, m := range d.Elsewhere[1:] {
			others = append(others, fmt.Sprintf("%s (%s)", m.C.Name, quoteList(m.Networks)))
		}
		fmt.Fprintf(&expl, " %s also matches %s, also on no network %s is on.", q.To.Host, quoteList(others), srcName)
	}
	f.Explanation = expl.String()

	net := dstNets[0]
	f.Fix = fmt.Sprintf("Put %s on %s's network: in %s's Compose file, declare networks: {%s: {external: true}} and list %s under the %s service's networks (keep default too if it needs its own services). Or run both services in one Compose project. To test without editing files: docker network connect %s %s.",
		srcName, dstName, srcName, net, net, srcName, net, src.C.Name)
	return []Finding{f}
}
