package rules

import (
	"fmt"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR006: a host-published port is used between containers. A mapping such
// as 18090:8080 applies only to traffic arriving from the host side; another
// container on a shared network must use the container port, 8080. The
// variant: reaching a published port through the host's address, which
// fails when it is published on loopback only. Port bindings settle it.
// Frequency rank 17.
type wr006 struct{}

func (wr006) ID() string                { return "WR006" }
func (wr006) Layer() Layer              { return LayerAddressing }
func (wr006) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }

// Supersedes: the destination listens on the container port, not the
// published one (WR003); the loopback "host service" is the published port
// (WR012).
func (wr006) Supersedes() []string { return []string{"WR003", "WR012"} }

func (r wr006) Evaluate(v evidence.View) []Finding {
	if v.HostSource() || connectedByName(v) {
		return nil
	}
	src, ok := v.Source()
	if !ok {
		return nil
	}
	port := v.Question().To.Port
	d := v.Destinations()
	if d.Host != nil {
		return r.throughHost(v, src, d)
	}
	for _, m := range d.OnSourceNets {
		b := m.C.PublishedAs(port)
		if len(b) == 0 || b[0].ContainerPort == port {
			continue
		}
		l, haveL := v.ListenersIn(m.C.ID)
		if haveL && len(l.L.OnPort(port)) > 0 {
			return nil // it listens on that number inside too
		}
		f := Finding{
			RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: Medium,
			Supporting: []string{src.ID, m.ID},
		}
		cport := b[0].ContainerPort
		if haveL {
			f.Supporting = append(f.Supporting, l.ID)
			if l.L.AcceptsRemote(cport) {
				f.Confidence = High
			}
		}
		f.Supporting = refusedFrom(v, f.Supporting)
		name := m.C.DisplayName()
		f.Title = fmt.Sprintf("%d is %s's port on %s; between containers use %d", port, name, v.HostLabel(), cport)
		f.Explanation = fmt.Sprintf("%s publishes its port %d on %s as %s. That mapping applies only to connections arriving at %s; %s reaches %s directly over network %s, where the port is %d.",
			containerLabel(m.C), cport, v.HostLabel(), publishedList(b), v.HostLabel(), src.C.DisplayName(), name, strings.Join(m.Shared, ", "), cport)
		f.Fix = fmt.Sprintf("Connect to %s instead of %s: containers on a shared network use the container port.", hostPort(v.Question().To.Host, cport), v.Question().To.String())
		return []Finding{f}
	}
	return nil
}

// throughHost is the variant: the target is the host, and the port is a
// container's port published on the host's loopback only.
func (r wr006) throughHost(v evidence.View, src evidence.ContainerEv, d evidence.Destinations) []Finding {
	if len(d.Published) > 0 {
		return nil // published where the connection arrives
	}
	if p, _, ok := platformOf(v); ok && p.Desktop {
		return nil // Docker Desktop forwards the host's loopback to containers (INITIAL.md §3.7)
	}
	port := v.Question().To.Port
	for _, c := range v.Containers() {
		b := c.C.PublishedAs(port)
		if len(b) == 0 {
			continue
		}
		for _, pm := range b {
			if !pm.LoopbackOnly() {
				return nil
			}
		}
		f := Finding{
			RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()), Confidence: High,
			Supporting: append([]string{src.ID, c.ID}, d.Host.Evidence...),
		}
		f.Supporting = refusedFrom(v, f.Supporting)
		name := c.C.DisplayName()
		cport := b[0].ContainerPort
		f.Title = fmt.Sprintf("%s publishes %d only on %s's loopback", name, port, v.HostLabel())
		f.Explanation = fmt.Sprintf("%s publishes its port %d on %s as %s: only %s itself can use that. %s's connection to %s arrives at another of its addresses, where nothing publishes it.",
			containerLabel(c.C), cport, v.HostLabel(), publishedList(b), v.HostLabel(), src.C.DisplayName(), v.Question().To.String())
		owner, _ := v.NetnsOwner()
		if shared := sharedNetworks(owner.C, c.C); len(shared) > 0 {
			f.Fix = fmt.Sprintf("Connect to %s directly over network %s instead of through the host.", hostPort(name, cport), shared[0])
		} else {
			f.Fix = fmt.Sprintf("Put %s and %s on one network and connect to %s, or publish the port on every address: ports: [\"%d:%d\"].",
				src.C.DisplayName(), name, hostPort(name, cport), port, cport)
		}
		return []Finding{f}
	}
	return nil
}

func publishedList(b []evidence.PortMap) string {
	var out []string
	for _, pm := range b {
		out = append(out, pm.HostAddr())
	}
	return strings.Join(out, " and ")
}

// refusedFrom adds the source's refused or closed connects to ids.
func refusedFrom(v evidence.View, in []string) []string {
	return ids(append(in, sourceConnects(v, evidence.OutcomeRefused, evidence.OutcomeClosed)...)...)
}
