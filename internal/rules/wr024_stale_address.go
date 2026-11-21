package rules

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR024: the source aims at an address on one of its own networks that no
// container holds: a stale or hard-coded container IP, given literally or
// through extra_hosts. Docker hands out addresses as containers start, so a
// recreated container may come back with another one, and nothing answers
// at the old one: a connect fails with "no route to host" (EHOSTUNREACH)
// once ARP gives up, after about 3 s, on normal and internal networks
// alike (measured on Engine 29.9.3; rule experiments, E8). whyreach's
// connect gives up after 2 s, so it usually times out first. Metadata
// infers it (medium); a connect from the source that got no answer
// confirms it (high), and one that reached something rules it out (Probe?
// partly). It supersedes WR016: nothing answers there, which explains a
// timeout. The catalog row's other half, an app's sockets still pointing
// at an old address it looked up once, needs the source's connection table
// and isn't built yet.
type wr024 struct{}

func (wr024) ID() string                { return "WR024" }
func (wr024) Layer() Layer              { return LayerAddressing }
func (wr024) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }
func (wr024) Supersedes() []string      { return []string{"WR016"} }

// maxNamed bounds the containers a WR024 finding names on the network.
const maxNamed = 6

func (r wr024) Evaluate(v evidence.View) []Finding {
	q := v.Question()
	src, ok := v.Source()
	if !ok {
		return nil
	}
	owner, ok := v.NetnsOwner()
	if !ok || owner.C.HostNetwork() {
		return nil
	}
	d := v.Destinations()
	if d.Host != nil || len(d.All()) > 0 {
		return nil // the host, or a container holds it
	}
	addr, ok := targetAddr(q, d)
	if !ok {
		return nil
	}
	network, ok := owner.C.SubnetHolding(addr)
	if !ok {
		return nil // off the source's networks: WR015's when they are internal
	}
	if att, _ := owner.C.Attachment(network); att.IsGateway(addr) {
		return nil // the bridge's own side: the host, or Docker Desktop's VM
	}
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()),
		Confidence: Medium,
		Supporting: []string{src.ID, owner.ID},
	}
	// A connect from the source to that address. Anything that answered,
	// even with a refusal, holds it: a host whyreach doesn't know as a
	// container. No answer confirms it: "no route to host" once ARP gives
	// up, or whyreach's own timeout before that.
	noAnswer, other := "", ""
	for _, t := range v.SourceTCP() {
		if !t.P.ByName() || t.P.Addr.Addr().Unmap() != addr {
			continue
		}
		switch t.P.Outcome {
		case evidence.OutcomeConnected, evidence.OutcomeRefused, evidence.OutcomeClosed, evidence.OutcomeReset:
			return nil
		case evidence.OutcomeUnreachable:
			if t.P.Errno != "EHOSTUNREACH" {
				other = cmp.Or(other, cmp.Or(t.P.Errno, t.P.Outcome))
				f.Contradicting = append(f.Contradicting, t.ID)
				continue
			}
			noAnswer = `failed with "no route to host" (EHOSTUNREACH): nothing on the network answered for it`
			f.Supporting = append(f.Supporting, t.ID)
		case evidence.OutcomeTimeout:
			noAnswer = cmp.Or(noAnswer, `timed out: nothing on the network answered for it (Linux gives up on such an address after about 3 s, with "no route to host")`)
			f.Supporting = append(f.Supporting, t.ID)
		}
	}
	if noAnswer != "" {
		f.Confidence = High
	}
	incomplete := v.Incomplete()
	peers, peerIDs := containersOn(v, owner.C, network)
	f.Supporting = append(f.Supporting, peerIDs...)

	srcName := src.C.DisplayName()
	target := hostPort(addr.String(), q.To.Port)
	where := network
	if !evidence.UserDefined(network) {
		where = "the default bridge"
	}
	var expl strings.Builder
	if d.HostsEntry != "" {
		fmt.Fprintf(&expl, "%s's extra_hosts map %s to %s, an address on %s", owner.C.DisplayName(), q.To.Host, addr, where)
		f.Title = fmt.Sprintf("%s's extra_hosts map %s to %s, which no container holds", owner.C.DisplayName(), q.To.Host, addr)
	} else {
		fmt.Fprintf(&expl, "%s connects to %s, an address on %s", srcName, target, where)
		f.Title = fmt.Sprintf("no container holds %s, the address %s aims at", addr, srcName)
	}
	fmt.Fprintf(&expl, ", but no container holds it now. Docker hands out addresses as containers start, so a recreated container can come back with another one, and an address written into configuration goes stale.")
	switch {
	case len(peers) > 0:
		fmt.Fprintf(&expl, " On %s now: %s.", where, quoteList(peers))
	case !incomplete:
		fmt.Fprintf(&expl, " No other container is on %s now.", where)
	}
	if noAnswer != "" {
		fmt.Fprintf(&expl, " %s's connect %s.", srcName, noAnswer)
	}
	if other != "" {
		f.Confidence = f.Confidence.Lower()
		fmt.Fprintf(&expl, " But a connect from %s ended in %s, not \"no route to host\": something else may be wrong as well.", srcName, other)
	}
	if incomplete {
		f.Confidence = f.Confidence.Lower()
		expl.WriteString(" Some containers' metadata could not be read or was skipped, so one of them might hold it.")
	}
	f.Supporting = ids(f.Supporting...)
	f.Contradicting = ids(f.Contradicting...)
	f.Explanation = expl.String()
	f.Fix = wr024Fix(v, src.C, owner.C, network, addr, q.To.Port, d.HostsEntry != "")
	return []Finding{f}
}

// containersOn names the containers on a network other than owner, with
// their addresses there ("api (172.18.0.3)"), sorted, at most maxNamed,
// and the records that show them.
func containersOn(v evidence.View, owner evidence.Container, network string) ([]string, []string) {
	type named struct{ name, id string }
	var all []named
	for _, c := range v.Containers() {
		if c.C.ID == owner.ID {
			continue
		}
		a, ok := c.C.Attachment(network)
		if !ok {
			continue
		}
		var at []string
		for _, ip := range []netip.Addr{a.IPv4, a.IPv6} {
			if ip.IsValid() {
				at = append(at, ip.String())
			}
		}
		name := c.C.DisplayName()
		if len(at) > 0 {
			name += " (" + strings.Join(at, ", ") + ")"
		} else {
			name += " (" + c.C.State + ", no address)"
		}
		all = append(all, named{name, c.ID})
	}
	slices.SortFunc(all, func(a, b named) int { return strings.Compare(a.name, b.name) })
	var names, evIDs []string
	for i, n := range all {
		if i == maxNamed {
			names = append(names, fmt.Sprintf("%d more", len(all)-maxNamed))
			break
		}
		names, evIDs = append(names, n.name), append(evIDs, n.id)
	}
	return names, evIDs
}

// wr024Fix points the source at a name, which Docker's DNS keeps up to
// date, instead of the address.
func wr024Fix(v evidence.View, src, owner evidence.Container, network string, addr netip.Addr, port uint16, hostsEntry bool) string {
	q := v.Question()
	name := src.DisplayName()
	recreate := "restart it so it reads its configuration again"
	if src.Compose != nil {
		recreate = fmt.Sprintf("recreate it (docker compose up -d %s)", src.Compose.Service)
	}
	if !evidence.UserDefined(network) {
		return fmt.Sprintf("On the default bridge, containers can't reach each other by name, and their addresses change when they are recreated. Attach %s and the service it needs to a user-defined network (Compose gives each project one), connect by the service's name instead of %s, and %s.",
			name, addr, recreate)
	}
	if hostsEntry {
		fix := fmt.Sprintf("Remove the extra_hosts entry that maps %s to %s from %s, so Docker's DNS answers %s with its current address", q.To.Host, addr, owner.DisplayName(), q.To.Host)
		if who := answering(v, owner, network, q.To.Host); who != "" {
			fix += fmt.Sprintf(" (%s answers to it on %s)", who, network)
		}
		recreateOwner := "recreate it"
		if owner.Compose != nil {
			recreateOwner = fmt.Sprintf("recreate it (docker compose up -d %s)", owner.Compose.Service)
		}
		return fix + ", then " + recreateOwner + "."
	}
	fix := fmt.Sprintf("Connect by name instead of by address: Docker's DNS on %s answers a service's name with its current address. Wherever %s's configuration has %s, use the name of the service that held it", network, name, addr)
	up, down := others(v, owner, network)
	if len(up) == 1 && len(down) == 0 {
		fix += fmt.Sprintf(" (probably %s, the only other container on %s)", hostPort(up[0], port), network)
	}
	fix += ", then " + recreate + "."
	switch len(down) {
	case 0:
	case 1:
		fix += fmt.Sprintf(" %s on %s isn't running: if the address was its, start it as well; it may come back with another address, which is why the name matters.", down[0], network)
	default:
		fix += fmt.Sprintf(" %s on %s aren't running: if the address was one of theirs, start that one as well; it may come back with another address, which is why the name matters.", quoteList(down), network)
	}
	return fix
}

// answering names the running containers on a network, other than owner,
// that Docker's DNS answers name for there.
func answering(v evidence.View, owner evidence.Container, network, name string) string {
	var out []string
	for _, c := range v.Containers() {
		if c.C.ID != owner.ID && c.C.Running() && slices.Contains(c.C.AnswersTo(name), network) {
			out = append(out, c.C.DisplayName())
		}
	}
	slices.Sort(out)
	return quoteList(slices.Compact(out))
}

// others lists the display names of the containers on a network other
// than owner, sorted: those that are up, and those that aren't.
func others(v evidence.View, owner evidence.Container, network string) (up, down []string) {
	for _, c := range v.Containers() {
		if _, ok := c.C.Attachment(network); !ok || c.C.ID == owner.ID {
			continue
		}
		if c.C.Up() {
			up = append(up, c.C.DisplayName())
		} else {
			down = append(down, c.C.DisplayName())
		}
	}
	slices.Sort(up)
	slices.Sort(down)
	return slices.Compact(up), slices.Compact(down)
}
