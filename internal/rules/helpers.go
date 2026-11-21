package rules

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// ids returns evidence IDs deduplicated and in numeric order (ev-2 < ev-10).
func ids(in ...string) []string {
	var out []string
	for _, id := range in {
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		return cmp.Or(cmp.Compare(idNum(a), idNum(b)), strings.Compare(a, b))
	})
	return out
}

func idNum(id string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(id, "ev-"))
	if err != nil {
		return -1
	}
	return n
}

// targetAddr is the address the source connects to when the target gives
// it: literally, or as a name the source's extra_hosts map to an address
// (host-gateway is the host, not an address).
func targetAddr(q evidence.Question, d evidence.Destinations) (netip.Addr, bool) {
	switch {
	case q.To.Class == evidence.TargetIP:
		return q.To.Addr.Unmap(), q.To.Addr.IsValid()
	case q.To.Class == evidence.TargetName && d.HostsEntry != "":
		a, err := netip.ParseAddr(d.HostsEntry)
		return a.Unmap(), err == nil
	default:
		return netip.Addr{}, false
	}
}

// sentence starts a sentence with s: it capitalizes a leading "the" (the
// host's, the WSL2 VM's) and leaves anything else as it is, a container's
// name above all, whose case is part of the name.
func sentence(s string) string {
	if rest, ok := strings.CutPrefix(s, "the "); ok {
		return "The " + rest
	}
	return s
}

// sourceConnects returns the IDs of the source's connects that ended in
// one of outcomes, in ID order.
func sourceConnects(v evidence.View, outcomes ...string) []string {
	var out []string
	for _, t := range v.SourceTCP() {
		if slices.Contains(outcomes, t.P.Outcome) {
			out = append(out, t.ID)
		}
	}
	return out
}

// resolvedFromSource reports that the target name resolved from the source.
func resolvedFromSource(v evidence.View) bool {
	q := v.Question()
	if q.To.Class != evidence.TargetName {
		return false
	}
	d, ok := v.SourceDNS(q.To.Host)
	return ok && len(d.P.Answers) > 0
}

// connectedByName reports a connect from the source that reached the target
// through the name the app uses (not through a metadata address).
func connectedByName(v evidence.View) bool {
	for _, t := range v.SourceTCP() {
		if t.P.ByName() && t.P.Outcome == evidence.OutcomeConnected {
			return true
		}
	}
	return false
}

// onlyInternal reports a container whose user-defined networks are all
// internal: true, and which isn't on the default bridge either: it has no
// way out of its networks (WR015, WR020).
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

// sharedNetworks lists the networks two containers are both attached to.
func sharedNetworks(a, b evidence.Container) []string {
	var out []string
	for _, n := range a.NetworkNames() {
		if _, ok := b.Attachment(n); ok {
			out = append(out, n)
		}
	}
	return out
}

// socketList renders sockets as "127.0.0.1:8080, [::1]:8080".
func socketList(socks []evidence.Socket) string {
	var parts []string
	for _, s := range socks {
		parts = append(parts, s.Local.String())
	}
	return strings.Join(parts, ", ")
}

// containerLabel names a container for prose: "api" or "api (shop-api-1)".
func containerLabel(c evidence.Container) string {
	if d := c.DisplayName(); d != c.Name {
		return d + " (container " + c.Name + ")"
	}
	return c.Name
}

// projectOf names a container's Compose project, or "".
func projectOf(c evidence.Container) string {
	if c.Compose == nil {
		return ""
	}
	return c.Compose.Project
}

// hostPort joins a host and port, bracketing IPv6 addresses.
func hostPort(host string, port uint16) string {
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() && !a.Is4In6() {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

// quoteList renders names as "a, b and c".
func quoteList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}

// plural picks a word form for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// serving is the other destinations that accept connections on their port
// from other network namespaces, with the records that show it. With
// replicas behind one name, a broken one fails only the connections that
// reach it.
type serving struct {
	names, ids []string
}

func servingReplicas(v evidence.View, matches []evidence.Match, m evidence.Match) serving {
	var out serving
	for _, o := range matches {
		if o.C.ID == m.C.ID || !o.C.Running() || o.C.HostNetwork() {
			continue
		}
		l, ok := v.ListenersIn(o.C.ID)
		switch {
		case ok && l.L.AcceptsRemote(o.Port):
			out.names, out.ids = append(out.names, o.C.Name), append(out.ids, o.ID, l.ID)
		case !ok && o.C.Health == "healthy":
			out.names, out.ids = append(out.names, o.C.Name), append(out.ids, o.ID)
		}
	}
	return out
}

// partOfReplicas lowers a finding about one of several replicas when others
// serve, and says so.
func partOfReplicas(f *Finding, s serving, broken string) {
	if len(s.names) == 0 {
		return
	}
	f.Confidence = f.Confidence.Lower()
	f.Supporting = ids(append(f.Supporting, s.ids...)...)
	f.Explanation += fmt.Sprintf(" %s answer%s to the same name and %s, so only the connections that reach %s fail.",
		quoteList(s.names), plural(len(s.names), "s", ""), plural(len(s.names), "serves", "serve"), broken)
}

// composeKey is how a Compose file names a network: without the project
// prefix Compose adds to the Docker network's name ("shop_default" is
// "default" in project shop).
func composeKey(c evidence.Container, network string) string {
	if p := projectOf(c); p != "" {
		if k, ok := strings.CutPrefix(network, p+"_"); ok && k != "" {
			return k
		}
	}
	return network
}

// replicaName names a destination for prose: its Compose service, or its
// container name when other destinations share that service name.
func replicaName(matches []evidence.Match, m evidence.Match) string {
	for _, o := range matches {
		if o.C.ID != m.C.ID && o.C.DisplayName() == m.C.DisplayName() {
			return m.C.Name
		}
	}
	return m.C.DisplayName()
}

// contradictedByPath lowers a listener finding when the source's connect
// through the target's name (or literal address) timed out or found no
// route instead of being refused: a listener explains a refusal, so
// something on the path (a firewall, say) drops the connection as well.
func contradictedByPath(v evidence.View, f *Finding) {
	var against []string
	unreachable := true
	for _, t := range v.SourceTCP() {
		if !t.P.ByName() {
			continue
		}
		switch t.P.Outcome {
		case evidence.OutcomeTimeout:
			unreachable = false
			against = append(against, t.ID)
		case evidence.OutcomeUnreachable:
			against = append(against, t.ID)
		}
	}
	if len(against) == 0 {
		return
	}
	how := "timed out"
	if unreachable {
		how = "found no route"
	}
	f.Confidence = f.Confidence.Lower()
	f.Contradicting = ids(append(f.Contradicting, against...)...)
	f.Explanation += fmt.Sprintf(" But %s's connect %s rather than being refused, so something on the path (a firewall, say) stops it too: fixing this alone may not be enough.", sourceName(v), how)
}
