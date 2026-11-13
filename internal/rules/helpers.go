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

// fromSource returns the TCP probes that ran in the source's netns.
func fromSource(v evidence.View) []evidence.TCPEv {
	q := v.Question()
	var out []evidence.TCPEv
	for _, t := range v.TCP() {
		switch q.From.Kind {
		case evidence.SourceHost:
			if t.Context.Kind == evidence.ContextHost {
				out = append(out, t)
			}
		case evidence.SourceContainer:
			if t.Context.Kind == evidence.ContextContainer && t.Context.Container == evidence.ShortID(q.From.ContainerID) {
				out = append(out, t)
			}
		}
	}
	return out
}

// dnsFromSource returns the source's lookup of name, if one ran.
func dnsFromSource(v evidence.View, name string) (evidence.DNSEv, bool) {
	q := v.Question()
	for _, d := range v.DNS() {
		if !strings.EqualFold(d.P.Name, name) {
			continue
		}
		if q.From.Kind == evidence.SourceHost && d.Context.Kind == evidence.ContextHost {
			return d, true
		}
		if q.From.Kind == evidence.SourceContainer && d.Context.Container == evidence.ShortID(q.From.ContainerID) {
			return d, true
		}
	}
	return evidence.DNSEv{}, false
}

// resolvedFromSource reports that the target name resolved from the source.
func resolvedFromSource(v evidence.View) bool {
	q := v.Question()
	if q.To.Class != evidence.TargetName {
		return false
	}
	d, ok := dnsFromSource(v, q.To.Host)
	return ok && len(d.P.Answers) > 0
}

// connectedByName reports a connect from the source that reached the target
// through the name the app uses (not through a metadata address).
func connectedByName(v evidence.View) bool {
	for _, t := range fromSource(v) {
		if t.P.ByName() && t.P.Outcome == evidence.OutcomeConnected {
			return true
		}
	}
	return false
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
	for _, t := range fromSource(v) {
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
