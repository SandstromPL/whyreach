package engine

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// maxFacts bounds the facts list: the structured output stays small (ADR 0001).
const maxFacts = 10

// compose turns the ranked findings and the evidence into the answer.
func (r *run) compose(v evidence.View, ranked rules.Ranked, sideEffects []string) *Diagnosis {
	d := &Diagnosis{
		SchemaVersion: SchemaVersion,
		Question:      r.q,
		Findings:      []rules.Finding{},
		Suppressed:    ranked.Suppressed,
		Evidence:      v.Items(),
		SideEffects:   sideEffects,
		ChangesMade:   false,
	}
	if d.SideEffects == nil {
		d.SideEffects = []string{}
	}
	if ranked.Primary != nil {
		d.Findings = append(d.Findings, *ranked.Primary)
		d.Findings = append(d.Findings, ranked.AlsoFound...)
	}
	connected, connAddr := connectedFromSource(v)
	switch {
	case connected:
		d.Verdict = VerdictNoProblem
	case ranked.Primary != nil && ranked.Primary.Confidence == rules.High:
		d.Verdict = VerdictCause
	case ranked.Primary != nil && ranked.Primary.Confidence == rules.Medium:
		d.Verdict = VerdictLikelyCause
	default:
		d.Verdict = VerdictInconclusive
	}
	d.Facts = facts(v, !r.metadataIncomplete)
	d.Gaps = append(slices.Clone(r.gaps), r.gapsFrom(v)...)
	if d.Gaps == nil {
		d.Gaps = []Gap{}
	}
	d.Summary = summary(d, v, connAddr)
	d.NextChecks = nextChecks(d)
	return d
}

// connectedFromSource reports whether the source connected to the target
// through the name (or literal address) the app uses.
func connectedFromSource(v evidence.View) (bool, string) {
	q := v.Question()
	for _, t := range v.TCP() {
		if !inSource(q, t.Context) || !t.P.ByName() {
			continue
		}
		if t.P.Outcome == evidence.OutcomeConnected {
			return true, t.P.Addr.String()
		}
	}
	return false, ""
}

func inSource(q evidence.Question, c evidence.ContextRef) bool {
	if q.From.Kind == evidence.SourceHost {
		return c.Kind == evidence.ContextHost
	}
	return c.Kind == evidence.ContextContainer && c.Container == evidence.ShortID(q.From.ContainerID)
}

func sourceName(v evidence.View) string {
	if src, ok := v.Source(); ok {
		return src.C.DisplayName()
	}
	if v.Question().From.Kind == evidence.SourceHost {
		return "the host"
	}
	return strings.TrimPrefix(strings.TrimPrefix(v.Question().From.Ref, "container:"), "service:")
}

func summary(d *Diagnosis, v evidence.View, connAddr string) string {
	src, to := sourceName(v), v.Question().To.String()
	switch d.Verdict {
	case VerdictNoProblem:
		s := fmt.Sprintf("%s connected to %s (%s): no problem reproduced.", src, to, connAddr)
		if connAddr == to {
			s = fmt.Sprintf("%s connected to %s: no problem reproduced.", src, to)
		}
		if len(d.Findings) > 0 {
			s += " Also found: " + d.Findings[0].Title + "."
		}
		return s
	case VerdictCause:
		return fmt.Sprintf("%s can't reach %s: %s.", src, to, d.Findings[0].Title)
	case VerdictLikelyCause:
		return fmt.Sprintf("%s can't reach %s, probably because %s.", src, to, d.Findings[0].Title)
	}
	switch {
	case len(d.Findings) > 0:
		return fmt.Sprintf("No settled cause for %s → %s; the best lead is weak: %s.", src, to, d.Findings[0].Title)
	case len(d.Gaps) > 0:
		return fmt.Sprintf("No cause found for %s → %s, but %d %s could not be checked (see gaps).", src, to, len(d.Gaps), plural(len(d.Gaps), "thing", "things"))
	}
	for _, t := range v.TCP() {
		if inSource(v.Question(), t.Context) && t.P.ByName() {
			return fmt.Sprintf("No cause found for %s → %s: the connect %s, and no rule explains it yet.", src, to, outcomeText(t.P))
		}
	}
	return fmt.Sprintf("No cause found for %s → %s.", src, to)
}

func outcomeText(p evidence.TCPProbe) string {
	switch p.Outcome {
	case evidence.OutcomeRefused:
		return "was refused"
	case evidence.OutcomeTimeout:
		return "timed out"
	case evidence.OutcomeUnreachable:
		return "found no route (" + p.Errno + ")"
	case evidence.OutcomeReset:
		return "was reset"
	case evidence.OutcomeClosed:
		return "was accepted and closed at once, without a byte: the network path and a listener work, and something rejected the connection"
	default:
		return "failed (" + p.Outcome + ")"
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Facts are a few short lines, each naming the context of every address it
// mentions.
// facts summarises the evidence. complete says whether every container
// that could match the target was inspected.
func facts(v evidence.View, complete bool) []Fact {
	var out []Fact
	add := func(text string, ids ...string) {
		if len(out) < maxFacts {
			out = append(out, Fact{Text: text, Evidence: sortIDs(ids)})
		}
	}
	q := v.Question()
	dests := v.Destinations()
	src, haveSrc := v.Source()
	owner, haveOwner := v.NetnsOwner()
	if haveSrc && haveOwner && owner.C.ID != src.C.ID {
		add(fmt.Sprintf("%s uses the network namespace of %s", src.C.DisplayName(), owner.C.DisplayName()), src.ID, owner.ID)
	}
	if haveOwner {
		if !owner.C.Running() {
			add(fmt.Sprintf("%s is %s", owner.C.DisplayName(), owner.C.State), owner.ID)
		}
		if dests.HostsEntry != "" && dests.Host == nil {
			add(fmt.Sprintf("%s's extra_hosts map %q to %s, ahead of any DNS", owner.C.DisplayName(), q.To.Host, dests.HostsEntry), owner.ID)
		}
		switch {
		case dests.Host != nil:
			// The target is the host: say which of its addresses, and what
			// publishes the port there.
			hostFact(dests.Host, q, owner.C, add)
		case len(dests.OnSourceNets) > 0:
			m := dests.OnSourceNets[0]
			add(fmt.Sprintf("%s and %s share network %s", owner.C.DisplayName(), m.C.DisplayName(), strings.Join(m.Shared, ", ")), owner.ID, m.ID)
		case len(dests.Elsewhere) > 0:
			m := dests.Elsewhere[0]
			add(fmt.Sprintf("%s is on %s; %s is on %s", owner.C.DisplayName(), orNone(owner.C.NetworkNames()), m.C.DisplayName(), describeNetworks(m.C)), owner.ID, m.ID)
		case q.To.Class == evidence.TargetName && dests.HostsEntry == "" && complete:
			add(fmt.Sprintf("no container answers to %q in Docker's metadata", q.To.Host), owner.ID)
		}
	}
	if !haveOwner && dests.Host != nil {
		hostFact(dests.Host, q, evidence.Container{}, add)
	}
	for _, m := range dests.Published {
		add(fmt.Sprintf("%s publishes %s → its port %d", m.C.DisplayName(), m.Published.HostAddr(), m.Port), m.ID)
	}
	for _, m := range dests.All() {
		if !m.C.Running() {
			add(fmt.Sprintf("%s %s", m.C.DisplayName(), stateText(m.C)), m.ID)
		} else if m.C.Health != "" && m.C.Health != "healthy" {
			add(fmt.Sprintf("%s is %s", m.C.DisplayName(), m.C.Health), m.ID)
		}
	}
	for _, d := range v.DNS() {
		if !inSource(q, d.Context) {
			continue
		}
		ctx := d.Context.String()
		if len(d.P.Answers) > 0 {
			via := "via " + d.P.Server
			if d.P.Via == evidence.ViaHosts {
				via = "via /etc/hosts"
			}
			add(fmt.Sprintf("%q → %s %s, in %s", d.P.Name, addrList(d.P.Answers), via, ctx), d.ID)
		} else {
			add(fmt.Sprintf("%q did not resolve in %s (%s from %s)", d.P.Name, ctx, d.P.Rcode, d.P.Server), d.ID)
		}
	}
	for _, t := range v.TCP() {
		if !inSource(q, t.Context) {
			continue
		}
		via := ""
		if t.P.Via == evidence.ViaMetadata {
			via = ", address from Docker metadata"
		}
		text := fmt.Sprintf("connect %s from %s: %s (%.1f ms%s)", t.P.Addr, t.Context.String(), t.P.Outcome, evidence.Millis(t.P.RTT), via)
		if t.P.Errno != "" {
			text = fmt.Sprintf("connect %s from %s: %s, %s (%.1f ms%s)", t.P.Addr, t.Context.String(), t.P.Outcome, t.P.Errno, evidence.Millis(t.P.RTT), via)
		}
		add(text, t.ID)
	}
	for _, e := range v.Of(evidence.KindListeners) {
		l, ok := e.Data.(evidence.Listeners)
		if !ok || !e.OK() {
			continue
		}
		port := q.To.Port
		for _, m := range dests.Published {
			if e.Context.Container == evidence.ShortID(m.C.ID) {
				port = m.Port // the container port the published one forwards to
			}
		}
		socks := l.OnPort(port)
		where := e.Context.String()
		if e.Context.Kind == evidence.ContextHost {
			where = "the host"
		}
		if len(socks) == 0 {
			if relevantListenerContext(v, e.Context) {
				add(fmt.Sprintf("nothing listens on port %d in %s", port, where), e.ID)
			}
			continue
		}
		var parts []string
		for _, s := range socks {
			parts = append(parts, s.Local.String()+"/tcp")
		}
		add(fmt.Sprintf("listening on port %d in %s: %s", port, where, strings.Join(parts, ", ")), e.ID)
	}
	if out == nil {
		out = []Fact{}
	}
	return out
}

// hostFact says how the target reaches the host.
func hostFact(h *evidence.HostTarget, q evidence.Question, owner evidence.Container, add func(string, ...string)) {
	where := ""
	if h.Addr.IsValid() {
		where = h.Addr.String()
		if h.Iface != "" {
			where += " on " + h.Iface
		}
	}
	switch h.Via {
	case evidence.HostViaGateway:
		if where != "" {
			add(fmt.Sprintf("%q is the host for %s: extra_hosts map it to host-gateway, the host's %s", q.To.Host, owner.DisplayName(), where), h.Evidence...)
		}
	case evidence.HostViaAddress:
		add(fmt.Sprintf("%s is the host's own address", where), h.Evidence...)
	case evidence.HostViaName:
		add(fmt.Sprintf("%s has no extra_hosts entry for %s", owner.DisplayName(), q.To.Host))
	}
}

// relevantListenerContext limits "nothing listens" facts to the source (for
// a loopback target), the destinations, and the host when it is the target.
func relevantListenerContext(v evidence.View, c evidence.ContextRef) bool {
	if c.Kind == evidence.ContextHost {
		_, ok := v.HostTarget()
		return ok
	}
	if owner, ok := v.NetnsOwner(); ok && evidence.ShortID(owner.C.ID) == c.Container {
		return true
	}
	for _, m := range v.Destinations().All() {
		if evidence.ShortID(m.C.ID) == c.Container {
			return true
		}
	}
	return false
}

// stateText completes "api …" for a container that isn't running.
func stateText(c evidence.Container) string {
	switch c.State {
	case evidence.StateExited:
		return fmt.Sprintf("has exited (code %d)", c.ExitCode)
	case evidence.StateRestarting:
		return fmt.Sprintf("is restarting (%d restarts)", c.RestartCount)
	default:
		return "is " + c.State
	}
}

// sortIDs orders evidence IDs numerically: ev-2 before ev-10.
func sortIDs(ids []string) []string {
	out := slices.Clone(ids)
	slices.SortFunc(out, func(a, b string) int {
		na, _ := strconv.Atoi(strings.TrimPrefix(a, "ev-"))
		nb, _ := strconv.Atoi(strings.TrimPrefix(b, "ev-"))
		return cmp.Or(cmp.Compare(na, nb), strings.Compare(a, b))
	})
	return slices.Compact(out)
}

// describeNetworks names a container's networks, or its network mode when
// it has none of its own.
func describeNetworks(c evidence.Container) string {
	switch {
	case c.HostNetwork():
		return "the host's network (network_mode: host)"
	case c.NetnsOwner() != "":
		return "another container's network namespace (network_mode: container)"
	default:
		return orNone(c.NetworkNames())
	}
}

func orNone(nets []string) string {
	if len(nets) == 0 {
		return "no network"
	}
	return strings.Join(nets, ", ")
}

func addrList(as []netip.Addr) string {
	parts := make([]string, 0, len(as))
	for _, a := range as {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

// gapsFrom turns every record without an observation into a gap, merging
// records that failed for the same reason in the same context. Skipped
// checks whose reason a finding explains (a stopped destination, a name that
// did not resolve) are not gaps.
func (r *run) gapsFrom(v evidence.View) []Gap {
	type key struct{ ctx, status, msg string }
	var order []key
	byKey := map[key]*Gap{}
	kinds := map[key][]string{}
	for _, e := range v.Items() {
		why, ok := gapWhy(e)
		if !ok {
			continue
		}
		ctx := e.Context.String()
		if e.Context.Kind == evidence.ContextHost {
			ctx = "the host"
		}
		k := key{ctx, string(e.Status), e.Err.Message}
		g, seen := byKey[k]
		if !seen {
			g = &Gap{Why: why, Detail: e.Err.Message, HowToEnable: r.howToEnable(e)}
			byKey[k] = g
			order = append(order, k)
		}
		g.Evidence = append(g.Evidence, e.ID)
		if label := kindLabel(e.Kind); !slices.Contains(kinds[k], label) {
			kinds[k] = append(kinds[k], label)
		}
	}
	var out []Gap
	for _, k := range order {
		g := byKey[k]
		prep := "from" // probes run from a context
		switch {
		case slices.Equal(kinds[k], []string{kindLabel(evidence.KindListeners)}):
			prep = "in"
		case slices.Equal(kinds[k], []string{kindLabel(evidence.KindContainer)}), slices.Equal(kinds[k], []string{kindLabel(evidence.KindHostAddrs)}):
			prep = "of"
		}
		g.What = fmt.Sprintf("%s %s %s", joinAnd(kinds[k]), prep, k.ctx)
		out = append(out, *g)
	}
	return out
}

func gapWhy(e evidence.Evidence) (string, bool) {
	if e.OK() || e.Err == nil {
		return "", false
	}
	switch e.Status {
	case evidence.StatusPermissionDenied:
		return "permission", true
	case evidence.StatusUnsupported:
		return "unsupported", true
	case evidence.StatusTimeout:
		return "timeout", true
	case evidence.StatusFailed:
		return "failed", true
	case evidence.StatusError:
		return "error", true
	case evidence.StatusSkipped:
		return "policy", e.Err.Code == evidence.CodePolicyDenied
	default:
		return "", false
	}
}

func (r *run) howToEnable(e evidence.Evidence) string {
	cfg := r.e.d.ConfigPath
	if cfg == "" {
		cfg = "the config file"
	}
	switch {
	case e.Err.Message == executor.HostHidden:
		return executor.HostHiddenAdvice + "."
	case e.Err.Message == executor.PIDsHidden:
		return executor.PIDsHiddenAdvice + "."
	case executor.CannotEnter(e.Err):
		return fmt.Sprintf("whyreach runs as root, so it enters containers' network namespaces itself, and couldn't here. Allow probe containers for whyreach to use one instead (the user's decision: approve them when an MCP client asks, or set probe_containers = true under [permissions] in %s), or run whyreach as a regular user.", cfg)
	case e.Status == evidence.StatusPermissionDenied && e.Err.Message == executor.ProbeContainersOff:
		return fmt.Sprintf("Enable probe containers (the user's decision, not an agent's): approve them when an MCP client asks, or set probe_containers = true under [permissions] in %s. whyreach then imports its own binary as the image whyreach-probe and runs each check in a short-lived, hardened container labeled io.whyreach.probe=1, which it removes afterwards.", cfg)
	case e.Status == evidence.StatusSkipped && e.Err.Code == evidence.CodePolicyDenied && e.Err.Message == probe.NameNotApproved:
		return fmt.Sprintf("A lookup sends its name to the DNS servers of the name's domain, so for an MCP client whyreach looks up a name with a dot that Docker doesn't know only with the user's approval (the user's decision, not an agent's): approve the name if whyreach asks (it asks only through clients that support elicitation, about 3 names at most in a session, and not again about a name the user declined), or list its domain under names in [probe] in %s (example.com covers its subdomains).", cfg)
	case e.Status == evidence.StatusSkipped && e.Err.Code == evidence.CodePolicyDenied && strings.Contains(e.Err.Message, "block list"):
		return "whyreach never sends a query to a link-local or cloud-metadata address (INITIAL.md §10 Q11), and the app's lookup would go to one (its first nameserver, or the next one after the first failed), so whyreach can't make that lookup. " +
			"Some clouds use 169.254.169.254 as their resolver, and Docker copies the host's resolver into containers on the default bridge and on the host's network. " +
			"From a container on a user-defined network, lookups go to Docker's DNS (127.0.0.11) instead."
	case e.Status == evidence.StatusSkipped && e.Err.Code == evidence.CodePolicyDenied && strings.Contains(e.Err.Message, "allowlist"):
		return fmt.Sprintf("Add the address or its range to allow under [probe] in %s (classes: loopback, rfc1918, docker; or CIDRs).", cfg)
	case e.Status == evidence.StatusSkipped && e.Err.Code == evidence.CodePolicyDenied && strings.Contains(e.Err.Message, "rate limit"):
		return fmt.Sprintf("Wait a minute and run it again, or raise rate_per_minute under [probe] in %s.", cfg)
	case e.Status == evidence.StatusPermissionDenied && e.Kind == evidence.KindListeners:
		return "Run whyreach as root, or as a user in the docker group on Linux Docker Engine, which can read /proc/<pid>/net/tcp."
	case e.Status == evidence.StatusUnsupported && e.Kind == evidence.KindListeners:
		return "On Docker Desktop and non-Linux hosts, listeners will be read inside a probe container (planned for v0.3)."
	case e.Status == evidence.StatusTimeout:
		return fmt.Sprintf("The diagnosis deadline passed first. Run it again, or raise diagnosis under [timeouts] in %s.", cfg)
	default:
		return ""
	}
}

func kindLabel(k evidence.Kind) string {
	switch k {
	case evidence.KindDNS:
		return "name lookup"
	case evidence.KindTCP:
		return "TCP connect"
	case evidence.KindListeners:
		return "listening sockets"
	case evidence.KindContainer:
		return "container metadata"
	case evidence.KindHostAddrs:
		return "the interfaces"
	default:
		return string(k)
	}
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}

// nextChecks proposes machine-actionable follow-ups that name whyreach's
// MCP tools (INITIAL.md §4.10).
func nextChecks(d *Diagnosis) []NextCheck {
	q := d.Question
	args := map[string]string{"from": q.From.Ref, "to": q.To.String()}
	var out []NextCheck
	switch d.Verdict {
	case VerdictNoProblem:
		out = append(out, NextCheck{
			Why:  "The TCP connection works from the source's network namespace. If the app still fails, check that it really uses this host and port (its config, proxy variables), then TLS and app-level errors.",
			Tool: "run_probe",
			Args: map[string]string{"kind": "dns", "from": q.From.Ref, "target": q.To.Host},
		})
	case VerdictCause, VerdictLikelyCause:
		out = append(out, NextCheck{Why: "Confirm the fix: run the same diagnosis after applying it.", Tool: "diagnose_connection", Args: args})
	default:
		out = append(out, NextCheck{Why: "Run the diagnosis again once the gaps are closed.", Tool: "diagnose_connection", Args: args})
	}
	return out
}
