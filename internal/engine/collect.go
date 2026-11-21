package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// collect gathers metadata for the containers the question involves and
// reads their listening sockets from the host. When the target is the host
// itself (localhost from the host, a host address, host.docker.internal),
// it reads the host's listeners and the containers that publish the port
// there instead (collectHost).
func (r *run) collect(ctx context.Context) error {
	// The host's interfaces say which addresses are the host's.
	if r.e.d.Interfaces != nil {
		r.store.Add(r.hostAddrs())
	}
	dk := r.docker
	if dk == nil || (r.q.From.Kind == evidence.SourceContainer && r.q.From.ContainerID == "") {
		r.hostSide(ctx)
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	list, err := dk.ListContainers(lctx, true)
	cancel()
	if err != nil {
		g := Gap{What: "the list of containers", Why: "failed", Detail: err.Error()}
		r.gaps = append(r.gaps, g)
		// A record too, as for skipped containers: rules must not claim that
		// no container has a name or an address when none could be listed.
		r.metadataIncomplete = true
		r.store.Add(unlisted(g))
		return nil
	}
	r.list = list
	r.hostSide(ctx)
	if r.hostDone {
		return nil // the target is the host
	}

	known := r.store.Snapshot()
	have := containerIDs(known)
	var srcNets []string
	ownerID := ""
	view := evidence.NewView(r.q, known)
	owner, haveOwner := view.NetnsOwner()
	if haveOwner && !owner.C.HostNetwork() {
		srcNets = owner.C.NetworkNames()
		ownerID = owner.C.ID
	}

	// What the target means in the container list: a name, or an address
	// (given literally, or from the source's own extra_hosts).
	to := r.q.To
	byName, byAddr := to.Class == evidence.TargetName, to.Addr
	// A name the source's extra_hosts map to loopback means the source
	// itself, as localhost does (WR007).
	loopback := to.Class == evidence.TargetLoopback
	if byName && haveOwner {
		if entry, ok := owner.C.HostsEntry(to.Host); ok {
			byName, byAddr = false, netip.Addr{}
			if a, err := netip.ParseAddr(entry); err == nil {
				byAddr = a.Unmap()
				loopback = byAddr.IsLoopback()
			}
		}
	}

	// Containers that match by name or address are always inspected (up to
	// maxMatches). The other containers on the source's networks are
	// inspected too, because only an inspect shows their aliases.
	var matches, peers []docker.Summary
	var droppedMatches, droppedPeers int
	for _, s := range list {
		if have[s.ID] {
			continue
		}
		switch {
		case (byName && nameMatches(s, to.Host)) || (byAddr.IsValid() && (s.HasAddr(byAddr) || s.HasFixedAddr(byAddr))):
			if len(matches) == maxMatches {
				droppedMatches++
				continue
			}
			matches = append(matches, s)
		case shares(s.Networks(), srcNets):
			if len(peers) == maxPeers {
				droppedPeers++
				continue
			}
			peers = append(peers, s)
		}
	}
	// Skipped containers are a gap, and a record too: rules must not claim
	// that no container has a name when some were never inspected.
	if droppedMatches > 0 {
		r.metadataIncomplete = true
		g := Gap{
			What:   fmt.Sprintf("%d more containers named %q", droppedMatches, to.Host),
			Why:    "skipped",
			Detail: fmt.Sprintf("whyreach inspects at most %d containers that match the target", maxMatches),
		}
		r.gaps = append(r.gaps, g)
		r.store.Add(skippedContainers(g))
	}
	if droppedPeers > 0 {
		r.metadataIncomplete = true
		g := Gap{
			What:   fmt.Sprintf("aliases of %d more containers on %s's networks", droppedPeers, r.q.From.Ref),
			Why:    "skipped",
			Detail: fmt.Sprintf("whyreach inspects at most %d containers on the source's networks; one of the others may answer to %q through an alias", maxPeers, to.Host),
		}
		r.gaps = append(r.gaps, g)
		r.store.Add(skippedContainers(g))
	}
	inspected, failed := r.inspectAll(ctx, append(matches, peers...))
	if len(failed) > 0 {
		r.metadataIncomplete = true
		r.store.Add(failed...)
	}

	// Decide what to record: for a loopback target every peer (WR007 looks
	// for the service among them); for a name that matches nothing, every
	// peer too (WR005 suggests the closest name); for an address on the
	// source's networks that no container holds, every peer as well (WR024
	// names the containers there now); otherwise the destinations and the
	// containers whose network namespace they use.
	view = evidence.NewView(r.q, append(slices.Clone(known), inspected...))
	dests := view.Destinations().All()
	unheld := false
	if byAddr.IsValid() && !loopback && len(dests) == 0 && haveOwner {
		_, unheld = owner.C.SubnetHolding(byAddr)
	}
	allPeers := loopback || (to.Class == evidence.TargetName && len(dests) == 0 && byName) || unheld
	record := map[string]bool{}
	for _, m := range dests {
		record[m.C.ID] = true
		if ref := m.C.NetnsOwner(); ref != "" {
			if o, ok := view.Container(ref); ok {
				record[o.C.ID] = true
			} else if !have[ref] {
				if _, err := r.inspect(ctx, ref); err != nil {
					r.store.Add(r.inspectFailure(ref, ref, err))
				}
			}
		}
	}
	var listenFor, peerListen []evidence.Container
	for _, ev := range inspected {
		c := ev.Data.(evidence.Container)
		if allPeers || record[c.ID] {
			r.store.Add(ev)
		}
		if loopback && c.NetnsOwner() != ownerID {
			peerListen = append(peerListen, c)
		}
	}
	// The destinations' listeners, even when the destination is the source's
	// own netns: a name resolves to the network address, which a
	// loopback-bound socket refuses there too (WR002). Then, for a loopback
	// target, the peers' (WR007 looks for the service among them).
	for i, m := range dests {
		if i == maxDestinations {
			break
		}
		listenFor = append(listenFor, m.C)
	}
	listenFor = append(listenFor, peerListen...)
	if loopback && haveOwner && !owner.C.HostNetwork() {
		// The source's own listeners first: where each read is a probe
		// container, the bound keeps the ones that matter.
		listenFor = append([]evidence.Container{owner.C}, listenFor...)
		// WR007 chooses host.docker.internal when the host serves the port.
		r.store.Add(r.hostListenersFor(nil))
	}
	r.readListeners(ctx, listenFor)
	return nil
}

// hostListenersFor reads the listening sockets of the host a container
// source reaches; ht is how the target refers to it (nil for WR007's
// question whether the host serves the port at all). On Docker Desktop's
// WSL integration that host isn't the WSL2 distro whyreach runs in, unless
// the container aims at one of the WSL2 VM's own addresses: the record then
// says so (executor.HostNotHere) instead of passing the VM's sockets off as
// the host's, and rules that need them leave a gap (INITIAL.md §3.7).
func (r *run) hostListenersFor(ht *evidence.HostTarget) evidence.Evidence {
	if r.q.From.Kind == evidence.SourceContainer && r.platform.WindowsHost() && (ht == nil || ht.Via != evidence.HostViaAddress) {
		return evidence.Evidence{
			Kind: evidence.KindListeners, Context: evidence.Host(), Subject: "listeners", Status: evidence.StatusUnsupported,
			ObservedAt: time.Now(), Source: "the listening sockets of the host Docker Desktop's containers reach",
			Err: &evidence.Error{Code: evidence.CodeUnsupported, Message: executor.HostNotHere},
		}
	}
	return r.hostListeners()
}

// maxScan bounds the running containers whose listeners are read to find
// the one that should answer a host port (WR019).
const maxScan = 32

// collectHost gathers what a connection to the host itself depends on: the
// host's listeners on the port, and the containers that publish it, expose
// it, or publish their own port of that number elsewhere. When the source
// is the host and nothing there accepts the port, it also reads the
// listeners of the running containers to find the one that serves it but
// doesn't publish it (WR019).
func (r *run) collectHost(ctx context.Context, list []docker.Summary, have map[string]bool) {
	r.hostDone = true
	port := r.q.To.Port
	hostL := r.hostListeners()
	if r.q.From.Kind == evidence.SourceContainer {
		ht, _ := evidence.NewView(r.q, r.store.Snapshot()).HostTarget()
		hostL = r.hostListenersFor(&ht)
	}
	r.store.Add(hostL)
	hostAccepts := false
	if l, ok := hostL.Data.(evidence.Listeners); ok && hostL.OK() {
		hostAccepts = len(l.OnPort(port)) > 0
	}
	known := evidence.NewView(r.q, r.store.Snapshot())
	var cands, others []docker.Summary
	var listenFor []evidence.Container
	for _, s := range list {
		switch {
		case have[s.ID]:
			// Recorded already (a peer of the source, say): a publisher
			// still needs its listeners.
			if c, ok := known.Container(s.ID); ok && s.MentionsPort(port) {
				if _, read := known.ListenersIn(c.C.ID); !read {
					listenFor = append(listenFor, c.C)
				}
			}
		case s.MentionsPort(port):
			cands = append(cands, s)
		case s.State == evidence.StateRunning:
			others = append(others, s)
		}
	}
	// The containers that publish the port come first, so the bound leaves
	// out only ones that merely expose it, unless more than maxMatches
	// publish it. Those left out are a gap and a record, as in collect.
	slices.SortStableFunc(cands, func(a, b docker.Summary) int { return cmp.Compare(publishRank(a, port), publishRank(b, port)) })
	if len(cands) > maxMatches {
		dropped := cands[maxMatches:]
		cands = cands[:maxMatches]
		r.metadataIncomplete = true
		g := Gap{
			What:   fmt.Sprintf("%d more %s with port %d published or exposed", len(dropped), plural(len(dropped), "container", "containers"), port),
			Why:    "skipped",
			Detail: fmt.Sprintf("whyreach inspects at most %d containers that publish or expose the target port, those that publish it first", maxMatches),
		}
		r.gaps = append(r.gaps, g)
		r.store.Add(skippedContainers(g))
		// A running one may serve the port without publishing it (WR019):
		// the search below reads it, ahead of those that don't mention it.
		var running []docker.Summary
		for _, s := range dropped {
			if s.State == evidence.StateRunning {
				running = append(running, s)
			}
		}
		others = append(running, others...)
	}
	inspected, failed := r.inspectAll(ctx, cands)
	r.store.Add(failed...)
	r.store.Add(inspected...)
	for _, ev := range inspected {
		listenFor = append(listenFor, ev.Data.(evidence.Container))
	}
	r.readListeners(ctx, listenFor)

	view := evidence.NewView(r.q, r.store.Snapshot())
	if !view.HostSource() || hostAccepts || len(view.Destinations().Published) > 0 {
		return
	}
	// The containers past the bound go unread too: each is a skipped record
	// among the unread below, so "nothing listens" isn't settled (WR001).
	var unscanned []evidence.Evidence
	if len(others) > maxScan {
		g := Gap{
			What:   fmt.Sprintf("the listeners of %d more running containers", len(others)-maxScan),
			Why:    "skipped",
			Detail: fmt.Sprintf("whyreach reads at most %d containers' listeners to find the one that serves port %d", maxScan, port),
		}
		r.gaps = append(r.gaps, g)
		for _, s := range others[maxScan:] {
			unscanned = append(unscanned, scanSkipped(s, g))
		}
		others = others[:maxScan]
	}
	scanned, failed := r.inspectAll(ctx, others)
	if len(failed) > 0 {
		r.metadataIncomplete = true
		r.store.Add(failed...)
	}
	// Containers whose sockets couldn't be read (Docker Desktop without
	// probe containers, whyreach's image without --pid host, the bound)
	// may serve the port unpublished: one record says so, so the rules
	// don't take their silence for "nothing listens".
	var unread []evidence.Evidence
	var cut []string
	for _, ev := range scanned {
		c := ev.Data.(evidence.Container)
		if c.HostNetwork() || c.NetnsOwner() != "" {
			continue // its sockets are the host's, or another container's
		}
		if !r.engineHere && !r.takeProbeListener() {
			unread = append(unread, r.listenersCut(c))
			cut = append(cut, c.DisplayName())
			continue
		}
		l := r.containerListeners(ctx, c)
		if !l.OK() {
			if l.Status != evidence.StatusSkipped || l.Err == nil || l.Err.Code != evidence.CodeNotFound {
				unread = append(unread, l)
			}
			continue
		}
		socks, ok := l.Data.(evidence.Listeners)
		if !ok || len(socks.OnPort(port)) == 0 {
			continue
		}
		r.store.Add(ev, l)
	}
	unread = append(unread, unscanned...)
	if len(unread) > 0 {
		r.store.Add(scanUnread(unread, port))
	}
	if len(cut) > 0 {
		r.gaps = append(r.gaps, r.probeListenersGap(cut)) // a skipped record makes no gap of its own
	}
}

// scanSkipped is the record of a running container whose listeners the
// search for an unpublished server (WR019) left unread at its bound, for
// scanUnread; g is the bound's gap, which says why, so the record is
// skipped rather than another gap.
func scanSkipped(s docker.Summary, g Gap) evidence.Evidence {
	name := s.Labels[docker.LabelComposeService] // as InContainer names an inspected one
	if name == "" {
		name = s.Name()
	}
	return evidence.Evidence{
		Kind: evidence.KindListeners, Subject: "listeners", Status: evidence.StatusSkipped,
		Context:    evidence.ContextRef{Kind: evidence.ContextContainer, Container: evidence.ShortID(s.ID), Name: name},
		ObservedAt: time.Now(), Source: "docker GET /containers/json (the running containers)",
		Err: &evidence.Error{Code: evidence.CodeLimit, Message: g.Detail},
	}
}

// publishRank orders the containers that mention a TCP port: those that
// publish it on the host first (what a connection to the host reaches),
// then those that publish their own port of that number elsewhere (WR006),
// then those that only expose it.
func publishRank(s docker.Summary, port uint16) int {
	rank := 2
	for _, p := range s.Ports {
		switch {
		case p.Type != "" && p.Type != "tcp":
		case p.PublicPort == port:
			return 0
		case p.PrivatePort == port && p.PublicPort != 0:
			rank = 1
		}
	}
	return rank
}

// scanUnread sums up the running containers whose listening sockets the
// search for an unpublished server (WR019) couldn't read, as one record:
// the first one's status and reason, in a context that names how many.
func scanUnread(unread []evidence.Evidence, port uint16) evidence.Evidence {
	first := unread[0]
	for _, e := range unread {
		if e.Err == nil || e.Err.Code != evidence.CodeLimit {
			first = e // a reason the gap can name, rather than the bound
			break
		}
	}
	names := make([]string, 0, len(unread))
	for _, e := range unread {
		names = append(names, e.Context.String())
	}
	return evidence.Evidence{
		Kind: evidence.KindListeners, Subject: "listeners", Status: first.Status, Err: first.Err,
		Context:    evidence.ContextRef{Kind: evidence.ContextContainer, Name: fmt.Sprintf("%d running %s", len(unread), plural(len(unread), "container", "containers"))},
		ObservedAt: time.Now(), Source: first.Source,
		Limitations: []string{fmt.Sprintf("read to find a container that serves port %d without publishing it (%s); one of these may", port, strings.Join(names, ", "))},
	}
}

// hostAddrs reads the host's interfaces.
func (r *run) hostAddrs() evidence.Evidence {
	ev := evidence.Evidence{Kind: evidence.KindHostAddrs, Context: r.host(), Subject: "interfaces", Source: "the kernel's interface list (netlink), in whyreach's own network namespace"}
	start := time.Now()
	addrs, err := r.e.d.Interfaces()
	ev.Duration, ev.ObservedAt = time.Since(start), time.Now()
	if err != nil {
		ev.Status, ev.Err = probe.Classify(err)
		return ev
	}
	ev.Status, ev.Data = evidence.StatusOK, addrs
	return ev
}

func shares(a, b []string) bool {
	for _, n := range a {
		if slices.Contains(b, n) {
			return true
		}
	}
	return false
}

// nameMatches is a cheap pre-filter on the container list: the container
// name or Compose service equals the target name. Aliases need an inspect,
// which is done for the containers on the source's networks.
func nameMatches(s docker.Summary, name string) bool {
	h := strings.TrimSuffix(strings.ToLower(name), ".")
	return strings.EqualFold(s.Name(), h) || strings.EqualFold(s.Labels[docker.LabelComposeService], h)
}

// inspectAll inspects containers in parallel. It returns the records in the
// order given, and a failure record for each container whose metadata could
// not be read. A container that vanished in between (404) is neither.
func (r *run) inspectAll(ctx context.Context, list []docker.Summary) (ok, failed []evidence.Evidence) {
	out := make([]evidence.Evidence, len(list))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(collectParallel)
	for i, s := range list {
		g.Go(func() error {
			_, ev, err := r.inspectEv(gctx, s.ID)
			switch {
			case err == nil:
				out[i] = ev
			case errors.Is(err, docker.ErrNotFound):
				r.e.d.Logger.Debug("container vanished", "container", s.Name())
			default:
				out[i] = r.inspectFailure(s.ID, s.Name(), err)
			}
			return nil
		})
	}
	_ = g.Wait() // the goroutines never return errors
	for _, ev := range out {
		switch {
		case ev.Kind == "":
		case ev.OK():
			ok = append(ok, ev)
		default:
			failed = append(failed, ev)
		}
	}
	return ok, failed
}

// hostAfterLookup collects the host's side of a target that only the
// source's own lookup showed to be the host: a name that resolved to a host
// address (devbox.lan from a container) or, from the host, to loopback (the
// machine's own hostname, 127.0.1.1 on Ubuntu). collect couldn't know that
// before the probes ran. It also collects it when collect couldn't list the
// containers.
func (r *run) hostAfterLookup(ctx context.Context) error {
	if ctx.Err() == nil {
		r.hostSide(ctx)
	}
	return nil
}

// hostSide collects the host's side of a target that is the host, once,
// and sets hostDone then: the host's listeners, as the source reaches them,
// and, with the container list, the containers that publish the port
// (collectHost). It does nothing for a target that isn't the host.
func (r *run) hostSide(ctx context.Context) {
	if r.hostDone {
		return
	}
	ht, ok := evidence.NewView(r.q, r.store.Snapshot()).HostTarget()
	if !ok {
		return
	}
	if r.docker == nil || r.list == nil {
		r.store.Add(r.hostListenersFor(&ht))
		r.hostDone = true
		return
	}
	r.collectHost(ctx, r.list, containerIDs(r.store.Snapshot()))
}

// containerIDs lists the containers whose metadata items records, by ID.
func containerIDs(items []evidence.Evidence) map[string]bool {
	have := map[string]bool{}
	for _, e := range items {
		if c, ok := e.Data.(evidence.Container); ok {
			have[c.ID] = true
		}
	}
	return have
}

// skippedContainers records containers whyreach did not inspect because of
// a bound. Its status keeps it out of the gaps derived from records (the gap
// is added with it), while View.Incomplete sees it.
// unlisted is the record of the containers whose metadata went unread
// because Docker's list of containers couldn't be read: skipped, so the
// gap the failed list already makes isn't made twice.
func unlisted(g Gap) evidence.Evidence {
	return evidence.Evidence{
		Kind:       evidence.KindContainer,
		Context:    evidence.ContextRef{Kind: evidence.ContextHost, Name: "docker"},
		Subject:    "the other containers",
		Status:     evidence.StatusSkipped,
		ObservedAt: time.Now(),
		Err:        &evidence.Error{Code: evidence.CodeDockerUnavailable, Message: "the list of containers could not be read: " + g.Detail},
		Source:     "docker GET /containers/json",
	}
}

func skippedContainers(g Gap) evidence.Evidence {
	return evidence.Evidence{
		Kind:       evidence.KindContainer,
		Context:    evidence.ContextRef{Kind: evidence.ContextHost, Name: "docker"},
		Subject:    g.What,
		Status:     evidence.StatusSkipped,
		ObservedAt: time.Now(),
		Err:        &evidence.Error{Code: evidence.CodeLimit, Message: g.Detail},
		Source:     "docker GET /containers/json",
	}
}

// inspectFailure records metadata that could not be read, so the diagnosis
// says so instead of treating the container as absent.
func (r *run) inspectFailure(id, name string, err error) evidence.Evidence {
	ev := evidence.Evidence{
		Kind:       evidence.KindContainer,
		Context:    evidence.ContextRef{Kind: evidence.ContextContainer, Container: evidence.ShortID(id), Name: name},
		Subject:    "container:" + name,
		Status:     evidence.StatusFailed,
		ObservedAt: time.Now(),
		Err:        &evidence.Error{Code: evidence.CodeDockerUnavailable, Message: err.Error()},
		Source:     "docker GET /containers/{id}/json",
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		ev.Status = evidence.StatusTimeout
		ev.Err.Code = evidence.CodeTimeout
	}
	return ev
}

// readListeners reads each container's listening sockets, once per
// container. Where Docker's PIDs aren't this machine's (Docker Desktop),
// each read is a probe container, so a diagnosis makes at most
// maxProbeListeners of them, in the order given (callers list the source
// and the destinations first); the rest become skipped records and a gap.
func (r *run) readListeners(ctx context.Context, cs []evidence.Container) {
	seen := map[string]bool{}
	var read []evidence.Container
	var cut []string
	for _, c := range cs {
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		if !r.engineHere && c.Running() && !r.takeProbeListener() {
			cut = append(cut, c.DisplayName())
			r.store.Add(r.listenersCut(c))
			continue
		}
		read = append(read, c)
	}
	if len(cut) > 0 {
		r.gaps = append(r.gaps, r.probeListenersGap(cut))
	}
	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(collectParallel)
	for _, c := range read {
		g.Go(func() error {
			r.store.Add(r.containerListeners(ctx, c))
			return nil
		})
	}
	_ = g.Wait() // the goroutines never return errors
}

// maxProbeListeners bounds the containers whose listening sockets one
// diagnosis reads inside probe containers, where Docker's PIDs aren't this
// machine's: each read is a container run and a probe token.
const maxProbeListeners = 6

// takeProbeListener takes one of the diagnosis's probe-container listener
// reads; false when none is left. Callers take them in order, before any
// read starts, so this bound picks the same containers every time. Each
// read also draws on the policy's rate limit, inside the parallel reads:
// close to that limit, which of them it refuses depends on timing.
func (r *run) takeProbeListener() bool {
	if r.probeListeners >= maxProbeListeners {
		return false
	}
	r.probeListeners++
	return true
}

// listenersCut is the record of a container whose listeners went unread
// because the diagnosis used its probe-container reads up.
func (r *run) listenersCut(c evidence.Container) evidence.Evidence {
	return evidence.Evidence{
		Kind: evidence.KindListeners, Context: evidence.InContainer(c), Subject: "listeners",
		Status: evidence.StatusSkipped, ObservedAt: time.Now(), Source: probeListenerSource,
		Err: &evidence.Error{Code: evidence.CodeLimit, Message: fmt.Sprintf(
			"whyreach reads at most %d containers' listening sockets through probe containers in one diagnosis", maxProbeListeners)},
	}
}

func (r *run) probeListenersGap(names []string) Gap {
	return Gap{
		What:   "listening sockets in " + strings.Join(names, ", "),
		Why:    "skipped",
		Detail: fmt.Sprintf("where Docker's PIDs aren't this machine's (Docker Desktop), each container's listening sockets take a probe container, and whyreach reads at most %d in one diagnosis", maxProbeListeners),
	}
}

// Where a container's listening sockets come from. ProcListenerSource is
// set only on a record whose read went through /proc/<pid> on this
// machine, so the lab can check that none did where Docker's PIDs aren't
// this machine's, whether the read worked or not.
const (
	ProcListenerSource  = "/proc/<pid>/net/tcp{,6} read from the host, after /proc/<pid>/cgroup named the container"
	probeListenerSource = "/proc/net/tcp{,6} read inside a probe container joined to the container's network namespace"
	stateSource         = "docker GET /containers/{id}/json (its state)"
)

// containerListeners reads a running container's listening sockets: from
// the host through /proc/<pid> where Docker Engine runs on this machine,
// otherwise inside a probe container (listenersElsewhere).
func (r *run) containerListeners(ctx context.Context, c evidence.Container) evidence.Evidence {
	ev := evidence.Evidence{
		Kind: evidence.KindListeners, Context: evidence.InContainer(c), Subject: "listeners",
		ObservedAt: time.Now(),
	}
	switch {
	case ctx.Err() != nil:
		ev.Status = evidence.StatusTimeout
		ev.Err = &evidence.Error{Code: evidence.CodeTimeout, Message: "the diagnosis deadline passed before the listeners were read"}
		return ev
	case !c.Running() || c.Pid <= 0:
		ev.Status, ev.Source = evidence.StatusSkipped, stateSource
		ev.Err = &evidence.Error{Code: evidence.CodeNotFound, Message: fmt.Sprintf("%s is %s, so it has no sockets to read", c.DisplayName(), c.State)}
		return ev
	case !r.engineHere:
		return r.listenersElsewhere(ctx, c)
	}
	ev.Source = ProcListenerSource
	start := time.Now()
	socks, err := r.e.d.Listeners.Container(c.Pid, c.ID)
	ev.Duration, ev.ObservedAt = time.Since(start), time.Now()
	if err != nil {
		ev.Status, ev.Err = probe.Classify(err)
		return ev
	}
	ev.Status = evidence.StatusOK
	ev.Data = evidence.Listeners{Sockets: socks}
	return ev
}

// listenersElsewhere reads a container's listening sockets where Docker's
// PIDs aren't this machine's (Docker Desktop, its WSL integration
// included): never through /proc/<pid> or setns, which would reach an
// unrelated local process, but inside a probe container joined to its
// network namespace (tier 2b; never the netns executor, which needs this
// machine's PIDs). Without probe containers the record says why and how
// to allow them (executor.PIDsElsewhere).
func (r *run) listenersElsewhere(ctx context.Context, c evidence.Container) evidence.Evidence {
	where := evidence.InContainer(c)
	elsewhere := func() evidence.Evidence {
		return evidence.Evidence{
			Kind: evidence.KindListeners, Context: where, Subject: "listeners", Status: evidence.StatusUnsupported,
			ObservedAt: time.Now(), Source: probeListenerSource,
			Err: &evidence.Error{Code: evidence.CodeUnsupported, Message: executor.PIDsElsewhere},
		}
	}
	if r.e.d.Probe == nil {
		return elsewhere()
	}
	evs, err := r.e.d.Probe.Run(ctx, where, []probe.Spec{{Kind: probe.SpecListeners}})
	if err != nil {
		r.e.d.Logger.Warn("listeners through a probe container failed", "container", c.DisplayName(), "err", err)
	}
	for _, ev := range evs {
		if ev.Kind != evidence.KindListeners {
			continue
		}
		if ev.Status == evidence.StatusPermissionDenied && ev.Err != nil && ev.Err.Message == executor.ProbeContainersOff {
			return elsewhere()
		}
		if ev.ObservedAt.IsZero() {
			ev.ObservedAt = time.Now()
		}
		if ev.Source == "" {
			ev.Source = probeListenerSource
		}
		return ev
	}
	return evidence.Evidence{
		Kind: evidence.KindListeners, Context: where, Subject: "listeners", Status: evidence.StatusFailed,
		ObservedAt: time.Now(), Source: probeListenerSource,
		Err: &evidence.Error{Code: evidence.CodeInternal, Message: "the probe container returned no listening sockets record"},
	}
}

// hostListeners reads the listening sockets of whyreach's own netns, which
// is the host's when whyreach runs natively.
func (r *run) hostListeners() evidence.Evidence {
	ev := evidence.Evidence{
		Kind: evidence.KindListeners, Context: r.host(), Subject: "listeners",
		Source: "/proc/thread-self/net/tcp{,6} in whyreach's own network namespace",
	}
	start := time.Now()
	socks, err := r.e.d.Listeners.Host()
	ev.Duration, ev.ObservedAt = time.Since(start), time.Now()
	if err != nil {
		ev.Status, ev.Err = probe.Classify(err)
		return ev
	}
	ev.Status = evidence.StatusOK
	ev.Data = evidence.Listeners{Sockets: socks}
	return ev
}
