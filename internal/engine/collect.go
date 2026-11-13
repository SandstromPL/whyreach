package engine

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// collect gathers metadata for the containers the question involves and
// reads their listening sockets from the host.
func (r *run) collect(ctx context.Context) error {
	dk := r.e.d.Docker
	if dk == nil || (r.q.From.Kind == evidence.SourceContainer && r.q.From.ContainerID == "") {
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	list, err := dk.ListContainers(lctx, true)
	cancel()
	if err != nil {
		r.gaps = append(r.gaps, Gap{What: "the list of containers", Why: "failed", Detail: err.Error()})
		return nil
	}

	known := r.store.Snapshot()
	have := map[string]bool{}
	var srcNets []string
	ownerID := ""
	view := evidence.NewView(r.q, known)
	if owner, ok := view.NetnsOwner(); ok && !owner.C.HostNetwork() {
		srcNets = owner.C.NetworkNames()
		ownerID = owner.C.ID
	}
	for _, e := range known {
		if c, ok := e.Data.(evidence.Container); ok {
			have[c.ID] = true
		}
	}

	// Containers on the source's networks are inspected for their aliases
	// (the list has none); elsewhere, only those that match by name or
	// address are.
	to := r.q.To
	var peers, elsewhere []string
	for _, s := range list {
		if have[s.ID] {
			continue
		}
		if shares(s.Networks(), srcNets) {
			if len(peers) < maxPeers {
				peers = append(peers, s.ID)
			}
			continue
		}
		if matchesTarget(s, to) && len(elsewhere) < maxElsewhere {
			elsewhere = append(elsewhere, s.ID)
		}
	}
	inspected := r.inspectAll(ctx, append(peers, elsewhere...))

	// Decide what to record: for a loopback target every peer (WR007 looks
	// for the service among them), otherwise the destinations.
	view = evidence.NewView(r.q, append(slices.Clone(known), inspected...))
	dests := view.Destinations().All()
	isDest := map[string]bool{}
	for _, m := range dests {
		isDest[m.C.ID] = true
	}
	var listenFor []evidence.Container
	for _, ev := range inspected {
		c := ev.Data.(evidence.Container)
		if to.Class == evidence.TargetLoopback || isDest[c.ID] {
			r.store.Add(ev)
		}
		if to.Class == evidence.TargetLoopback && c.NetnsOwner() != ownerID {
			listenFor = append(listenFor, c)
		}
	}
	for i, m := range dests {
		if i == maxDestinations {
			break
		}
		if m.C.ID != ownerID {
			listenFor = append(listenFor, m.C)
		}
	}
	if to.Class == evidence.TargetLoopback {
		if owner, ok := view.NetnsOwner(); ok && !owner.C.HostNetwork() {
			listenFor = append(listenFor, owner.C)
			// WR007 chooses host.docker.internal when the host serves the port.
			r.store.Add(r.hostListeners())
		}
	}
	r.readListeners(ctx, listenFor)
	return nil
}

func shares(a, b []string) bool {
	for _, n := range a {
		if slices.Contains(b, n) {
			return true
		}
	}
	return false
}

// matchesTarget is a cheap pre-filter on the container list: the container
// name or Compose service equals the target name, or it holds the target
// address. Aliases need an inspect, which is done for the source's networks.
func matchesTarget(s docker.Summary, to evidence.Target) bool {
	switch to.Class {
	case evidence.TargetName:
		h := strings.TrimSuffix(strings.ToLower(to.Host), ".")
		return strings.EqualFold(s.Name(), h) || strings.EqualFold(s.Labels[docker.LabelComposeService], h)
	case evidence.TargetIP:
		return s.HasAddr(to.Addr)
	default:
		return false
	}
}

// inspectAll inspects containers in parallel and returns their records in
// the order given. A container that vanished in between is skipped.
func (r *run) inspectAll(ctx context.Context, ids []string) []evidence.Evidence {
	out := make([]evidence.Evidence, len(ids))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(collectParallel)
	for i, id := range ids {
		g.Go(func() error {
			_, ev, err := r.inspectEv(gctx, id)
			if err != nil {
				r.e.d.Logger.Debug("inspect failed", "container", evidence.ShortID(id), "err", err)
				return nil
			}
			out[i] = ev
			return nil
		})
	}
	_ = g.Wait() // the goroutines never return errors
	var kept []evidence.Evidence
	for _, ev := range out {
		if ev.Kind != "" {
			kept = append(kept, ev)
		}
	}
	return kept
}

// readListeners reads each container's listening sockets, once per netns.
func (r *run) readListeners(ctx context.Context, cs []evidence.Container) {
	seen := map[string]bool{}
	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(collectParallel)
	for _, c := range cs {
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		g.Go(func() error {
			r.store.Add(r.containerListeners(ctx, c))
			return nil
		})
	}
	_ = g.Wait() // the goroutines never return errors
}

const listenerSource = "/proc/<pid>/net/tcp{,6} read from the host, after /proc/<pid>/cgroup named the container"

func (r *run) containerListeners(ctx context.Context, c evidence.Container) evidence.Evidence {
	ev := evidence.Evidence{
		Kind: evidence.KindListeners, Context: evidence.InContainer(c), Subject: "listeners",
		ObservedAt: time.Now(), Source: listenerSource,
	}
	switch {
	case ctx.Err() != nil:
		ev.Status = evidence.StatusTimeout
		ev.Err = &evidence.Error{Code: evidence.CodeTimeout, Message: "the diagnosis deadline passed before the listeners were read"}
		return ev
	case !r.linux:
		ev.Status = evidence.StatusUnsupported
		ev.Err = &evidence.Error{Code: evidence.CodeUnsupported, Message: fmt.Sprintf(
			"container listeners are read through /proc only on Linux Docker Engine (daemon %q on %s)", r.version.Platform.Name, r.version.Os)}
		return ev
	case !c.Running() || c.Pid <= 0:
		ev.Status = evidence.StatusSkipped
		ev.Err = &evidence.Error{Code: evidence.CodeNotFound, Message: fmt.Sprintf("%s is %s, so it has no sockets to read", c.DisplayName(), c.State)}
		return ev
	}
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

// hostListeners reads the listening sockets of whyreach's own netns, which
// is the host's when whyreach runs natively.
func (r *run) hostListeners() evidence.Evidence {
	ev := evidence.Evidence{
		Kind: evidence.KindListeners, Context: evidence.Host(), Subject: "listeners",
		Source: "/proc/net/tcp{,6} in whyreach's own network namespace",
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
