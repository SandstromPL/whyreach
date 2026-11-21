package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/platform"
	"github.com/SandstromPL/whyreach/internal/target"
)

// resolve negotiates with Docker, records its version, and finds the source
// container and the container whose network namespace it uses.
func (r *run) resolve(ctx context.Context) error {
	dk := r.docker
	if dk == nil {
		r.dockerGap(r.e.d.DockerErr)
		r.recordPlatform()
		return nil
	}
	vctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	start := time.Now()
	v, err := dk.Negotiate(vctx)
	cancel()
	if err != nil {
		r.docker = nil // nothing else will work in this diagnosis either
		r.dockerGap(err)
		r.recordPlatform()
		return nil
	}
	r.setDaemon(v)
	r.store.Add(evidence.Evidence{
		Kind: evidence.KindDockerVersion, Context: r.host(), Subject: "docker", Status: evidence.StatusOK,
		ObservedAt: time.Now(), Duration: time.Since(start), Source: "docker GET /version",
		Data: evidence.DockerVersion{
			Version: v.Version, APIVersion: dk.APIVersion(), DaemonMaxAPI: v.APIVersion, Os: v.Os, Arch: v.Arch,
			PlatformName: v.Platform.Name, Endpoint: dk.Endpoint(), LinuxEngine: r.engineHere, KernelVersion: v.KernelVersion,
		},
	})
	r.recordPlatform()
	if r.from.Kind == target.FromHost {
		return nil
	}
	r.networks = r.networkList(ctx)
	src, err := r.findSource(ctx)
	if err != nil {
		if _, ok := errors.AsType[*Error](err); ok {
			return err
		}
		r.dockerGap(err)
		return nil
	}
	r.q.From.ContainerID = src.ID
	if owner := src.NetnsOwner(); owner != "" {
		if _, err := r.inspect(ctx, owner); err != nil {
			r.gaps = append(r.gaps, Gap{
				What: fmt.Sprintf("the container whose network namespace %s uses (%s)", src.DisplayName(), evidence.ShortID(owner)),
				Why:  "failed", Detail: err.Error(),
			})
		}
	}
	return nil
}

// platformSource is where the platform record comes from.
const platformSource = "whyreach's own environment (/proc/sys/kernel/osrelease, WSL's interop entry in /proc/sys/fs/binfmt_misc, container markers) and the daemon's GET /version"

// recordPlatform records where whyreach and the containers run (INITIAL.md
// §3.7): rules read it from the view. Without the daemon's answer, it says
// only where whyreach runs.
func (r *run) recordPlatform() {
	ev := evidence.Evidence{
		Kind: evidence.KindPlatform, Context: r.host(), Subject: "platform", Status: evidence.StatusOK,
		ObservedAt: time.Now(), Source: platformSource,
	}
	if r.platform.Name == "" {
		r.platform = r.e.platformFor(platform.Daemon{})
		ev.Limitations = []string{"the Docker daemon didn't answer, so which Docker runs the containers is unknown"}
	}
	ev.Data = r.platform
	r.store.Add(ev)
}

// findSource resolves "container:<name|id>" or "service:<name>[@<project>]".
func (r *run) findSource(ctx context.Context) (evidence.Container, error) {
	switch r.from.Kind {
	case target.FromContainer:
		c, err := r.inspect(ctx, r.from.Name)
		if errors.Is(err, docker.ErrNotFound) {
			return c, &Error{Code: evidence.CodeNotFound, Message: fmt.Sprintf("no container named %q (or with that ID); list them with docker ps", r.from.Name)}
		}
		return c, err
	case target.FromService:
		labels := []string{docker.LabelComposeService + "=" + r.from.Name}
		if r.from.Project != "" {
			labels = append(labels, docker.LabelComposeProject+"="+r.from.Project)
		}
		lctx, cancel := context.WithTimeout(ctx, dockerTimeout)
		list, err := r.docker.ListContainers(lctx, true, labels...)
		cancel()
		if err != nil {
			return evidence.Container{}, err
		}
		if len(list) == 0 {
			return evidence.Container{}, &Error{Code: evidence.CodeNotFound, Message: fmt.Sprintf("no container runs Compose service %q", r.from.String())}
		}
		var projects []string
		for _, s := range list {
			if p := s.Labels[docker.LabelComposeProject]; !slices.Contains(projects, p) {
				projects = append(projects, p)
			}
		}
		slices.Sort(projects)
		if len(projects) > 1 {
			return evidence.Container{}, &Error{Code: evidence.CodeInvalidArgument, Message: fmt.Sprintf(
				"Compose service %q exists in several projects (%s); name one: service:%s@<project>",
				r.from.Name, strings.Join(projects, ", "), r.from.Name)}
		}
		// Prefer a running replica; the list is sorted by name.
		pick := list[0]
		for _, s := range list {
			if s.State == evidence.StateRunning {
				pick = s
				break
			}
		}
		return r.inspect(ctx, pick.ID)
	default:
		return evidence.Container{}, &Error{Code: evidence.CodeInternal, Message: "unknown source kind " + r.from.Kind}
	}
}

// inspect fetches a container's metadata and records it as evidence.
func (r *run) inspect(ctx context.Context, idOrName string) (evidence.Container, error) {
	c, ev, err := r.inspectEv(ctx, idOrName)
	if err == nil {
		r.store.Add(ev)
	}
	return c, err
}

// inspectEv fetches a container's metadata without recording it.
func (r *run) inspectEv(ctx context.Context, idOrName string) (evidence.Container, evidence.Evidence, error) {
	ictx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	start := time.Now()
	c, err := r.docker.InspectContainer(ictx, idOrName)
	if err != nil {
		return c, evidence.Evidence{}, err
	}
	for i := range c.Networks {
		if n, ok := r.networks[c.Networks[i].Network]; ok {
			c.Networks[i].Internal = n.Internal
			c.Networks[i].Subnets = n.Subnets
			c.Networks[i].Gateways = n.Gateways
			c.Networks[i].ICCDisabled = n.ICCDisabled
		}
	}
	return c, evidence.Evidence{
		Kind: evidence.KindContainer, Context: evidence.InContainer(c), Subject: "container:" + c.Name,
		Status: evidence.StatusOK, ObservedAt: time.Now(), Duration: time.Since(start), Data: c,
		Source: "docker GET /containers/{id}/json",
	}, nil
}

// networkList reads Docker's networks by name: whether each is internal:
// true, whose containers have no way out of the host (WR015, and what a
// failed external lookup means for WR020), and its subnets, which tell what
// a container reaches on a network directly. It returns nil when the list
// can't be read.
func (r *run) networkList(ctx context.Context) map[string]docker.Network {
	lctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	nets, err := r.docker.ListNetworks(lctx)
	if err != nil {
		return nil
	}
	out := map[string]docker.Network{}
	for _, n := range nets {
		out[n.Name] = n
	}
	return out
}

// dockerGap records that Docker metadata is unavailable.
func (r *run) dockerGap(err error) {
	g := Gap{
		What:        "Docker metadata (containers, networks, listeners)",
		Why:         "failed",
		HowToEnable: "Start Docker, or make the socket readable: add the user to the docker group (Docker access is root-equivalent).",
	}
	if err != nil {
		g.Detail = err.Error()
		if errors.Is(err, docker.ErrUnsupported) {
			g.Why = "unsupported"
			g.HowToEnable = ""
		}
	} else {
		g.Detail = "Docker access is turned off in the config ([permissions] docker = false)"
		g.Why = "permission"
		g.HowToEnable = "Set docker = true under [permissions] in " + r.e.d.ConfigPath + "."
	}
	r.gaps = append(r.gaps, g)
}
