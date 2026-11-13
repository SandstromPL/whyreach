package engine

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Check is one line of whyreach doctor: a capability and whether it works.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok, warn, fail or info
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// Check statuses.
const (
	CheckOK   = "ok"
	CheckWarn = "warn" // works partly, or a tier is off
	CheckFail = "fail" // something whyreach needs doesn't work
	CheckInfo = "info"
)

// SelfCheck reports what the engine can observe on this machine: the Docker
// API, the host's interfaces and listeners, and a container's listeners
// through /proc. It writes nothing.
func (e *Engine) SelfCheck(ctx context.Context) []Check {
	r := &run{e: e, docker: e.d.Docker, timing: map[string]time.Duration{}}
	var out []Check
	switch {
	case e.d.Docker == nil && e.d.DockerErr == nil:
		out = append(out, Check{Name: "docker", Status: CheckWarn, Detail: "Docker access is turned off in the config",
			Fix: "Set docker = true under [permissions] in " + e.d.ConfigPath + "."})
	case e.d.Docker == nil:
		out = append(out, Check{Name: "docker", Status: CheckFail, Detail: e.d.DockerErr.Error(), Fix: dockerFix})
	default:
		v, err := negotiate(ctx, e.d.Docker)
		if err != nil {
			out = append(out, Check{Name: "docker", Status: CheckFail, Detail: err.Error(), Fix: dockerFix})
			r.docker = nil
			break
		}
		r.version = v
		r.linux = runtime.GOOS == "linux" && v.Os == "linux" && !v.Desktop()
		c := Check{Name: "docker", Status: CheckOK, Detail: fmt.Sprintf("%s %s on %s/%s, API %s (whyreach speaks %s), %s",
			v.Platform.Name, v.Version, v.Os, v.Arch, v.APIVersion, e.d.Docker.APIVersion(), e.d.Docker.Endpoint())}
		if !r.linux {
			c.Status = CheckWarn
			c.Detail += "; this is not Linux Docker Engine on this host, which v0.1 supports (Docker Desktop arrives in v0.3)"
		}
		out = append(out, c)
	}

	if e.d.Interfaces == nil {
		out = append(out, Check{Name: "interfaces", Status: CheckWarn, Detail: "no interface reader on this platform"})
	} else if addrs, err := e.d.Interfaces(); err != nil {
		out = append(out, Check{Name: "interfaces", Status: CheckFail, Detail: err.Error()})
	} else {
		out = append(out, Check{Name: "interfaces", Status: CheckOK, Detail: fmt.Sprintf("%d with addresses, read from the kernel", len(addrs.Interfaces))})
	}

	if ev := r.hostListeners(); ev.OK() {
		n := len(ev.Data.(evidence.Listeners).Sockets)
		out = append(out, Check{Name: "host listeners", Status: CheckOK, Detail: fmt.Sprintf("%d TCP listeners readable from /proc/net/tcp{,6}", n)})
	} else {
		out = append(out, Check{Name: "host listeners", Status: CheckFail, Detail: ev.Err.Message})
	}
	out = append(out, r.containerListenerCheck(ctx))
	return out
}

const dockerFix = "Start Docker, or let this user use its socket: add it to the docker group (Docker access is root-equivalent)."

// containerListenerCheck reads one running container's listeners, the way
// a diagnosis reads the destination's.
func (r *run) containerListenerCheck(ctx context.Context) Check {
	c := Check{Name: "container listeners"}
	if r.docker == nil {
		c.Status, c.Detail = CheckInfo, "not checked: no Docker API"
		return c
	}
	if !r.linux {
		c.Status, c.Detail = CheckWarn, "read through /proc only on Linux Docker Engine; elsewhere they will be read inside probe containers (v0.3)"
		return c
	}
	lctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	list, err := r.docker.ListContainers(lctx, false)
	cancel()
	if err != nil {
		c.Status, c.Detail = CheckFail, err.Error()
		return c
	}
	if len(list) == 0 {
		c.Status, c.Detail = CheckInfo, "no running container to try; listeners are read through /proc/<pid>/net/tcp{,6}, which needs no root on Linux Docker Engine"
		return c
	}
	ctr, err := r.inspect(ctx, list[0].ID)
	if err != nil {
		c.Status, c.Detail = CheckFail, err.Error()
		return c
	}
	ev := r.containerListeners(ctx, ctr)
	if !ev.OK() {
		c.Status, c.Detail = CheckFail, ev.Err.Message
		c.Fix = "Run whyreach as a user in the docker group on Linux Docker Engine, or as root."
		return c
	}
	c.Status, c.Detail = CheckOK, fmt.Sprintf("read %s's through /proc/<pid>/net/tcp{,6}, no root needed", ctr.Name)
	return c
}
