package engine

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/platform"
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
		r.setDaemon(v)
		c := Check{Name: "docker", Status: CheckOK, Detail: fmt.Sprintf("%s %s on %s/%s, API %s (whyreach speaks %s), %s",
			v.Platform.Name, v.Version, v.Os, v.Arch, v.APIVersion, e.d.Docker.APIVersion(), e.d.Docker.Endpoint())}
		if !r.engineHere && !r.platform.WindowsHost() {
			c.Status = CheckWarn
			c.Detail += "; whyreach supports Docker Engine on Linux, and in WSL2 Docker Engine or Docker Desktop's WSL integration (other Docker Desktop setups arrive in v0.3)"
		}
		out = append(out, c)
	}
	if r.platform.Name == "" {
		r.platform = e.platformFor(platform.Daemon{})
	}
	out = append(out, platformChecks(r.platform)...)

	if e.d.Interfaces == nil {
		out = append(out, Check{Name: "interfaces", Status: CheckWarn, Detail: "no interface reader on this platform"})
	} else if addrs, err := e.d.Interfaces(); err != nil && err.Error() == executor.HostHidden {
		out = append(out, Check{Name: "interfaces", Status: CheckWarn, Detail: err.Error(), Fix: executor.HostHiddenAdvice + "."})
	} else if err != nil {
		out = append(out, Check{Name: "interfaces", Status: CheckFail, Detail: err.Error()})
	} else {
		out = append(out, Check{Name: "interfaces", Status: CheckOK, Detail: fmt.Sprintf("%d with addresses, read from the kernel", len(addrs.Interfaces))})
	}

	if ev := r.hostListeners(); ev.OK() {
		n := len(ev.Data.(evidence.Listeners).Sockets)
		out = append(out, Check{Name: "host listeners", Status: CheckOK, Detail: fmt.Sprintf("%d TCP listeners readable from /proc/thread-self/net/tcp{,6}", n)})
	} else if ev.Err.Message == executor.HostHidden {
		// Only host flows need them: whyreach's image without --network host
		// still diagnoses containers.
		out = append(out, Check{Name: "host listeners", Status: CheckWarn, Detail: ev.Err.Message, Fix: executor.HostHiddenAdvice + "."})
	} else {
		out = append(out, Check{Name: "host listeners", Status: CheckFail, Detail: ev.Err.Message})
	}
	out = append(out, r.containerListenerCheck(ctx))
	return out
}

const dockerFix = "Start Docker, or let this user use its socket: add it to the docker group (Docker access is root-equivalent)."

// WSLIdle is doctor's warning on wsl2-engine: WSL stops idle distros, and
// dockerd with them (INITIAL.md §3.7).
const WSLIdle = "WSL stops a distro soon after its last process exits (instanceIdleTimeout, 15 s by default) and the WSL2 VM once every distro has stopped (vmIdleTimeout, 60 s by default): that stops dockerd and every container in this distro. When the distro starts again (an MCP client's wsl.exe launch does), dockerd restarts only if a service manager starts it, and only containers with a restart policy come back"

// WSLIdleFix says how to keep the distro running. Docker itself
// recommends Docker Desktop over Docker Engine in WSL2.
const WSLIdleFix = "Keep a terminal open on this distro while you work, or set instanceIdleTimeout=-1 under [general] in %UserProfile%\\.wslconfig on Windows (then wsl --shutdown once); Docker recommends Docker Desktop's WSL integration over Docker Engine in WSL2."

// platformChecks are doctor's lines about the platform: which setup
// whyreach found (INITIAL.md §3.7) and what that means for its checks.
func platformChecks(p evidence.Platform) []Check {
	c := Check{Name: "platform", Status: CheckInfo}
	switch p.Name {
	case platform.LinuxEngine:
		c.Detail = p.Name + ": Docker Engine on this Linux machine"
		if p.InContainer {
			c.Detail += " (whyreach runs in a container on it)"
		}
	case platform.WSL2Engine:
		c.Detail = p.Name + ": Docker Engine in this WSL2 distro; host-side checks describe the WSL2 VM, not Windows"
		if p.InContainer {
			c.Detail = p.Name + ": Docker Engine in a WSL2 distro (whyreach runs in a container on it); host-side checks describe the WSL2 VM, not Windows"
		}
		return []Check{c, {Name: "wsl idle shutdown", Status: CheckWarn, Detail: WSLIdle, Fix: WSLIdleFix}}
	case platform.WSL2Desktop:
		c.Detail = p.Name + ": Docker Desktop's WSL integration. Its containers run in Docker Desktop's VM, so Docker's PIDs aren't this distro's: whyreach runs container checks and reads containers' listening sockets only inside probe containers (tier 2b), never through /proc or setns. Host-side checks describe this WSL2 VM; the host containers reach (host.docker.internal) is Windows, whose side whyreach can't check"
	case "":
	default:
		c.Status = CheckWarn
		c.Detail = p.Name + ": whyreach can't tell where Docker runs its containers, or the setup isn't supported yet (Docker Desktop on Linux, macOS and Windows hosts arrive in v0.3)"
		if p.WSL {
			c.Detail += "; whyreach runs in WSL2, so host-side checks describe the WSL2 VM, not Windows"
		}
	}
	return []Check{c}
}

// containerListenerCheck reads one running container's listeners, the way
// a diagnosis reads the destination's.
func (r *run) containerListenerCheck(ctx context.Context) Check {
	c := Check{Name: "container listeners"}
	if r.docker == nil {
		c.Status, c.Detail = CheckInfo, "not checked: no Docker API"
		return c
	}
	if !r.engineHere {
		c.Status, c.Detail = CheckInfo, "Docker's PIDs here are processes in Docker Desktop's VM, not this machine's, so containers' listening sockets are read inside probe containers (tier 2b), never through /proc/<pid>"
		return c
	}
	lctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	list, err := r.docker.ListContainers(lctx, false)
	cancel()
	if err != nil {
		c.Status, c.Detail = CheckFail, err.Error()
		return c
	}
	// Not whyreach's own container: inside its own cgroup namespace, its
	// cgroup file can't name it.
	list = slices.DeleteFunc(list, func(s docker.Summary) bool { return r.e.d.Self != "" && s.ID == r.e.d.Self })
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
		if ev.Err.Message == executor.PIDsHidden {
			c.Fix = executor.PIDsHiddenAdvice + "."
		}
		return c
	}
	c.Status, c.Detail = CheckOK, fmt.Sprintf("read %s's through /proc/<pid>/net/tcp{,6}, no root needed", ctr.Name)
	return c
}
