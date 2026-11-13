package policy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/platform"
)

// Doctor checks what whyreach can do on this machine and with this config
// (whyreach doctor): the engine's own checks, the permission tiers, whether
// probe containers could run, where whyreach runs, and the audit log. It
// writes nothing to Docker.
func (p *Policy) Doctor(ctx context.Context) []engine.Check {
	out := p.engine.SelfCheck(ctx)
	out = append(out, p.probeContainerCheck(ctx))
	allow := "any address the block list allows (no allowlist)"
	if len(p.d.Settings.Allow) > 0 {
		allow = strings.Join(p.d.Settings.Allow, ", ")
	}
	out = append(out, engine.Check{Name: "probe policy", Status: engine.CheckInfo,
		Detail: fmt.Sprintf("TCP probes may go to %s; at most %d probes a minute; link-local and cloud-metadata addresses are always blocked", allow, p.d.Settings.RatePerMinute)})

	pl := platform.Detect()
	out = append(out, p.netnsCheck(pl))
	if pl.InContainer {
		out = append(out, engine.Check{Name: "environment", Status: engine.CheckWarn,
			Detail: "whyreach runs inside a container: host interfaces and listeners describe that container's network namespace, not the host's"})
	}
	if pl.WSL {
		out = append(out, engine.Check{Name: "environment", Status: engine.CheckWarn,
			Detail: "WSL2: host checks describe the WSL2 VM, not Windows (support arrives in v0.2)"})
	}
	return append(out, p.auditCheck())
}

// netnsCheck says whether container checks enter the containers' network
// namespaces themselves (tier 3, the netns executor).
func (p *Policy) netnsCheck(pl platform.Info) engine.Check {
	c := engine.Check{Name: "netns executor", Status: engine.CheckInfo}
	_, why := pl.NetnsExecutor()
	switch {
	case p.d.Netns != nil:
		c.Detail = "on (root): on Linux Docker Engine, DNS and TCP checks from containers enter their network namespaces directly, with no Docker write. Run whyreach as root for the CLI only; as an MCP server, prefer a regular user (INITIAL.md §3.5)"
	case why == "":
		c.Detail = "off: it needs the Docker API"
	default:
		c.Detail = "off: " + why + ". whyreach needs no root: without it, container checks use probe containers (tier 2b)"
	}
	return c
}

func (p *Policy) probeContainerCheck(ctx context.Context) engine.Check {
	c := engine.Check{Name: "probe containers"}
	if p.d.Netns != nil && !p.ProbeContainers() {
		c.Status = engine.CheckInfo
		c.Detail = "off (tier 2b), and not needed on Linux Docker Engine while whyreach runs as root: the netns executor runs container checks"
		return c
	}
	if !p.ProbeContainers() {
		c.Status = engine.CheckWarn
		c.Detail = "off (tier 2b): DNS and TCP checks from inside containers are skipped; metadata and listeners still settle most causes"
		c.Fix = "Set probe_containers = true under [permissions] in " + p.d.Settings.ConfigPath + ", or approve them when an MCP client asks."
		if !p.CanUseProbeContainers() {
			c.Fix = "They need the Docker API."
		}
		return c
	}
	ex, err := p.probeExecutor()
	if err != nil {
		c.Status, c.Detail = engine.CheckFail, err.Error()
		return c
	}
	pc, ok := ex.(*executor.ProbeContainer)
	if !ok {
		c.Status, c.Detail = engine.CheckOK, "on"
		return c
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, err := pc.Readiness(rctx)
	switch {
	case err != nil:
		c.Status, c.Detail = engine.CheckFail, "on, but they can't run: "+err.Error()
	case r.Imported:
		c.Status, c.Detail = engine.CheckOK, "on; image "+r.Image+" is imported"
	default:
		c.Status, c.Detail = engine.CheckOK, "on; the first probe imports whyreach's own binary as "+r.Image+" (no registry pull)"
	}
	return c
}

func (p *Policy) auditCheck() engine.Check {
	c := engine.Check{Name: "audit log"}
	if p.d.Audit == nil {
		c.Status, c.Detail = engine.CheckWarn, "none: tool calls are not recorded"
		return c
	}
	path := p.d.Audit.Path()
	st, err := os.Stat(path)
	switch {
	case err == nil && st.Mode().Perm()&0o077 != 0:
		c.Status, c.Detail = engine.CheckWarn, fmt.Sprintf("%s is readable by other users (mode %v)", path, st.Mode().Perm())
		c.Fix = "chmod 600 " + path
	case err == nil:
		c.Status, c.Detail = engine.CheckOK, path
	case errors.Is(err, fs.ErrNotExist):
		c.Status, c.Detail = engine.CheckOK, path+" (created on the first tool call, in "+filepath.Dir(path)+")"
	default:
		c.Status, c.Detail = engine.CheckFail, err.Error()
	}
	return c
}
