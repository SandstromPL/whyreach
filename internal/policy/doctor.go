package policy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/platform"
	"github.com/SandstromPL/whyreach/internal/probe"
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
	names := "no domain is listed under [probe] names"
	if len(p.d.Settings.Names) > 0 {
		names = "names under " + strings.Join(p.d.Settings.Names, ", ") + " need no approval ([probe] names)"
	}
	private := ""
	if p.rfc1918 {
		private = fmt.Sprintf(" A connect to a private address outside Docker's networks and this machine's own addresses needs the user's approval of that address and port (%d connects an approval), unless an address or CIDR in allow covers it.", ApprovalBudget)
	}
	out = append(out, engine.Check{Name: "probe policy", Status: engine.CheckInfo,
		Detail: fmt.Sprintf("TCP probes may go to %s; at most %d probes a minute; link-local and cloud-metadata addresses are always blocked, and as nameservers asked only when they are the host's own resolvers (DNS only). "+
			"For MCP clients, a name with a dot that Docker doesn't know is looked up only after the user approves it (%d lookups an approval); %s.%s", allow, p.d.Settings.RatePerMinute, ApprovalBudget, names, private)})

	var host []netip.Addr
	if p.d.HostResolvers != nil {
		host = p.d.HostResolvers()
	}
	out = append(out, dnsChecks("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf", host)...)
	pl := platform.Detect()
	out = append(out, p.netnsCheck(ctx, pl))
	if pl.InContainer {
		// The interfaces, host listeners and container listeners lines say
		// what it has: host-side checks are unsupported records without
		// --network host, never the container's own state.
		out = append(out, engine.Check{Name: "environment", Status: engine.CheckInfo,
			Detail: "whyreach runs inside a container: it sees the host's network only with --network host, and containers' listening sockets only with --pid host"})
	}
	// Under WSL2 the engine's platform line says what the host's side is.
	return append(out, p.auditCheck())
}

// netnsCheck says whether container checks enter the containers' network
// namespaces themselves (tier 3, the netns executor), and when they do,
// enters one running container's namespace once to show that it works. It
// sends nothing and writes nothing.
func (p *Policy) netnsCheck(ctx context.Context, pl platform.Info) engine.Check {
	c := engine.Check{Name: "netns executor", Status: engine.CheckInfo}
	_, why := pl.NetnsExecutor()
	switch {
	case p.d.Netns != nil:
		c.Detail = "on (root): where Docker Engine runs on this machine, DNS and TCP checks from containers enter their network namespaces directly, with no Docker write (a probe container stands in only if entering fails and they are allowed). Run whyreach as root for the CLI only; as an MCP server, prefer a regular user"
		if pl := p.engine.Platform(ctx); p.d.Docker != nil && !pl.EngineHere() {
			c.Status = engine.CheckWarn
			c.Detail += "; not used here (" + pl.Name + "): Docker Engine doesn't run on this machine, so Docker's PIDs aren't processes whyreach can enter, and probe containers run container checks instead"
			return c
		}
		p.tryNetns(ctx, &c)
	case p.d.Settings.NetnsOff && why == "":
		c.Detail = "off: netns = false under [permissions] in " + p.d.Settings.ConfigPath
	case why == "":
		c.Detail = "off: it needs the Docker API"
	default:
		c.Detail = "off: " + why + ". whyreach needs no root: without it, container checks use probe containers (tier 2b)"
	}
	return c
}

// tryNetns enters the first running container's namespace, as a diagnosis
// would, without sending a probe.
func (p *Policy) tryNetns(ctx context.Context, c *engine.Check) {
	n, ok := p.d.Netns.(*executor.Netns)
	if !ok || p.d.Docker == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := p.d.Docker.Negotiate(ctx); err != nil {
		return // the docker check reports it
	}
	list, err := p.d.Docker.ListContainers(ctx, false)
	if err != nil || len(list) == 0 {
		return
	}
	s := list[0]
	if err := n.Check(ctx, evidence.ContextRef{Kind: evidence.ContextContainer, Container: evidence.ShortID(s.ID), Name: s.Name()}); err != nil {
		c.Status = engine.CheckFail
		c.Detail = "on (root), but entering " + s.Name() + "'s network namespace failed: " + err.Error()
		c.Fix = "Set probe_containers = true under [permissions] in " + p.d.Settings.ConfigPath + " for whyreach to use a probe container when it can't enter, or set netns = false there, or run whyreach as a regular user."
		return
	}
	c.Status = engine.CheckOK
	c.Detail += "; entered " + s.Name() + "'s and read its /etc/resolv.conf (no probe sent)"
}

func (p *Policy) probeContainerCheck(ctx context.Context) engine.Check {
	c := engine.Check{Name: "probe containers"}
	pl := p.engine.Platform(ctx)
	if p.d.Netns != nil && !p.ProbeContainers() && pl.EngineHere() {
		c.Status = engine.CheckInfo
		c.Detail = "off (tier 2b), and not needed while whyreach runs as root on Docker Engine here: the netns executor runs container checks"
		return c
	}
	if !p.ProbeContainers() {
		c.Status = engine.CheckWarn
		c.Detail = "off (tier 2b): DNS and TCP checks from inside containers are skipped; metadata and listeners still settle most causes"
		if !pl.EngineHere() && pl.Name != platform.Other {
			c.Detail = "off (tier 2b): on Docker Desktop they are the only way into containers, so containers' listening sockets and DNS and TCP checks from inside them are all skipped; metadata alone settles few causes"
		}
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

// resolverCheck is doctor's line about a host resolver on the block list
// (INITIAL.md §10 Q13): whyreach asks it for DNS only, as one of the host's
// own resolvers, unless it can't see the host's resolver files (its image
// without --network host).
func resolverCheck(which, ns string, host []netip.Addr) engine.Check {
	if a, err := netip.ParseAddr(ns); err == nil && (probe.Limits{HostResolvers: host}).HostResolver(a) {
		return engine.Check{Name: "dns", Status: engine.CheckInfo, Detail: fmt.Sprintf(
			"%s, %s, is a link-local or cloud-metadata address, and one of the host's own resolvers: whyreach asks it for DNS only, and never connects to it otherwise (INITIAL.md §10 Q13). "+
				"A blocked nameserver that only a container's own resolv.conf names stays refused", which, ns)}
	}
	return engine.Check{Name: "dns", Status: engine.CheckWarn, Detail: fmt.Sprintf(
		"%s, %s, is a link-local or cloud-metadata address, and whyreach can't see the host's resolvers from here, so it doesn't ask it: no lookups through it (INITIAL.md §10 Q13)", which, ns),
		Fix: executor.HostHiddenAdvice + "."}
}

// dnsChecks are doctor's lines about the resolvers the host and Docker's
// default-bridge containers ask, when one is on the probe block list
// (INITIAL.md §10 Q13): hostResolv is the host's resolv.conf, systemdResolv
// systemd-resolved's upstream list, host the host's own resolvers.
func dnsChecks(hostResolv, systemdResolv string, host []netip.Addr) []engine.Check {
	if ns, blocked, err := probe.FirstNameserverBlocked(hostResolv); err == nil && blocked {
		return []engine.Check{resolverCheck("the first nameserver in "+hostResolv, ns, host)}
	}
	path := probe.DockerResolvConf(hostResolv, systemdResolv)
	if path == hostResolv {
		return nil
	}
	// systemd-resolved: the host asks its stub, and Docker gives
	// default-bridge containers the upstreams behind it instead.
	switch ns, blocked, err := probe.FirstNameserverBlocked(path); {
	case err != nil:
		// whyreach's image doesn't see that file unless it is mounted.
		return []engine.Check{{Name: "dns", Status: engine.CheckWarn,
			Detail: hostResolv + " lists only systemd-resolved's 127.0.0.53, so Docker gives containers on the default bridge the upstreams in " + path +
				", which whyreach can't read here: if the first of them is a link-local or cloud-metadata address (169.254.169.254 on some clouds), whyreach can't tell it is the host's own resolver, and makes no lookups through it from those containers (INITIAL.md §10 Q13)",
			Fix: "In whyreach's image, mount systemd-resolved's directory read-only: -v /run/systemd/resolve:/run/systemd/resolve:ro."}}
	case blocked:
		return []engine.Check{resolverCheck("the first nameserver Docker gives containers on the default bridge (from "+path+", since "+hostResolv+" lists only systemd-resolved's 127.0.0.53)", ns, host)}
	}
	return nil
}
