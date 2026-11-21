package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/SandstromPL/whyreach/internal/engine"
)

// RenderInspection writes an inspection for people, and as the MCP text
// summary of inspect_environment.
func RenderInspection(w io.Writer, in *engine.Inspection) {
	var b strings.Builder
	writeWrapped(&b, "", "  ", in.Summary)
	line := func(label string, items []string) {
		if len(items) > 0 {
			writeWrapped(&b, fmt.Sprintf("  %-12s", label), "              ", strings.Join(items, ", "))
		}
	}
	if h := in.Host; h != nil {
		if d := h.Docker; d != nil {
			line("docker", []string{fmt.Sprintf("%s %s, API %s, %s", d.Platform, d.Version, d.API, d.Endpoint)})
		}
		if p := h.Permissions; p != nil {
			line("permissions", []string{fmt.Sprintf("docker %v, probe containers %s, netns %s, root %v, %d probes/min, allow %s",
				p.Docker, p.ProbeContainers, p.Netns, p.Root, p.RatePerMinute, orAny(p.Allow))})
			if p.OutsideNames != "" {
				line("names", []string{"outside names (with a dot, unknown to Docker): " + p.OutsideNames})
			}
		}
		ifs := make([]string, 0, len(h.Interfaces))
		for _, i := range h.Interfaces {
			s := i.Name + " " + strings.Join(i.Addrs, " ")
			if i.Network != "" {
				s += " (network " + i.Network + ")"
			}
			if i.Down {
				s += " (down)"
			}
			ifs = append(ifs, s)
		}
		line("interfaces", ifs)
		line("listening", h.Listening)
		for i, c := range h.Containers {
			label := ""
			if i == 0 {
				label = "containers"
			}
			s := c.Name + " " + c.State
			if c.Service != "" {
				s += " [" + c.Service + "]"
			}
			if len(c.Networks) > 0 {
				s += " on " + strings.Join(c.Networks, ", ")
			}
			if len(c.Published) > 0 {
				s += " publishes " + strings.Join(c.Published, ", ")
			}
			writeWrapped(&b, fmt.Sprintf("  %-12s", label), "              ", s)
		}
		if h.Omitted > 0 {
			fmt.Fprintf(&b, "  (%d more left out)\n", h.Omitted)
		}
	}
	if c := in.Container; c != nil {
		line("container", []string{fmt.Sprintf("%s %s, image %s", c.Name, c.ID, c.Image)})
		if c.Service != "" {
			line("service", []string{c.Service})
		}
		line("mode", []string{c.NetworkMode})
		nets := make([]string, 0, len(c.Networks))
		for _, n := range c.Networks {
			s := n.Network
			if n.IPv4 != "" {
				s += " " + n.IPv4
			}
			if n.IPv6 != "" {
				s += " " + n.IPv6
			}
			if len(n.Names) > 0 {
				s += " (names " + strings.Join(n.Names, " ") + ")"
			}
			nets = append(nets, s)
		}
		line("networks", nets)
		line("listening", c.Listening)
		line("publishes", c.Published)
		line("extra_hosts", c.ExtraHosts)
		line("dns", c.DNS)
	}
	if n := in.Network; n != nil {
		line("network", []string{fmt.Sprintf("%s %s, driver %s, internal %v", n.Name, n.ID, n.Driver, n.Internal)})
		line("subnets", n.Subnets)
		line("gateways", n.Gateways)
		line("members", n.Members)
		if n.Omitted > 0 {
			fmt.Fprintf(&b, "  (%d more members left out)\n", n.Omitted)
		}
	}
	for _, g := range in.Gaps {
		writeWrapped(&b, "  could not check ", "    ", fmt.Sprintf("%s (%s): %s", g.What, g.Why, g.Detail))
	}
	_, _ = io.WriteString(w, Sanitize(b.String()))
}

func orAny(allow []string) string {
	if len(allow) == 0 {
		return "any address"
	}
	return strings.Join(allow, " ")
}

// RenderProbe writes run_probe's result for people, and as its MCP text
// summary.
func RenderProbe(w io.Writer, r ProbeResult) {
	var b strings.Builder
	for _, rec := range r.Results {
		writeWrapped(&b, "", "  ", fmt.Sprintf("[%s] %s", rec.ID, rec.Text))
	}
	if len(r.Results) == 0 {
		b.WriteString("no result\n")
	}
	if r.HowToEnable != "" {
		writeWrapped(&b, "  → ", "    ", r.HowToEnable)
	}
	effects := "none"
	if len(r.SideEffects) > 0 {
		effects = strings.Join(r.SideEffects, "; ")
	}
	writeWrapped(&b, "", "  ", "side effects: "+effects+" · changes made: none")
	_, _ = io.WriteString(w, Sanitize(b.String()))
}
