//go:build lab

package e2e

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/test/bench"
)

// newBenchMasker collects the owner's private details from the machine
// (docs/research/agent-benchmark.md, "Privacy").
func newBenchMasker(t *testing.T) *bench.Masker {
	t.Helper()
	m := bench.NewMasker()
	if u, err := user.Current(); err == nil {
		m.Literal(u.HomeDir, "home")
		m.Literal(u.Username, "user")
		if name, _, _ := strings.Cut(u.Name, ","); name != "" {
			m.Literal(name, "name")
		}
	}
	if h, err := os.Hostname(); err == nil {
		m.Literal(h, "hostname")
	}
	for _, args := range [][]string{{"config", "--get", "user.email"}, {"config", "--global", "--get", "user.email"}} {
		if out, err := exec.CommandContext(context.Background(), "git", args...).Output(); err == nil {
			email := strings.TrimSpace(string(out))
			m.Literal(email, "email")
			if _, domain, ok := strings.Cut(email, "@"); ok {
				m.Literal(domain, "domain")
			}
		}
	}
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch fields[0] {
			case "nameserver":
				if a, err := netip.ParseAddr(fields[1]); err == nil {
					if a = a.Unmap(); a != netip.MustParseAddr("127.0.0.53") && a != netip.MustParseAddr("127.0.0.11") {
						m.DNSServer(a)
					}
				}
			case "search", "domain":
				for _, d := range fields[1:] {
					m.Literal(strings.TrimSuffix(d, "."), "search")
				}
			}
		}
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			if i.Name == "lo" || i.Name == "docker0" || strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "veth") {
				continue
			}
			m.Literal(i.Name, "if")
		}
	}
	// Docker resources outside the lab, their Compose projects (whyreach
	// names a container's service as service@project), and the daemon's ID.
	for _, args := range [][]string{
		{"ps", "-a", "--format", "{{.Names}}"},
		{"ps", "-a", "--format", `{{.Label "com.docker.compose.project"}}`},
		{"network", "ls", "--format", "{{.Name}}"},
		{"network", "ls", "--format", `{{.Label "com.docker.compose.project"}}`},
		{"volume", "ls", "--format", "{{.Name}}"},
		{"info", "--format", "{{.ID}}"},
	} {
		out, err := exec.CommandContext(context.Background(), "docker", args...).Output()
		if err != nil {
			continue
		}
		for _, name := range strings.Fields(string(out)) {
			if strings.HasPrefix(name, bench.LabPrefix) || name == "bridge" || name == "host" || name == "none" || len(name) < 6 {
				continue
			}
			m.Literal(name, "docker")
		}
	}
	for _, p := range networkSubnets(t, "bridge") {
		m.Keep(p)
	}
	return m
}

func networkSubnets(t *testing.T, network string) []netip.Prefix {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "docker", "network", "inspect", network, "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}").Output()
	if err != nil {
		return nil
	}
	var ps []netip.Prefix
	for _, f := range strings.Fields(string(out)) {
		if p, err := netip.ParsePrefix(f); err == nil {
			ps = append(ps, p)
		}
	}
	return ps
}
