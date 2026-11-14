//go:build lab

package e2e

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/SandstromPL/whyreach/internal/report"
)

// TestLabPrivateAddresses checks INITIAL.md §10 Q15 on this machine's own
// interfaces, through the MCP server of the binary under test, with the
// default allowlist: a TCP probe to the host's LAN address needs no
// approval (E3: containers reach published ports that way), and one to a
// private address that is neither the host's nor on a Docker network is
// held back, with nothing sent, until the user approves it. The LAN address
// is found at run time and never written down.
func TestLabPrivateAddresses(t *testing.T) {
	lan, ok := lanAddress()
	if !ok {
		t.Skip("no private IPv4 address on this machine's interfaces")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", net.JoinHostPort(lan.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { // hold it open, as a server waiting for a request does
				time.Sleep(time.Second)
				_ = c.Close()
			}()
		}
	}()
	other, ok := strangerAddress(t, lan)
	if !ok {
		t.Skip("every candidate private address is this machine's or on a Docker network")
	}

	var asked atomic.Int32
	client := mcp.NewClient(&mcp.Implementation{Name: "lab", Version: "0"}, &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			asked.Add(1)
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
	})
	cmd := exec.CommandContext(ctx, l.bin, "mcp", "serve")
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+l.noProbe,
		"XDG_STATE_HOME="+filepath.Join(l.home, "state"), "XDG_DATA_HOME="+filepath.Join(l.home, "data"))
	if l.dockerHost != "" {
		cmd.Env = append(cmd.Env, "DOCKER_HOST="+l.dockerHost)
	}
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	probe := func(target string) report.ProbeResult {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "run_probe", Arguments: map[string]any{"kind": "tcp", "target": target}})
		if err != nil || res.IsError {
			t.Fatalf("run_probe %s: %v %+v", target, err, res)
		}
		var p report.ProbeResult
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	own := probe(net.JoinHostPort(lan.String(), strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)))
	if asked.Load() != 0 || len(own.Results) != 1 || !strings.Contains(own.Results[0].Text, "connected") {
		t.Errorf("the host's own LAN address: asked %d times, %+v", asked.Load(), own)
	}
	held := probe(net.JoinHostPort(other.String(), "9"))
	if asked.Load() != 1 || len(held.Results) != 1 || held.Results[0].Status != "skipped" || !strings.Contains(held.HowToEnable, "[probe]") {
		t.Errorf("a stranger's private address: asked %d times, %+v", asked.Load(), held)
	}
}

// lanAddress finds a private IPv4 address on one of this machine's own
// interfaces that isn't a Docker bridge's.
func lanAddress() (netip.Addr, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.Name == "docker0" || strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "veth") {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && p.Addr().IsPrivate() {
				return p.Addr(), true
			}
		}
	}
	return netip.Addr{}, false
}

// strangerAddress picks a private address that is neither one of this
// machine's own nor inside a Docker network: the policy's free addresses.
func strangerAddress(t *testing.T, lan netip.Addr) (netip.Addr, bool) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "docker", "network", "ls", "-q").Output()
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"network", "inspect", "-f", "{{range .IPAM.Config}}{{.Subnet}} {{end}}"}, strings.Fields(string(out))...)
	subnets, err := exec.CommandContext(context.Background(), "docker", args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	var docker []netip.Prefix
	for _, f := range strings.Fields(string(subnets)) {
		if p, err := netip.ParsePrefix(f); err == nil {
			docker = append(docker, p)
		}
	}
	for _, c := range []string{"192.168.255.254", "10.255.255.254", "172.31.255.254"} {
		a := netip.MustParseAddr(c)
		if a == lan || slices.ContainsFunc(docker, func(p netip.Prefix) bool { return p.Contains(a) }) {
			continue
		}
		return a, true
	}
	return netip.Addr{}, false
}
