package engine

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/target"
)

func inspectWorld() *world {
	api := ctr("a", "shop-api-1", "shop", "api", "shop_default", "172.22.0.3", 20)
	api.Ports = []evidence.PortMap{{ContainerPort: 8080, Proto: "tcp", HostIP: "127.0.0.1", HostPort: 18080}}
	worker := ctr("b", "shop-worker-1", "shop", "worker", "shop_default", "172.22.0.2", 10)
	return &world{
		containers: []evidence.Container{api, worker},
		sockets:    map[int][]string{20: {"0.0.0.0:8080", "127.0.0.11:41234"}},
		host:       []string{"127.0.0.1:5432", "0.0.0.0:22"},
	}
}

func TestInspect(t *testing.T) {
	w := inspectWorld()
	ifaces := func() (evidence.HostAddrs, error) {
		return evidence.HostAddrs{Interfaces: []evidence.Interface{
			{Name: "docker0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
			{Name: "br-shop_default", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("172.22.0.1/16")}},
		}}, nil
	}
	e := New(Deps{Docker: w, Listeners: w, Interfaces: ifaces})
	ctx := context.Background()

	in, err := e.Inspect(ctx, target.Scope{Kind: target.ScopeHost})
	if err != nil {
		t.Fatal(err)
	}
	h := in.Host
	if h == nil || h.Docker == nil || len(h.Containers) != 2 || len(h.Listening) != 2 || len(h.Interfaces) != 2 {
		t.Fatalf("host facts = %+v", h)
	}
	if !strings.Contains(in.Summary, "2 containers listed, 2 running") {
		t.Errorf("summary = %q", in.Summary)
	}

	in, err = e.Inspect(ctx, target.Scope{Kind: target.ScopeContainer, Name: "shop-api-1"})
	if err != nil {
		t.Fatal(err)
	}
	c := in.Container
	if c == nil || c.Service != "api@shop" || len(c.Listening) != 1 || c.Listening[0] != "0.0.0.0:8080" ||
		len(c.Published) != 1 || c.Published[0] != "127.0.0.1:18080->8080/tcp" {
		t.Errorf("container facts = %+v (Docker's DNS listener must be left out)", c)
	}
	if _, err := e.Inspect(ctx, target.Scope{Kind: target.ScopeService, Name: "worker", Project: "shop"}); err != nil {
		t.Errorf("by service: %v", err)
	}
	if _, err := e.Inspect(ctx, target.Scope{Kind: target.ScopeContainer, Name: "nope"}); !IsUsage(err) {
		t.Errorf("unknown container: %v", err)
	}

	in, err = e.Inspect(ctx, target.Scope{Kind: target.ScopeNetwork, Name: "shop_default"})
	if err != nil {
		t.Fatal(err)
	}
	if n := in.Network; n == nil || !n.DNS || len(n.Members) != 2 {
		t.Errorf("network facts = %+v", in.Network)
	}
	if _, err := e.Inspect(ctx, target.Scope{Kind: target.ScopeNetwork, Name: "nope"}); !IsUsage(err) {
		t.Errorf("unknown network: %v", err)
	}

	noDocker := New(Deps{Listeners: w})
	in, err = noDocker.Inspect(ctx, target.Scope{Kind: target.ScopeHost})
	if err != nil || in.Host.Docker != nil || len(in.Gaps) == 0 {
		t.Errorf("host without Docker: %+v, %v", in, err)
	}
	if _, err := noDocker.Inspect(ctx, target.Scope{Kind: target.ScopeContainer, Name: "api"}); err == nil {
		t.Error("a container scope needs Docker")
	}
}

func TestSingleProbe(t *testing.T) {
	w := inspectWorld()
	w.tcp = map[string]string{"172.22.0.3:8080": evidence.OutcomeConnected}
	w.dns = map[string][]string{"api": {"172.22.0.3"}}
	pc := &scripted{w: w, name: evidence.ExecutorProbeContainer}
	host := &scripted{w: w, name: evidence.ExecutorHost}
	e := New(Deps{Docker: w, Listeners: w, Host: host, Probe: pc})
	ctx := context.Background()
	worker, _ := target.ParseFrom("container:shop-worker-1")

	res, err := e.Probe(ctx, worker, probe.Spec{Kind: probe.SpecTCP, Host: "api", Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Evidence) != 2 || res.Evidence[0].ID != "ev-01" || res.Evidence[1].Context.Name != "worker" {
		t.Errorf("tcp from worker: %+v", res.Evidence)
	}
	if len(pc.ran) != 1 || pc.where[0].Name != "worker" {
		t.Errorf("the probe container must join worker: %+v", pc.where)
	}

	res, err = e.Probe(ctx, worker, probe.Spec{Kind: probe.SpecListeners})
	if err != nil {
		t.Fatal(err)
	}
	if len(pc.ran) != 1 || len(res.Evidence) != 1 || res.Evidence[0].Kind != evidence.KindListeners {
		t.Errorf("listeners are read from /proc, not through a probe container: %+v", res.Evidence)
	}

	hostFrom, _ := target.ParseFrom("host")
	if _, err := e.Probe(ctx, hostFrom, probe.Spec{Kind: probe.SpecDNS, Host: "api"}); err != nil || len(host.ran) != 1 {
		t.Errorf("dns from the host: %v, %d runs", err, len(host.ran))
	}

	off := New(Deps{Docker: w, Listeners: w, Host: host})
	res, err = off.Probe(ctx, worker, probe.Spec{Kind: probe.SpecDNS, Host: "api"})
	if err != nil || res.Evidence[0].Status != evidence.StatusPermissionDenied {
		t.Errorf("without a probe executor: %+v, %v", res, err)
	}
	nope, _ := target.ParseFrom("container:nope")
	if _, err := e.Probe(ctx, nope, probe.Spec{Kind: probe.SpecListeners}); !IsUsage(err) {
		t.Errorf("unknown source: %v", err)
	}
}
