package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
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

// TestInspectNamesBridges: the host's interfaces name the Docker network
// whose bridge each one is, by the bridge name Docker reports: docker0,
// br-<id>, or a name com.docker.network.bridge.name sets.
func TestInspectNamesBridges(t *testing.T) {
	w := inspectWorld()
	w.nets = []docker.Network{
		{ID: strings.Repeat("c", 64), Name: "lab_custom", Driver: "bridge", Bridge: "labbr0"},
		{ID: strings.Repeat("d", 64), Name: "lab_vlan", Driver: "macvlan"},
	}
	ifaces := func() (evidence.HostAddrs, error) {
		return evidence.HostAddrs{Interfaces: []evidence.Interface{
			{Name: "br-shop_default", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("172.22.0.1/16")}},
			{Name: "eth0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}},
			{Name: "labbr0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("172.30.0.1/16")}},
		}}, nil
	}
	in, err := New(Deps{Docker: w, Listeners: w, Interfaces: ifaces}).Inspect(context.Background(), target.Scope{Kind: target.ScopeHost})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, i := range in.Host.Interfaces {
		got[i.Name] = i.Network
	}
	want := map[string]string{"br-shop_default": "shop_default", "eth0": "", "labbr0": "lab_custom"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("interface → network (-want +got):\n%s", diff)
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

func TestSelfCheck(t *testing.T) {
	w := inspectWorld()
	e := New(Deps{Docker: w, Listeners: w, Interfaces: hostIfaces})
	got := map[string]string{}
	for _, c := range e.SelfCheck(context.Background()) {
		got[c.Name] = c.Status
	}
	want := map[string]string{"docker": CheckOK, "interfaces": CheckOK, "host listeners": CheckOK, "container listeners": CheckOK}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	off := New(Deps{DockerErr: errors.New("no socket"), Listeners: w})
	for _, c := range off.SelfCheck(context.Background()) {
		if c.Name == "docker" && (c.Status != CheckFail || c.Fix == "") {
			t.Errorf("an unreachable Docker is a failure with a fix: %+v", c)
		}
	}
}

// asksKnown stands in for the policy's guard and the probe: it asks the
// engine whether Docker knows a name, and holds the lookup back if not.
type asksKnown struct{}

func (asksKnown) Name() string { return evidence.ExecutorProbeContainer }

func (asksKnown) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	known := executor.KnownNamesFrom(ctx)
	var out []evidence.Evidence
	for _, s := range specs {
		ev := evidence.Evidence{Kind: evidence.KindDNS, Context: where, Subject: s.Host, Status: evidence.StatusOK, Data: evidence.DNSProbe{Name: s.Host}}
		if !known(ctx, s.Host) {
			ev.Status, ev.Err = evidence.StatusSkipped, &evidence.Error{Code: evidence.CodePolicyDenied, Message: probe.NameNotApproved}
		}
		out = append(out, ev)
	}
	return out, nil
}

// Past maxPeers containers on the source's networks, a name whyreach didn't
// find among the aliases it read may still be one: the held-back lookup
// says so (M4 re-check).
func TestBoundedNameSearchIsNoted(t *testing.T) {
	if !strings.Contains(NameSearchBounded, fmt.Sprintf(" %d)", maxPeers)) {
		t.Fatalf("NameSearchBounded doesn't name maxPeers (%d): %s", maxPeers, NameSearchBounded)
	}
	w := shopWorld()
	for i := range maxPeers + 6 {
		c := ctr(fmt.Sprintf("%02x", i+16), fmt.Sprintf("shop-svc%02d-1", i), "shop", fmt.Sprintf("svc%02d", i), "shop_default", fmt.Sprintf("172.22.1.%d", i+10), 1000+i)
		switch i {
		case 3:
			c.Networks[0].Names = append(c.Networks[0].Names, "near.internal")
		case maxPeers + 5:
			c.Networks[0].Names = append(c.Networks[0].Names, "far.internal")
		}
		w.containers = append(w.containers, c)
	}
	e := New(Deps{Docker: w, Listeners: w, Host: &scripted{w: w, name: evidence.ExecutorHost}, Probe: asksKnown{}})
	worker, _ := target.ParseFrom("container:shop-worker-1")
	for name, bounded := range map[string]bool{"near.internal": false, "far.internal": true, "nowhere.example": true} {
		res, err := e.Probe(context.Background(), worker, probe.Spec{Kind: probe.SpecDNS, Host: name})
		if err != nil {
			t.Fatal(err)
		}
		ev := res.Evidence[0]
		held := ev.Status == evidence.StatusSkipped
		noted := slices.Contains(ev.Limitations, NameSearchBounded)
		if held != bounded || noted != bounded {
			t.Errorf("%s: held back %v, noted %v; want both %v", name, held, noted, bounded)
		}
	}

	// A container whose inspect failed went unread too.
	w = shopWorld()
	api := w.containers[0]
	for i := range w.containers {
		if w.containers[i].Name == "shop-api-1" {
			w.containers[i].Networks[0].Names = append(w.containers[i].Networks[0].Names, "db.internal")
			api = w.containers[i]
		}
	}
	w.failInspect = map[string]error{api.Name: errors.New("inspect failed")}
	e = New(Deps{Docker: w, Listeners: w, Host: &scripted{w: w, name: evidence.ExecutorHost}, Probe: asksKnown{}})
	res, err := e.Probe(context.Background(), worker, probe.Spec{Kind: probe.SpecDNS, Host: "db.internal"})
	if err != nil {
		t.Fatal(err)
	}
	if ev := res.Evidence[0]; ev.Status != evidence.StatusSkipped || !slices.Contains(ev.Limitations, NameSearchBounded) {
		t.Errorf("an unread container's alias: %s, limitations %q", ev.Status, ev.Limitations)
	}
}
