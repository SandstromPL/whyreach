package engine

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/target"
)

func hostIfaces() (evidence.HostAddrs, error) {
	return evidence.HostAddrs{Interfaces: []evidence.Interface{
		{Name: "docker0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
		{Name: "eth0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}},
	}}, nil
}

func diagnoseWith(t *testing.T, w *world, from, to string, probes bool) *Diagnosis {
	t.Helper()
	f, err := target.ParseFrom(from)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := target.ParseTo(to)
	if err != nil {
		t.Fatal(err)
	}
	deps := Deps{Docker: w, Listeners: w, Interfaces: hostIfaces, Host: &scripted{w: w, name: evidence.ExecutorHost}}
	if probes {
		deps.Probe = &scripted{w: w, name: evidence.ExecutorProbeContainer}
	}
	d, err := New(deps).Diagnose(context.Background(), f, dst)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func recorded(d *Diagnosis) (containers, listeners []string) {
	for _, e := range d.Evidence {
		switch v := e.Data.(type) {
		case evidence.Container:
			containers = append(containers, v.Name)
		case evidence.Listeners:
			listeners = append(listeners, e.Context.String())
		}
	}
	return containers, listeners
}

func TestHostFlowCollection(t *testing.T) {
	web := ctr("e", "shop-web-1", "shop", "web", "shop_default", "172.22.0.4", 40)
	web.Ports = []evidence.PortMap{{ContainerPort: 8080, Proto: "tcp", HostIP: "0.0.0.0", HostPort: 18080}}
	quiet := ctr("q", "shop-quiet-1", "shop", "quiet", "shop_default", "172.22.0.5", 50)
	hidden := ctr("h", "shop-hidden-1", "shop", "hidden", "shop_default", "172.22.0.6", 60)
	worker := ctr("w", "shop-worker-1", "shop", "worker", "shop_default", "172.22.0.2", 10)
	worker.ExtraHosts = []string{"host.docker.internal:host-gateway"}
	w := &world{
		containers: []evidence.Container{web, quiet, hidden, worker},
		sockets:    map[int][]string{40: {"0.0.0.0:8080"}, 50: {"0.0.0.0:9000"}, 60: {"0.0.0.0:28080"}, 10: {"0.0.0.0:7000"}},
		host:       []string{"0.0.0.0:18080", "127.0.0.1:5432"},
		tcp:        map[string]string{"127.0.0.1:18080": evidence.OutcomeConnected, "127.0.0.1:28080": evidence.OutcomeRefused},
	}

	// Through a published port: the publisher is the destination, on its
	// container port.
	d := diagnoseWith(t, w, "host", "localhost:18080", false)
	cs, ls := recorded(d)
	if !slices.Contains(cs, "shop-web-1") || !slices.Contains(ls, "web") || !slices.Contains(ls, "host") {
		t.Errorf("published: containers %v, listeners %v", cs, ls)
	}
	v := evidence.NewView(d.Question, d.Evidence)
	if p := v.Destinations().Published; len(p) != 1 || p[0].Port != 8080 {
		t.Errorf("published destinations = %+v", p)
	}

	// Nothing on the host answers 28080: whyreach looks for the container
	// that listens on it without publishing it, and records only that one.
	d = diagnoseWith(t, w, "host", "localhost:28080", false)
	cs, ls = recorded(d)
	if !slices.Contains(cs, "shop-hidden-1") || slices.Contains(cs, "shop-quiet-1") || !slices.Contains(ls, "hidden") {
		t.Errorf("search: containers %v, listeners %v", cs, ls)
	}

	// From a container through host-gateway: the host's listeners and the
	// publisher, no search.
	d = diagnoseWith(t, w, "container:shop-worker-1", "host.docker.internal:5432", false)
	cs, ls = recorded(d)
	if !slices.Contains(ls, "host") || slices.Contains(cs, "shop-hidden-1") {
		t.Errorf("host-gateway: containers %v, listeners %v", cs, ls)
	}
	if v := evidence.NewView(d.Question, d.Evidence); v.Destinations().Host == nil {
		t.Error("host.docker.internal mapped to host-gateway is the host")
	}
	foundFact := false
	for _, f := range d.Facts {
		if f.Text == `"host.docker.internal" is the host for worker: extra_hosts map it to host-gateway, the host's 172.17.0.1 on docker0` {
			foundFact = true
		}
	}
	if !foundFact {
		t.Errorf("facts = %+v", d.Facts)
	}
}

func TestControlLookup(t *testing.T) {
	w := shopWorld()
	_, ex := runScenario(t, scenario{w: w, from: "container:shop-worker-1", to: "example.com:443", probes: true})
	if len(ex.ran) != 1 || len(ex.ran[0]) < 3 {
		t.Fatalf("specs = %+v", ex.ran)
	}
	last := ex.ran[0][len(ex.ran[0])-1]
	if last.Kind != "dns" || last.Host != "shop-worker-1" {
		t.Errorf("want a control lookup of the source's own name, got %+v", ex.ran[0])
	}
	// A name that matches a container needs no control.
	_, ex = runScenario(t, scenario{w: w, from: "container:shop-worker-1", to: "api:8080", probes: true})
	for _, s := range ex.ran[0] {
		if s.Kind == "dns" && s.Host == "shop-worker-1" {
			t.Error("no control lookup when the name matches a container")
		}
	}
}
