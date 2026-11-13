package engine

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/rules"
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

// TestNewRulesEndToEnd runs the collect → probe → evaluate pipeline for the
// M2 rules on fake Docker hosts, with and without probe containers.
func TestNewRulesEndToEnd(t *testing.T) {
	type tc struct {
		name, from, to string
		w              func() *world
		top            string // with probes; "" means no finding
		noProbeTop     string
		verdict        string
	}
	shop := func(mut func(*world)) func() *world {
		return func() *world {
			w := shopWorld()
			mut(w)
			return w
		}
	}
	tests := []tc{
		{name: "WR019 not published", from: "host", to: "localhost:28080", top: "WR019", noProbeTop: "WR019", verdict: VerdictCause,
			w: shop(func(w *world) {
				w.sockets[200] = []string{"0.0.0.0:28080"}
				w.tcp["127.0.0.1:28080"] = evidence.OutcomeRefused
			})},
		{name: "WR012 host loopback", from: "container:shop-worker-1", to: "host.docker.internal:5432", top: "WR012", noProbeTop: "WR012", verdict: VerdictCause,
			w: shop(func(w *world) {
				w.containers[0].ExtraHosts = []string{"host.docker.internal:host-gateway"}
				w.host = []string{"127.0.0.1:5432"}
				w.dns["host.docker.internal"] = []string{"172.17.0.1"}
				w.tcp["172.17.0.1:5432"] = evidence.OutcomeRefused
			})},
		{name: "WR011 no mapping", from: "container:shop-worker-1", to: "host.docker.internal:5432", top: "WR011", noProbeTop: "WR011", verdict: VerdictCause,
			w: shop(func(*world) {})},
		{name: "WR005 typo", from: "container:shop-worker-1", to: "apii:8080", top: "WR005", noProbeTop: "WR005", verdict: VerdictCause,
			w: shop(func(w *world) { w.dns["shop-worker-1"] = []string{"172.22.0.2"} })},
		{name: "WR003 other port", from: "container:shop-worker-1", to: "api:8080", top: "WR003", noProbeTop: "WR003", verdict: VerdictCause,
			w: shop(func(w *world) {
				w.sockets[200] = []string{"0.0.0.0:8000"}
				w.tcp["172.22.0.3:8080"] = evidence.OutcomeRefused
			})},
		{name: "WR001 nothing listening", from: "container:shop-worker-1", to: "api:8080", top: "WR001", noProbeTop: "WR001", verdict: VerdictCause,
			w: shop(func(w *world) {
				w.sockets[200] = []string{"127.0.0.1:9000"}
				w.tcp["172.22.0.3:8080"] = evidence.OutcomeRefused
			})},
	}
	for _, tt := range tests {
		for _, probes := range []bool{true, false} {
			name := tt.name + map[bool]string{true: "/probe-containers", false: "/default-config"}[probes]
			t.Run(name, func(t *testing.T) {
				d := diagnoseWith(t, tt.w(), tt.from, tt.to, probes)
				want := tt.noProbeTop
				if probes {
					want = tt.top
				}
				got := ""
				if p := d.Primary(); p != nil {
					got = p.RuleID
				}
				if got != want || (probes && d.Verdict != tt.verdict) {
					t.Errorf("primary %q verdict %s, want %q %s\nfindings %+v\ngaps %+v", got, d.Verdict, want, tt.verdict, d.Findings, d.Gaps)
				}
			})
		}
	}
}

// TestSkippedPeersLowerWR005: past maxPeers containers on the source's
// networks, the uninspected ones might answer to the name through an alias,
// so WR005 can't claim that none does with its usual confidence (M2 review).
func TestSkippedPeersLowerWR005(t *testing.T) {
	w := shopWorld()
	for i := range maxPeers + 6 {
		c := ctr(fmt.Sprintf("%02x", i+16), fmt.Sprintf("shop-svc%02d-1", i), "shop", fmt.Sprintf("svc%02d", i), "shop_default", fmt.Sprintf("172.22.1.%d", i+10), 1000+i)
		if i == maxPeers+5 {
			c.Networks[0].Names = append(c.Networks[0].Names, "dbx")
		}
		w.containers = append(w.containers, c)
	}
	d := diagnoseWith(t, w, "container:shop-worker-1", "dbx:5432", false)
	p := d.Primary()
	if p == nil || p.RuleID != "WR005" || p.Confidence != rules.Low {
		t.Fatalf("primary = %+v, want WR005 at low confidence", p)
	}
	if !slices.ContainsFunc(d.Gaps, func(g Gap) bool { return strings.HasPrefix(g.What, "aliases of ") && g.Why == "skipped" }) {
		t.Errorf("no gap for the skipped containers: %+v", d.Gaps)
	}
}

// TestInternalNetworkIsNotUpstreamDNS: on internal: true networks Docker's
// DNS answers SERVFAIL for external names at once; that is the network's
// isolation, not a failing upstream (WR020; M2 review).
func TestInternalNetworkIsNotUpstreamDNS(t *testing.T) {
	for _, internal := range []bool{false, true} {
		w := shopWorld()
		w.dns["shop-worker-1"] = []string{"172.22.0.2"}
		if internal {
			w.internal = map[string]bool{"shop_default": true}
		}
		d := diagnoseWith(t, w, "container:shop-worker-1", "example.com:443", true)
		got := ""
		if p := d.Primary(); p != nil {
			got = p.RuleID
		}
		want := "WR020"
		if internal {
			want = ""
		}
		if got != want {
			t.Errorf("internal=%v: primary %q, want %q: %+v", internal, got, want, d.Findings)
		}
		for _, e := range d.Evidence {
			if c, ok := e.Data.(evidence.Container); ok && c.Name == "shop-worker-1" {
				if a, _ := c.Attachment("shop_default"); a.Internal != internal {
					t.Errorf("internal=%v: the source's attachment says internal=%v", internal, a.Internal)
				}
			}
		}
	}
}
