package engine

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/target"
)

// firewallWorld: worker reaches the host through host.docker.internal
// (host-gateway, docker0's 172.17.0.1), where the host's postgres listens on
// 0.0.0.0:5432. The tests set what worker's connect and the host's own get.
func firewallWorld(fromWorker, fromHost string) *world {
	w := shopWorld()
	w.containers[0].ExtraHosts = []string{"host.docker.internal:host-gateway"}
	w.dns["host.docker.internal"] = []string{"172.17.0.1"}
	w.host = []string{"0.0.0.0:5432"}
	w.tcp["172.17.0.1:5432"] = fromWorker
	w.hostTCP = map[string]string{"172.17.0.1:5432": fromHost}
	return w
}

// diagnoseControl is diagnoseWith that also returns the host executor, to
// see which connects whyreach made from the host.
func diagnoseControl(t *testing.T, w *world, from, to string, probes bool) (*Diagnosis, *scripted) {
	t.Helper()
	f, err := target.ParseFrom(from)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := target.ParseTo(to)
	if err != nil {
		t.Fatal(err)
	}
	host := &scripted{w: w, name: evidence.ExecutorHost}
	deps := Deps{Docker: w, Listeners: w, Interfaces: hostIfaces, Routes: w.route, Host: host}
	if probes {
		deps.Probe = &scripted{w: w, name: evidence.ExecutorProbeContainer}
	}
	d, err := New(deps).Diagnose(context.Background(), f, dst)
	if err != nil {
		t.Fatal(err)
	}
	return d, host
}

// controls lists the host's own connects for comparison that the host
// executor was asked for.
func controls(ex *scripted) []probe.Spec {
	var out []probe.Spec
	for _, batch := range ex.ran {
		for _, s := range batch {
			if s.Via == evidence.ViaControl {
				out = append(out, s)
			}
		}
	}
	return out
}

// TestHostControl: the host's own connect for comparison (WR021) is made
// only after a container's connect to one of the host's addresses was
// rejected, timed out, or was refused while a host listener takes the
// address; once per address, through the host executor, recorded in the
// host's context with the via that keeps it apart from the app's connects.
func TestHostControl(t *testing.T) {
	const from, to = "container:shop-worker-1", "host.docker.internal:5432"
	published := firewallWorld(evidence.OutcomeTimeout, evidence.OutcomeConnected)
	published.containers[1].Ports = []evidence.PortMap{{ContainerPort: 8080, Proto: "tcp", HostIP: "0.0.0.0", HostPort: 5432}}
	loopback := firewallWorld(evidence.OutcomeRefused, evidence.OutcomeRefused)
	loopback.host = []string{"127.0.0.1:5432"}
	desktop := firewallWorld(evidence.OutcomeUnreachable, evidence.OutcomeConnected)
	desktop.desktop = true
	for _, tt := range []struct {
		name     string
		w        *world
		from, to string
		probes   bool
		want     int
	}{
		{"rejected", firewallWorld(evidence.OutcomeUnreachable, evidence.OutcomeConnected), from, to, true, 1},
		{"timed out", firewallWorld(evidence.OutcomeTimeout, evidence.OutcomeConnected), from, to, true, 1},
		{"refused, a listener takes the address", firewallWorld(evidence.OutcomeRefused, evidence.OutcomeConnected), from, to, true, 1},
		{"refused, the listener is on loopback", loopback, from, to, true, 0},
		{"connected", firewallWorld(evidence.OutcomeConnected, evidence.OutcomeConnected), from, to, true, 0},
		{"a port a container publishes", published, from, to, true, 0},
		{"no connect from the source", firewallWorld(evidence.OutcomeUnreachable, evidence.OutcomeConnected), from, to, false, 0},
		{"Docker Desktop", desktop, from, to, true, 0},
		{"from the host", firewallWorld(evidence.OutcomeTimeout, evidence.OutcomeConnected), "host", "172.17.0.1:5432", true, 0},
	} {
		d, host := diagnoseControl(t, tt.w, tt.from, tt.to, tt.probes)
		cs := controls(host)
		if len(cs) != tt.want {
			t.Errorf("%s: the host's own connects %+v, want %d", tt.name, cs, tt.want)
			continue
		}
		if tt.want == 0 {
			continue
		}
		if cs[0].Host != "172.17.0.1" || cs[0].Port != 5432 {
			t.Errorf("%s: the host's own connect went to %s:%d", tt.name, cs[0].Host, cs[0].Port)
		}
		var rec *evidence.Evidence
		for i, e := range d.Evidence {
			if tp, ok := e.Data.(evidence.TCPProbe); ok && tp.Via == evidence.ViaControl {
				rec = &d.Evidence[i]
			}
		}
		if rec == nil || rec.Context.Kind != evidence.ContextHost || rec.Context.Executor != evidence.ExecutorHost {
			t.Errorf("%s: the record isn't in the host's context: %+v", tt.name, rec)
		}
		if !slices.ContainsFunc(d.Facts, func(f Fact) bool { return strings.Contains(f.Text, "whyreach's own connect, for comparison") }) {
			t.Errorf("%s: no fact for the host's own connect: %+v", tt.name, d.Facts)
		}
	}
}
