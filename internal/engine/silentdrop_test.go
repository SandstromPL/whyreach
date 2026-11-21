package engine

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// dropWorld is the shop with worker's connects to api timing out.
func dropWorld() *world {
	w := shopWorld()
	delete(w.tcp, "172.22.0.3:8080") // missing means timeout
	return w
}

func suppressedBy(d *Diagnosis, id, by string) bool {
	return slices.ContainsFunc(d.Suppressed, func(s rules.Suppressed) bool { return s.RuleID == id && s.By == by })
}

func fired(d *Diagnosis, id string) bool {
	return slices.ContainsFunc(d.Findings, func(f rules.Finding) bool { return f.RuleID == id }) ||
		slices.ContainsFunc(d.Suppressed, func(s rules.Suppressed) bool { return s.RuleID == id })
}

// TestSilentDrop: WR016 end to end. A network that disables
// inter-container communication names the dropper (high); a destination
// that would have answered leaves an unnamed drop (medium), primary before
// a listener finding the timeout contradicts; on the host's side it stays
// WR016's when the host's own connect times out too, and is WR021's when
// the host answers it; an address outside Docker is a weak lead with the
// host's route.
// Every rule that explains a timeout suppresses it, and without a connect
// from the source (probe containers off) it isn't evaluated.
func TestSilentDrop(t *testing.T) {
	icc := dropWorld()
	icc.iccOff = map[string]bool{"shop_default": true}
	d := diagnoseWith(t, icc, "container:shop-worker-1", "api:8080", true)
	if p := d.Primary(); p == nil || p.RuleID != "WR016" || p.Confidence != rules.High || d.Verdict != VerdictCause ||
		!strings.Contains(p.Fix, "com.docker.network.bridge.enable_icc") || !strings.Contains(d.Summary, "disables inter-container communication") {
		t.Errorf("ICC disabled: verdict %s, primary %+v, summary %q", d.Verdict, p, d.Summary)
	}
	d = diagnoseWith(t, icc, "container:shop-worker-1", "api:8080", false)
	if fired(d, "WR016") || d.Verdict != VerdictInconclusive ||
		!slices.ContainsFunc(d.Gaps, func(g Gap) bool { return strings.Contains(g.HowToEnable, "probe_containers = true") }) {
		t.Errorf("without probe containers WR016 isn't evaluated: verdict %s, findings %+v, gaps %+v", d.Verdict, d.Findings, d.Gaps)
	}

	d = diagnoseWith(t, dropWorld(), "container:shop-worker-1", "api:8080", true)
	if p := d.Primary(); p == nil || p.RuleID != "WR016" || p.Confidence != rules.Medium || d.Verdict != VerdictLikelyCause {
		t.Errorf("unnamed drop: verdict %s, primary %+v", d.Verdict, p)
	}

	loopback := dropWorld()
	loopback.sockets[200] = []string{"127.0.0.1:8080", "127.0.0.11:40001"}
	d = diagnoseWith(t, loopback, "container:shop-worker-1", "api:8080", true)
	if p := d.Primary(); p == nil || p.RuleID != "WR016" || p.Confidence != rules.Medium ||
		!slices.ContainsFunc(d.Findings, func(f rules.Finding) bool { return f.RuleID == "WR002" && f.Confidence == rules.Medium }) {
		t.Errorf("loopback listener and a timeout: primary %+v, findings %+v", p, d.Findings)
	}

	hostSvc := dropWorld()
	hostSvc.containers[0].ExtraHosts = []string{"host.docker.internal:host-gateway"}
	hostSvc.dns["host.docker.internal"] = []string{"172.17.0.1"}
	hostSvc.host = []string{"0.0.0.0:5432"}
	d = diagnoseWith(t, hostSvc, "container:shop-worker-1", "host.docker.internal:5432", true)
	if p := d.Primary(); p == nil || p.RuleID != "WR016" || p.Confidence != rules.Medium || fired(d, "WR021") ||
		!strings.Contains(p.Explanation, "timed out as well") || !strings.Contains(p.Fix, "sudo nft list ruleset") {
		t.Errorf("the host's own connect times out too (WR021 stays out): verdict %s, primary %+v", d.Verdict, p)
	}
	hostSvc.hostTCP = map[string]string{"172.17.0.1:5432": evidence.OutcomeConnected}
	d = diagnoseWith(t, hostSvc, "container:shop-worker-1", "host.docker.internal:5432", true)
	if p := d.Primary(); p == nil || p.RuleID != "WR021" || !suppressedBy(d, "WR016", "WR021") || !strings.Contains(p.Fix, "sudo ufw allow from 172.22.0.0/16") {
		t.Errorf("the host answers its own connect: the host's firewall is WR021's: primary %+v, suppressed %+v", p, d.Suppressed)
	}

	// §2.3: the timeout by address to a container of another project is
	// WR004's consequence, and a stale address's is WR024's.
	separate := &world{
		containers: []evidence.Container{
			ctr("w", "b-worker-1", "b", "worker", "b_default", "172.31.0.2", 100),
			ctr("a", "a-api-1", "a", "api", "a_default", "172.30.0.2", 200),
		},
		sockets: map[int][]string{100: {"0.0.0.0:7000"}, 200: {"0.0.0.0:8080"}},
		dns:     map[string][]string{}, tcp: map[string]string{},
	}
	d = diagnoseWith(t, separate, "container:b-worker-1", "172.30.0.2:8080", true)
	if p := d.Primary(); p == nil || p.RuleID != "WR004" || !suppressedBy(d, "WR016", "WR004") {
		t.Errorf("another project by address: primary %+v, suppressed %+v", p, d.Suppressed)
	}
	d = diagnoseWith(t, separate, "container:b-worker-1", "api:8080", true)
	if fired(d, "WR016") {
		t.Errorf("another project by name: no connect through the name was made, so WR016 has no timeout: %+v %+v", d.Findings, d.Suppressed)
	}
	d = diagnoseWith(t, dropWorld(), "container:shop-worker-1", "172.22.0.200:8080", true)
	if p := d.Primary(); p == nil || p.RuleID != "WR024" || !suppressedBy(d, "WR016", "WR024") {
		t.Errorf("stale address: primary %+v, suppressed %+v", p, d.Suppressed)
	}
}

// TestOutsideLead: WR016's weak lead for an address outside Docker cites
// the host's route (TestRouteRecordsOutside has the record itself), and
// says so when only the default route covers a private address; on Docker
// Desktop it doesn't fire.
func TestOutsideLead(t *testing.T) {
	outside := func(desktop bool) *world {
		w := dropWorld()
		w.desktop = desktop
		dflt := evidence.Route{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Dev: "eth0"}
		w.routes = map[string]evidence.HostRoute{"10.8.20.5": {Chosen: &dflt, Covering: []evidence.Route{dflt}}}
		return w
	}
	for _, from := range []string{"host", "container:shop-worker-1"} {
		d := diagnoseWith(t, outside(false), from, "10.8.20.5:5432", true)
		recs := routeRecords(d)
		p := d.Primary()
		if len(recs) != 1 || p == nil || p.RuleID != "WR016" || p.Confidence != rules.Low || d.Verdict != VerdictInconclusive ||
			!slices.Contains(p.Supporting, recs[0].ID) || !strings.Contains(p.Explanation, "the route to it is missing") {
			t.Errorf("%s: verdict %s, primary %+v, route records %+v", from, d.Verdict, p, recs)
		}
	}
	if d := diagnoseWith(t, outside(true), "container:shop-worker-1", "10.8.20.5:5432", true); fired(d, "WR016") {
		t.Errorf("Docker Desktop: findings %+v", d.Findings)
	}
}
