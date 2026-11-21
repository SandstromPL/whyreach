package engine

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// exposers returns n running containers that expose port without
// publishing it, named app-svcNN-1 so that they sort before zz-web-1.
func exposers(n int, port uint16) []evidence.Container {
	var out []evidence.Container
	for i := range n {
		c := ctr(fmt.Sprintf("%02x", i), fmt.Sprintf("app-svc%02d-1", i), "app", fmt.Sprintf("svc%02d", i), "app_default", fmt.Sprintf("172.23.0.%d", 10+i), 1000+i)
		c.Ports = []evidence.PortMap{{ContainerPort: port, Proto: "tcp"}}
		out = append(out, c)
	}
	return out
}

// TestHostPortPublisherAmongManyExposers: whyreach inspects at most
// maxMatches containers that mention the target port. The one that
// publishes it on the host comes first, however its name sorts, and the
// containers left out are a gap and a record, not silence.
func TestHostPortPublisherAmongManyExposers(t *testing.T) {
	web := ctr("ff", "zz-web-1", "zz", "web", "zz_default", "172.24.0.2", 900)
	web.Ports = []evidence.PortMap{{ContainerPort: 80, Proto: "tcp", HostIP: "0.0.0.0", HostPort: 8080}}
	w := &world{
		containers: append(exposers(maxMatches+1, 8080), web),
		sockets:    map[int][]string{900: {"0.0.0.0:80"}},
		// userland-proxy false: no host process listens on the port
		tcp: map[string]string{"127.0.0.1:8080": evidence.OutcomeRefused, "[::1]:8080": evidence.OutcomeRefused},
	}
	d := diagnoseWith(t, w, "host", "localhost:8080", false)
	v := evidence.NewView(d.Question, d.Evidence)
	if p := v.Destinations().Published; len(p) != 1 || p[0].C.Name != "zz-web-1" {
		t.Errorf("published destinations = %+v, want zz-web-1", p)
	}
	if _, ok := v.ListenersIn(web.ID); !ok {
		t.Error("the publisher's listeners weren't read")
	}
	if !slices.ContainsFunc(d.Gaps, func(g Gap) bool {
		return g.Why == "skipped" && g.What == "2 more containers with port 8080 published or exposed"
	}) {
		t.Errorf("no gap for the containers left out: %+v", d.Gaps)
	}
	if !slices.ContainsFunc(d.Evidence, func(e evidence.Evidence) bool {
		return e.Kind == evidence.KindContainer && e.Status == evidence.StatusSkipped && e.Err != nil && e.Err.Code == evidence.CodeLimit
	}) {
		t.Error("no record of the containers left out")
	}
	for _, f := range d.Findings {
		if f.RuleID == "WR001" && strings.Contains(f.Title, "on the host") {
			t.Errorf("WR001 says nothing on the host listens, while zz-web-1 publishes the port: %+v", f)
		}
	}
}

// TestSearchBoundLowersWR001: from the host, when nothing answers a port,
// whyreach reads at most maxScan running containers' listeners to find one
// that serves it unpublished (WR019). The ones past the bound went unread,
// so "nothing on the host listens" (WR001) is only likely, as when probe
// containers' reads are cut.
func TestSearchBoundLowersWR001(t *testing.T) {
	w := &world{
		containers: exposers(maxScan+2, 7000), // none mentions port 9000
		sockets:    map[int][]string{},
		tcp:        map[string]string{"127.0.0.1:9000": evidence.OutcomeRefused, "[::1]:9000": evidence.OutcomeRefused},
	}
	d := diagnoseWith(t, w, "host", "localhost:9000", false)
	i := slices.IndexFunc(d.Findings, func(f rules.Finding) bool { return f.RuleID == "WR001" })
	if i < 0 || d.Findings[i].Confidence != rules.Medium {
		t.Errorf("findings %+v, want WR001 at medium confidence", d.Findings)
	}
	if !slices.ContainsFunc(d.Evidence, func(e evidence.Evidence) bool {
		return e.Kind == evidence.KindListeners && e.Context.Name == "2 running containers" && e.Err != nil && e.Err.Code == evidence.CodeLimit
	}) {
		t.Error("no record of the containers left unread")
	}
	if !slices.ContainsFunc(d.Gaps, func(g Gap) bool { return g.What == "the listeners of 2 more running containers" }) {
		t.Errorf("gaps %+v, want the bound's", d.Gaps)
	}
	// Within the bound, every container's listeners were read: settled.
	w.containers = w.containers[:maxScan]
	d = diagnoseWith(t, w, "host", "localhost:9000", false)
	if i := slices.IndexFunc(d.Findings, func(f rules.Finding) bool { return f.RuleID == "WR001" }); i < 0 || d.Findings[i].Confidence != rules.High {
		t.Errorf("within the bound: findings %+v, want WR001 at high confidence", d.Findings)
	}
}

// hostListenerRecords lists a diagnosis's records of the host's listeners.
func hostListenerRecords(d *Diagnosis) []evidence.Evidence {
	var out []evidence.Evidence
	for _, e := range d.Evidence {
		if e.Kind == evidence.KindListeners && e.Context.Kind == evidence.ContextHost {
			out = append(out, e)
		}
	}
	return out
}

// TestWindowsHostWithoutContainerList: on Docker Desktop's WSL integration,
// the host a container reaches through host.docker.internal is Windows.
// When Docker's container list can't be read, the host's side is collected
// after the probes without it, and the WSL2 VM's own sockets still aren't
// passed off as Windows'.
func TestWindowsHostWithoutContainerList(t *testing.T) {
	w := shopWorld()
	w.desktop = true
	w.failList = errors.New("the daemon timed out")
	w.host = []string{"127.0.0.1:5432"} // the WSL2 VM's own loopback listener
	r := diagnoseOn(t, w, wslRoot, true, "container:shop-worker-1", "host.docker.internal:5432")
	hostL := hostListenerRecords(r.d)
	if len(hostL) != 1 || hostL[0].Status != evidence.StatusUnsupported || hostL[0].Err == nil || hostL[0].Err.Message != executor.HostNotHere {
		t.Errorf("host listeners = %+v, want one unsupported record (%q)", hostL, executor.HostNotHere)
	}
}
