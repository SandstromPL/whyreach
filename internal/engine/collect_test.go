package engine

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/evidence"
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
