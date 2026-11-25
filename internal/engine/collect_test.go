package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/rules"
	"github.com/SandstromPL/whyreach/internal/target"
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

// countedReads is a listener reader that counts its reads.
type countedReads struct {
	*world
	mu              sync.Mutex
	host, container int
}

func (c *countedReads) Host() ([]evidence.Socket, error) {
	c.mu.Lock()
	c.host++
	c.mu.Unlock()
	return c.world.Host()
}

func (c *countedReads) Container(pid int, id string) ([]evidence.Socket, error) {
	c.mu.Lock()
	c.container++
	c.mu.Unlock()
	return c.world.Container(pid, id)
}

// TestListenerReadsAreNotWasted: each listening-socket read whyreach makes
// ends up in the answer. A container reaching the host reads the host's
// listeners once, and run_probe reads a host-network container's sockets
// as the host's, without reading them through its PID first.
func TestListenerReadsAreNotWasted(t *testing.T) {
	w := firewallWorld(evidence.OutcomeConnected, evidence.OutcomeConnected)
	reads := &countedReads{world: w}
	e := New(Deps{Docker: w, Listeners: reads, Interfaces: hostIfaces, Host: &scripted{w: w, name: evidence.ExecutorHost}})
	f, _ := target.ParseFrom("container:shop-worker-1")
	to, _ := target.ParseTo("host.docker.internal:5432")
	d, err := e.Diagnose(context.Background(), f, to)
	if err != nil {
		t.Fatal(err)
	}
	if reads.host != 1 || len(hostListenerRecords(d)) != 1 {
		t.Errorf("%d reads of the host's listeners for %d records, want 1", reads.host, len(hostListenerRecords(d)))
	}

	w = shopWorld()
	w.containers[1].NetworkMode, w.containers[1].Networks = "host", nil
	w.host = []string{"0.0.0.0:8080"}
	reads = &countedReads{world: w}
	e = New(Deps{Docker: w, Listeners: reads, Host: &scripted{w: w, name: evidence.ExecutorHost}})
	f, _ = target.ParseFrom("container:shop-api-1")
	res, err := e.Probe(context.Background(), f, probe.Spec{Kind: probe.SpecListeners})
	if err != nil {
		t.Fatal(err)
	}
	if reads.host != 1 || reads.container != 0 || len(res.Evidence) != 1 || !res.Evidence[0].OK() {
		t.Errorf("a host-network container's listeners: %d host reads, %d through its PID, evidence %+v; want 1, 0 and one record", reads.host, reads.container, res.Evidence)
	}
}

// failingReads is a probe executor whose listener reads in one container
// fail; it runs everything else as scripted does.
type failingReads struct {
	*scripted
	in string // the container's display name
}

func (f *failingReads) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	if where.Name == f.in && len(specs) == 1 && specs[0].Kind == probe.SpecListeners {
		where.Executor = f.name
		return []evidence.Evidence{{Kind: evidence.KindListeners, Subject: "listeners", Context: where, Status: evidence.StatusFailed,
			Err: &evidence.Error{Code: evidence.CodeInternal, Message: "the probe container exited 1"}}}, nil
	}
	return f.scripted.Run(ctx, where, specs)
}

// overlappingReads is a probe executor whose listener reads each wait, up
// to a second, until two of them are in flight at once.
type overlappingReads struct {
	*scripted
	mu             sync.Mutex
	inFlight, most int
}

func (o *overlappingReads) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	if len(specs) != 1 || specs[0].Kind != probe.SpecListeners {
		return o.scripted.Run(ctx, where, specs)
	}
	o.mu.Lock()
	o.inFlight++
	o.most = max(o.most, o.inFlight)
	o.mu.Unlock()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		o.mu.Lock()
		overlapped := o.most > 1
		o.mu.Unlock()
		if overlapped {
			break
		}
	}
	o.mu.Lock()
	o.inFlight--
	o.mu.Unlock()
	return o.scripted.Run(ctx, where, specs)
}

// TestUnpublishedServerSearchReadsInParallel: on Docker Desktop each read
// of the search is a probe container (0.5 to 1.5 s), so they overlap.
func TestUnpublishedServerSearchReadsInParallel(t *testing.T) {
	w := &world{containers: exposers(maxProbeListeners, 7000), sockets: map[int][]string{}, desktop: true}
	probes := &overlappingReads{scripted: &scripted{w: w, name: evidence.ExecutorProbeContainer}}
	f, _ := target.ParseFrom("host")
	to, _ := target.ParseTo("localhost:9000")
	if _, err := New(Deps{Docker: w, Listeners: w, Host: &scripted{w: w, name: evidence.ExecutorHost}, Probe: probes, Platform: wslRoot}).Diagnose(context.Background(), f, to); err != nil {
		t.Fatal(err)
	}
	if len(probes.where) != maxProbeListeners || probes.most < 2 {
		t.Errorf("%d listener reads, at most %d at once; want %d, overlapping", len(probes.where), probes.most, maxProbeListeners)
	}
}

// masked prints a diagnosis's records and gaps without their times.
func masked(d *Diagnosis) string {
	var b strings.Builder
	for _, e := range d.Evidence {
		fmt.Fprintf(&b, "%s %s [%s %s %s %d %s] %s %s", e.ID, e.Kind, e.Context.Kind, e.Context.Name, e.Context.Container, e.Context.NetnsID, e.Context.Executor, e.Subject, e.Status)
		if e.Err != nil {
			fmt.Fprintf(&b, " %s: %s", e.Err.Code, e.Err.Message)
		}
		fmt.Fprintf(&b, " %v %q", e.Limitations, e.Source)
		if l, ok := e.Data.(evidence.Listeners); ok {
			fmt.Fprintf(&b, " %v", l.Sockets)
		}
		b.WriteString("\n")
	}
	for _, g := range d.Gaps {
		fmt.Fprintf(&b, "gap %q %s %q %q %v\n", g.What, g.Why, g.Detail, g.HowToEnable, g.Evidence)
	}
	return b.String()
}

// TestUnpublishedServerSearchOnDesktop: on Docker Desktop each running
// container's listeners take a probe container, read in parallel. The
// search for the one that serves a port unpublished (WR019) takes its
// probe-container reads in name order first, so the records, which
// containers it cut and the gaps are the same every time: pinned here.
func TestUnpublishedServerSearchOnDesktop(t *testing.T) {
	w := &world{containers: exposers(9, 7000), sockets: map[int][]string{}, desktop: true}
	w.sockets[w.containers[2].Pid] = []string{"0.0.0.0:9000"}
	w.containers[3].NetworkMode, w.containers[3].Networks = "host", nil // its sockets are the host's
	w.tcp = map[string]string{"127.0.0.1:9000": evidence.OutcomeRefused, "[::1]:9000": evidence.OutcomeRefused}
	f, _ := target.ParseFrom("host")
	to, _ := target.ParseTo("localhost:9000")
	for range 3 {
		probes := &failingReads{scripted: &scripted{w: w, name: evidence.ExecutorProbeContainer}, in: "svc01"}
		d, err := New(Deps{Docker: w, Listeners: w, Host: &scripted{w: w, name: evidence.ExecutorHost}, Probe: probes, Platform: wslRoot}).Diagnose(context.Background(), f, to)
		if err != nil {
			t.Fatal(err)
		}
		if p := d.Primary(); p == nil || p.RuleID != "WR019" {
			t.Errorf("primary %+v, want WR019", p)
		}
		if got := masked(d); got != unpublishedSearchWant {
			t.Errorf("records and gaps (-want +got):\n%s", cmp.Diff(unpublishedSearchWant, got))
		}
		var read []string // besides svc01's, which failed
		for _, where := range probes.where {
			read = append(read, where.Name)
		}
		slices.Sort(read)
		if want := []string{"svc00", "svc02", "svc04", "svc05", "svc06"}; !slices.Equal(read, want) {
			t.Errorf("probe containers read the listeners in %v, want %v", read, want)
		}
	}
}

const unpublishedSearchWant = `ev-01 docker.version [host WSL2 VM  0 ] docker ok [] "docker GET /version"
ev-02 platform [host WSL2 VM  0 ] platform ok [] "whyreach's own environment (/proc/sys/kernel/osrelease, WSL's interop entry in /proc/sys/fs/binfmt_misc, container markers) and the daemon's GET /version"
ev-03 docker.container [container svc02 020202020202 0 ] container:app-svc02-1 ok [] "docker GET /containers/{id}/json"
ev-04 netns.listeners [host WSL2 VM  0 ] listeners ok [] "/proc/thread-self/net/tcp{,6} in whyreach's own network namespace" []
ev-05 netns.listeners [container 3 running containers  0 ] listeners failed internal: the probe container exited 1 [read to find a container that serves port 9000 without publishing it (svc01, svc07, svc08); one of these may] "/proc/net/tcp{,6} read inside a probe container joined to the container's network namespace"
ev-06 netns.listeners [container svc02 020202020202 0 probe-container] listeners ok [] "/proc/net/tcp{,6} read inside a probe container joined to the container's network namespace" [{tcp 0.0.0.0:9000 0}]
ev-07 probe.dns [host WSL2 VM  0 host] localhost ok [] ""
ev-08 probe.tcp [host WSL2 VM  0 host] localhost:9000 ok [] ""
ev-09 probe.tcp [host WSL2 VM  0 host] localhost:9000 ok [] ""
gap "listening sockets in svc07, svc08" skipped "where Docker's PIDs aren't this machine's (Docker Desktop), each container's listening sockets take a probe container, and whyreach reads at most 6 in one diagnosis" "" []
gap "listening sockets in 3 running containers" failed "the probe container exited 1" "" [ev-05]
`

// TestLoopbackPublisherInAnotherProject: a container's localhost:8443 is
// another Compose project's published port. whyreach inspects the
// container that publishes it, though it shares no network with the
// source, so WR007's fix names it and its own port, with the network to
// join, instead of host.docker.internal (so-78873209 in the real-case
// check, docs/research/real-cases.md).
func TestLoopbackPublisherInAnotherProject(t *testing.T) {
	app := ctr("aa", "spring-app-1", "spring", "app", "spring_default", "172.22.0.2", 100)
	server := ctr("bb", "authentik-server-1", "authentik", "server", "authentik_default", "172.23.0.2", 200)
	server.Ports = []evidence.PortMap{{ContainerPort: 9443, Proto: "tcp", HostIP: "0.0.0.0", HostPort: 8443}}
	w := &world{
		containers: []evidence.Container{app, server},
		sockets:    map[int][]string{100: {"0.0.0.0:8080"}, 200: {"0.0.0.0:9000", "0.0.0.0:9443"}},
		host:       []string{"0.0.0.0:8443"},
		tcp:        map[string]string{"127.0.0.1:8443": evidence.OutcomeRefused, "[::1]:8443": evidence.OutcomeRefused},
	}
	d := diagnoseWith(t, w, "container:spring-app-1", "localhost:8443", false)
	p := d.Primary()
	if p == nil || p.RuleID != "WR007" {
		t.Fatalf("primary = %+v, want WR007", p)
	}
	for _, want := range []string{"server:9443", "authentik_default"} {
		if !strings.Contains(p.Fix, want) {
			t.Errorf("fix %q lacks %q", p.Fix, want)
		}
	}
}
