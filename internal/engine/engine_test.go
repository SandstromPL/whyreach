package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/rules"
	"github.com/SandstromPL/whyreach/internal/target"
)

// world is a fake Docker host: containers, their sockets, and what probes
// from inside them observe.
type world struct {
	containers  []evidence.Container
	sockets     map[int][]string // pid → listening addresses
	host        []string         // the host's listening addresses
	dns         map[string][]string
	tcp         map[string]string // "addr:port" → outcome; missing means timeout
	desktop     bool
	failInspect map[string]error // container name → inspect error
	internal    map[string]bool  // network name → internal: true
}

func (w *world) Negotiate(context.Context) (docker.Version, error) {
	v := docker.Version{Version: "29.9.3", APIVersion: "1.56", Os: "linux", Arch: "amd64"}
	v.Platform.Name = "Docker Engine - Community"
	if w.desktop {
		v.Platform.Name = "Docker Desktop 4.50.0"
	}
	return v, nil
}

func (w *world) Endpoint() string   { return "unix:///var/run/docker.sock" }
func (w *world) APIVersion() string { return "1.56" }

func (w *world) ListContainers(_ context.Context, _ bool, labels ...string) ([]docker.Summary, error) {
	var out []docker.Summary
	for _, c := range w.containers {
		s := docker.Summary{ID: c.ID, Names: []string{"/" + c.Name}, State: c.State, Labels: map[string]string{}}
		if c.Compose != nil {
			s.Labels[docker.LabelComposeProject] = c.Compose.Project
			s.Labels[docker.LabelComposeService] = c.Compose.Service
		}
		s.NetworkSettings.Networks = map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		}{}
		for _, pm := range c.Ports {
			s.Ports = append(s.Ports, docker.SummaryPort{IP: pm.HostIP, PrivatePort: pm.ContainerPort, PublicPort: pm.HostPort, Type: pm.Proto})
		}
		for _, a := range c.Networks {
			ip := ""
			if a.IPv4.IsValid() {
				ip = a.IPv4.String()
			}
			s.NetworkSettings.Networks[a.Network] = struct {
				IPAddress         string `json:"IPAddress"`
				GlobalIPv6Address string `json:"GlobalIPv6Address"`
			}{IPAddress: ip}
		}
		match := true
		for _, l := range labels {
			k, v, _ := strings.Cut(l, "=")
			if s.Labels[k] != v {
				match = false
			}
		}
		if match {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b docker.Summary) int { return strings.Compare(a.Name(), b.Name()) })
	return out, nil
}

func (w *world) InspectContainer(_ context.Context, ref string) (evidence.Container, error) {
	for _, c := range w.containers {
		if c.ID == ref || c.Name == ref || evidence.ShortID(c.ID) == ref {
			if err := w.failInspect[c.Name]; err != nil {
				return evidence.Container{}, err
			}
			return c, nil
		}
	}
	return evidence.Container{}, &docker.APIError{Status: 404, Message: "No such container: " + ref}
}

// ListNetworks derives the networks from the containers' attachments.
func (w *world) ListNetworks(context.Context) ([]docker.Network, error) {
	seen := map[string]bool{}
	var out []docker.Network
	for _, c := range w.containers {
		for _, a := range c.Networks {
			if seen[a.Network] {
				continue
			}
			seen[a.Network] = true
			n := docker.Network{ID: a.Network + "-id", Name: a.Network, Driver: "bridge", Internal: w.internal[a.Network]}
			if a.IPv4.IsValid() {
				n.Subnets = []netip.Prefix{netip.PrefixFrom(a.IPv4, 16).Masked()}
			}
			out = append(out, n)
		}
	}
	slices.SortFunc(out, func(a, b docker.Network) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (w *world) InspectNetwork(ctx context.Context, ref string) (docker.Network, error) {
	nets, _ := w.ListNetworks(ctx)
	for _, n := range nets {
		if n.Name != ref && n.ID != ref {
			continue
		}
		for _, c := range w.containers {
			if a, ok := c.Attachment(n.Name); ok {
				n.Members = append(n.Members, docker.NetworkMember{ID: c.ID, Name: c.Name, IPv4: a.IPv4})
			}
		}
		return n, nil
	}
	return docker.Network{}, &docker.APIError{Status: 404, Message: "network " + ref + " not found"}
}

func (w *world) Host() ([]evidence.Socket, error) { return socks(w.host), nil }

func (w *world) Container(pid int, id string) ([]evidence.Socket, error) {
	for _, c := range w.containers {
		if c.ID == id && c.Pid == pid {
			return socks(w.sockets[pid]), nil
		}
	}
	return nil, probe.ErrNotContainer
}

func socks(addrs []string) []evidence.Socket {
	var out []evidence.Socket
	for _, a := range addrs {
		ap := netip.MustParseAddrPort(a)
		proto := "tcp"
		if ap.Addr().Is6() {
			proto = "tcp6"
		}
		out = append(out, evidence.Socket{Proto: proto, Local: ap})
	}
	return out
}

// scripted is a fake executor that answers probes from the world.
type scripted struct {
	w      *world
	name   string
	block  bool
	mu     sync.Mutex
	ran    [][]probe.Spec
	where  []evidence.ContextRef
	effect []string
}

func (s *scripted) Name() string { return s.name }

func (s *scripted) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	s.mu.Lock()
	s.ran = append(s.ran, specs)
	s.where = append(s.where, where)
	s.mu.Unlock()
	for _, e := range s.effect {
		executor.RecordSideEffect(ctx, e)
	}
	if s.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var out []evidence.Evidence
	lookup := func(name string) evidence.DNSProbe {
		p := evidence.DNSProbe{Name: name, Server: "127.0.0.11:53", Rcode: "SERVFAIL"}
		if name == "localhost" {
			return evidence.DNSProbe{Name: name, Via: evidence.ViaHosts, Answers: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}}
		}
		if as, ok := s.w.dns[name]; ok {
			p.Rcode, p.Via = "NOERROR", evidence.ViaDNS
			for _, a := range as {
				p.Answers = append(p.Answers, netip.MustParseAddr(a))
			}
		}
		return p
	}
	dial := func(subject string, ap netip.AddrPort, via string) evidence.Evidence {
		outcome, ok := s.w.tcp[ap.String()]
		if !ok {
			outcome = evidence.OutcomeTimeout
		}
		return evidence.Evidence{Kind: evidence.KindTCP, Subject: subject, Status: evidence.StatusOK,
			Context: evidence.ContextRef{Executor: s.name},
			Data:    evidence.TCPProbe{Target: subject, Addr: ap, Via: via, Outcome: outcome}}
	}
	looked := map[string]bool{}
	for _, sp := range specs {
		switch sp.Kind {
		case probe.SpecDNS:
			looked[sp.Host] = true
			out = append(out, evidence.Evidence{Kind: evidence.KindDNS, Subject: sp.Host, Status: evidence.StatusOK, Context: evidence.ContextRef{Executor: s.name}, Data: lookup(sp.Host)})
		case probe.SpecTCP:
			subject := fmt.Sprintf("%s:%d", sp.Host, sp.Port)
			if a, err := netip.ParseAddr(sp.Host); err == nil {
				via := evidence.ViaLiteral
				if sp.Via != "" {
					via = sp.Via
				}
				out = append(out, dial(subject, netip.AddrPortFrom(a, sp.Port), via))
				continue
			}
			p := lookup(sp.Host)
			if !looked[sp.Host] {
				looked[sp.Host] = true
				out = append(out, evidence.Evidence{Kind: evidence.KindDNS, Subject: sp.Host, Status: evidence.StatusOK, Context: evidence.ContextRef{Executor: s.name}, Data: p})
			}
			for _, a := range p.Answers {
				out = append(out, dial(subject, netip.AddrPortFrom(a, sp.Port), p.Via))
			}
		}
	}
	return out, nil
}

func ctr(id, name, project, service, net, ip string, pid int) evidence.Container {
	c := evidence.Container{
		ID: strings.Repeat(id, 64/len(id)), Name: name, State: evidence.StateRunning, Pid: pid,
		StartedAt: time.Now().Add(-time.Hour), NetworkMode: net,
		Compose: &evidence.ComposeRef{Project: project, Service: service},
		Networks: []evidence.NetAttachment{{
			Network: net, IPv4: netip.MustParseAddr(ip), Names: []string{name, service},
		}},
	}
	return c
}

type scenario struct {
	name       string
	w          *world
	from, to   string
	probes     bool
	verdict    string
	top        string
	confidence string
	mustNot    []string
	check      func(t *testing.T, d *Diagnosis, ex *scripted)
}

func runScenario(t *testing.T, s scenario) (*Diagnosis, *scripted) {
	t.Helper()
	from, err := target.ParseFrom(s.from)
	if err != nil {
		t.Fatal(err)
	}
	to, err := target.ParseTo(s.to)
	if err != nil {
		t.Fatal(err)
	}
	ex := &scripted{w: s.w, name: evidence.ExecutorProbeContainer, effect: []string{"ephemeral probe container wr-probe-test (removed)"}}
	deps := Deps{Docker: s.w, Listeners: s.w, Host: &scripted{w: s.w, name: evidence.ExecutorHost}, ConfigPath: "/home/u/.config/whyreach/config.toml"}
	if s.probes {
		deps.Probe = ex
	}
	d, err := New(deps).Diagnose(context.Background(), from, to)
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	return d, ex
}

func shopWorld() *world {
	return &world{
		containers: []evidence.Container{
			ctr("w", "shop-worker-1", "shop", "worker", "shop_default", "172.22.0.2", 100),
			ctr("a", "shop-api-1", "shop", "api", "shop_default", "172.22.0.3", 200),
		},
		sockets: map[int][]string{100: {"0.0.0.0:7000", "127.0.0.11:40000"}, 200: {"0.0.0.0:8080", "127.0.0.11:40001"}},
		dns:     map[string][]string{"api": {"172.22.0.3"}},
		tcp:     map[string]string{"172.22.0.3:8080": evidence.OutcomeConnected, "127.0.0.1:8080": evidence.OutcomeRefused, "[::1]:8080": evidence.OutcomeRefused},
	}
}

func TestSliceScenarios(t *testing.T) {
	loopback := shopWorld()
	loopback.sockets[200] = []string{"127.0.0.1:8080", "127.0.0.11:40001"}
	loopback.tcp["172.22.0.3:8080"] = evidence.OutcomeRefused

	separate := &world{
		containers: []evidence.Container{
			ctr("w", "b-worker-1", "b", "worker", "b_default", "172.31.0.2", 100),
			ctr("a", "a-api-1", "a", "api", "a_default", "172.30.0.2", 200),
		},
		sockets: map[int][]string{100: {"0.0.0.0:7000"}, 200: {"0.0.0.0:8080"}},
		dns:     map[string][]string{},
		tcp:     map[string]string{},
	}

	stopped := shopWorld()
	stopped.containers[1].State, stopped.containers[1].Pid, stopped.containers[1].ExitCode = evidence.StateExited, 0, 1
	stopped.containers[1].Networks[0].IPv4 = netip.Addr{}

	tests := []scenario{
		{
			name: "healthy", w: shopWorld(), from: "container:shop-worker-1", to: "api:8080", probes: true,
			verdict: VerdictNoProblem,
		},
		{
			name: "healthy without probe containers", w: shopWorld(), from: "container:shop-worker-1", to: "api:8080",
			verdict: VerdictInconclusive,
			check: func(t *testing.T, d *Diagnosis, _ *scripted) {
				if len(d.Gaps) != 1 || d.Gaps[0].Why != "permission" || !strings.Contains(d.Gaps[0].HowToEnable, "probe_containers = true") {
					t.Errorf("want one tier-2b gap, got %+v", d.Gaps)
				}
			},
		},
		{
			name: "WR007 localhost", w: shopWorld(), from: "service:worker@shop", to: "localhost:8080", probes: true,
			verdict: VerdictCause, top: "WR007", confidence: "high", mustNot: []string{"WR002", "WR004"},
			check: func(t *testing.T, d *Diagnosis, _ *scripted) {
				if !strings.Contains(d.Findings[0].Fix, "api:8080") {
					t.Errorf("fix = %q, want api:8080", d.Findings[0].Fix)
				}
			},
		},
		{
			name: "WR007 without probe containers", w: shopWorld(), from: "container:shop-worker-1", to: "localhost:8080",
			verdict: VerdictCause, top: "WR007", confidence: "high",
		},
		{
			name: "WR004 separate projects", w: separate, from: "container:b-worker-1", to: "api:8080", probes: true,
			verdict: VerdictCause, top: "WR004", confidence: "high", mustNot: []string{"WR016", "WR005", "WR002"},
			check: func(t *testing.T, d *Diagnosis, ex *scripted) {
				var metadata bool
				for _, sp := range ex.ran[0] {
					metadata = metadata || (sp.Via == evidence.ViaMetadata && sp.Host == "172.30.0.2")
				}
				if !metadata {
					t.Errorf("want a connect to api's metadata address, specs %+v", ex.ran[0])
				}
				if len(d.Findings[0].Supporting) < 4 {
					t.Errorf("WR004 should cite the containers, the DNS failure and the timeout: %v", d.Findings[0].Supporting)
				}
			},
		},
		{
			name: "WR004 without probe containers", w: separate, from: "container:b-worker-1", to: "api:8080",
			verdict: VerdictCause, top: "WR004", confidence: "high",
		},
		{
			name: "WR002 loopback bind", w: loopback, from: "container:shop-worker-1", to: "api:8080", probes: true,
			verdict: VerdictCause, top: "WR002", confidence: "high", mustNot: []string{"WR004", "WR005"},
		},
		{
			name: "WR008 destination exited", w: stopped, from: "container:shop-worker-1", to: "api:8080", probes: true,
			verdict: VerdictCause, top: "WR008", confidence: "high",
			check: func(t *testing.T, d *Diagnosis, ex *scripted) {
				if len(ex.ran) != 0 {
					t.Errorf("no probe may run towards a stopped destination, ran %v", ex.ran)
				}
				for _, g := range d.Gaps {
					t.Errorf("a stopped destination explains the skipped probes; unexpected gap %+v", g)
				}
			},
		},
	}
	for _, s := range tests {
		t.Run(s.name, func(t *testing.T) {
			d, ex := runScenario(t, s)
			if d.Verdict != s.verdict {
				t.Fatalf("verdict = %s, want %s\nsummary: %s\nfindings: %+v\ngaps: %+v", d.Verdict, s.verdict, d.Summary, d.Findings, d.Gaps)
			}
			if s.top != "" {
				p := d.Primary()
				if p == nil || p.RuleID != s.top || string(p.Confidence) != s.confidence {
					t.Fatalf("primary = %+v, want %s (%s)", p, s.top, s.confidence)
				}
			}
			for _, f := range append(slices.Clone(d.Findings), suppressedFindings(d)...) {
				if slices.Contains(s.mustNot, f.RuleID) {
					t.Errorf("%s must not fire: %+v", f.RuleID, f)
				}
			}
			if d.ChangesMade || d.Summary == "" || len(d.NextChecks) == 0 || d.ID == "" {
				t.Errorf("incomplete diagnosis: %+v", d)
			}
			for _, f := range d.Facts {
				for _, id := range f.Evidence {
					if !slices.ContainsFunc(d.Evidence, func(e evidence.Evidence) bool { return e.ID == id }) {
						t.Errorf("fact %q cites unknown evidence %s", f.Text, id)
					}
				}
			}
			if s.check != nil {
				s.check(t, d, ex)
			}
		})
	}
}

func suppressedFindings(d *Diagnosis) []rules.Finding {
	var out []rules.Finding
	for _, s := range d.Suppressed {
		out = append(out, s.Finding)
	}
	return out
}

func TestProbesRunInTheSourceContext(t *testing.T) {
	d, ex := runScenario(t, scenario{w: shopWorld(), from: "container:shop-worker-1", to: "api:8080", probes: true})
	if len(ex.where) != 1 || ex.where[0].Container != evidence.ShortID(strings.Repeat("w", 64)) {
		t.Fatalf("probe ran in %+v, want worker", ex.where)
	}
	for _, e := range d.Evidence {
		if e.Kind == evidence.KindTCP && (e.Context.Name != "worker" || e.Context.Executor != evidence.ExecutorProbeContainer) {
			t.Errorf("TCP evidence context = %+v", e.Context)
		}
	}
	if !slices.Contains(d.SideEffects, "ephemeral probe container wr-probe-test (removed)") {
		t.Errorf("side effects = %v", d.SideEffects)
	}
}

func TestFindingsAreDeterministic(t *testing.T) {
	var prev []byte
	for i := range 5 {
		d, _ := runScenario(t, scenario{w: func() *world {
			w := shopWorld()
			w.sockets[200] = []string{"127.0.0.1:8080"}
			w.tcp["172.22.0.3:8080"] = evidence.OutcomeRefused
			return w
		}(), from: "container:shop-worker-1", to: "api:8080", probes: true})
		b, err := json.Marshal(struct {
			V string
			F any
			X any
			G any
		}{d.Verdict, d.Findings, d.Facts, d.Gaps})
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && string(b) != string(prev) {
			t.Fatalf("run %d differs:\n%s\n%s", i, prev, b)
		}
		prev = b
	}
}

func TestUsageErrors(t *testing.T) {
	two := shopWorld()
	two.containers = append(two.containers, ctr("x", "other-worker-1", "other", "worker", "other_default", "172.40.0.2", 300))
	tests := []struct {
		name string
		w    *world
		from string
		code string
	}{
		{"unknown container", shopWorld(), "container:wroker", evidence.CodeNotFound},
		{"unknown service", shopWorld(), "service:nope", evidence.CodeNotFound},
		{"ambiguous service", two, "service:worker", evidence.CodeInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, _ := target.ParseFrom(tt.from)
			to, _ := target.ParseTo("api:8080")
			_, err := New(Deps{Docker: tt.w, Listeners: tt.w}).Diagnose(context.Background(), from, to)
			var e *Error
			if !errors.As(err, &e) || e.Code != tt.code || !IsUsage(err) {
				t.Fatalf("err = %v, want code %s", err, tt.code)
			}
		})
	}
}

func TestDockerUnavailableIsAGap(t *testing.T) {
	from, _ := target.ParseFrom("container:worker")
	to, _ := target.ParseTo("api:8080")
	d, err := New(Deps{DockerErr: docker.ErrUnavailable}).Diagnose(context.Background(), from, to)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != VerdictInconclusive || len(d.Gaps) == 0 || d.ExitCode() != 2 {
		t.Errorf("verdict %s gaps %+v", d.Verdict, d.Gaps)
	}
}

func TestDeadlineGivesPartialResults(t *testing.T) {
	w := shopWorld()
	from, _ := target.ParseFrom("container:shop-worker-1")
	to, _ := target.ParseTo("api:8080")
	ex := &scripted{w: w, name: evidence.ExecutorProbeContainer, block: true}
	start := time.Now()
	d, err := New(Deps{Docker: w, Listeners: w, Probe: blockingExec{ex}, Deadline: 200 * time.Millisecond}).Diagnose(context.Background(), from, to)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("took %s, the deadline is 200ms", took)
	}
	if !d.Timing.DeadlineHit || d.Verdict != VerdictInconclusive {
		t.Errorf("verdict %s, deadline hit %v", d.Verdict, d.Timing.DeadlineHit)
	}
	var timeouts int
	for _, g := range d.Gaps {
		if g.Why == "timeout" {
			timeouts++
		}
	}
	if timeouts == 0 {
		t.Errorf("want a timeout gap, got %+v", d.Gaps)
	}
}

// blockingExec turns a blocked run into per-spec timeout records, as the
// real probe-container executor does.
type blockingExec struct{ s *scripted }

func (b blockingExec) Name() string { return b.s.Name() }

func (b blockingExec) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	_, err := b.s.Run(ctx, where, specs)
	var out []evidence.Evidence
	for _, sp := range specs {
		kind := evidence.KindTCP
		if sp.Kind == probe.SpecDNS {
			kind = evidence.KindDNS
		}
		out = append(out, evidence.Evidence{Kind: kind, Subject: sp.Host, Status: evidence.StatusTimeout,
			Err: &evidence.Error{Code: evidence.CodeTimeout, Message: "wait for probe container: " + err.Error()}})
	}
	return out, err
}

func TestDesktopListenersAreUnsupported(t *testing.T) {
	w := shopWorld()
	w.desktop = true
	d, _ := runScenario(t, scenario{w: w, from: "container:shop-worker-1", to: "api:8080"})
	found := false
	for _, g := range d.Gaps {
		found = found || (g.Why == "unsupported" && strings.Contains(g.What, "listening sockets"))
	}
	if !found {
		t.Errorf("want an unsupported-listeners gap on Docker Desktop, got %+v", d.Gaps)
	}
}

// flaky fails its first negotiation, then works.
type flaky struct {
	*world
	calls int
}

func (f *flaky) Negotiate(ctx context.Context) (docker.Version, error) {
	f.calls++
	if f.calls == 1 {
		return docker.Version{}, docker.ErrUnavailable
	}
	return f.world.Negotiate(ctx)
}

// TestDockerFailureDoesNotStick checks that one failed negotiation doesn't
// disable Docker for the next diagnosis of a long-lived engine (M2's MCP
// server).
func TestDockerFailureDoesNotStick(t *testing.T) {
	w := shopWorld()
	f := &flaky{world: w}
	e := New(Deps{Docker: f, Listeners: w})
	from, _ := target.ParseFrom("container:shop-worker-1")
	to, _ := target.ParseTo("api:8080")
	d1, err := e.Diagnose(context.Background(), from, to)
	if err != nil || d1.Verdict != VerdictInconclusive {
		t.Fatalf("first: %v %+v", err, d1)
	}
	d2, err := e.Diagnose(context.Background(), from, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(d2.Evidence) == 0 || d2.Gaps[0].What == "Docker metadata (containers, networks, listeners)" {
		t.Errorf("the second diagnosis still has no Docker: %+v", d2.Gaps)
	}
}

func factTexts(d *Diagnosis) string {
	var out []string
	for _, f := range d.Facts {
		out = append(out, f.Text)
	}
	return strings.Join(out, "\n")
}

// The review of M1 found these; each test reproduces one.
func TestReviewFindings(t *testing.T) {
	t.Run("a crowded network doesn't hide the destination", func(t *testing.T) {
		w := shopWorld()
		w.containers[1].Name = "shop-zz-api-1"
		w.sockets[200] = []string{"127.0.0.1:8080"}
		for i := range 70 {
			w.containers = append(w.containers, ctr(fmt.Sprintf("%02d", i), fmt.Sprintf("shop-aa-%02d-1", i), "shop", fmt.Sprintf("svc%02d", i), "shop_default", fmt.Sprintf("172.22.1.%d", i), 1000+i))
		}
		d, _ := runScenario(t, scenario{w: w, from: "container:shop-worker-1", to: "api:8080"})
		if p := d.Primary(); p == nil || p.RuleID != "WR002" {
			t.Errorf("primary = %+v, want WR002\nfacts:\n%s", p, factTexts(d))
		}
		skipped := false
		for _, g := range d.Gaps {
			skipped = skipped || strings.Contains(g.What, "aliases of")
		}
		if !skipped {
			t.Errorf("want a gap for the containers that were not inspected: %+v", d.Gaps)
		}
	})

	t.Run("a failed inspect is a gap, not a missing container", func(t *testing.T) {
		w := shopWorld()
		w.failInspect = map[string]error{"shop-api-1": context.DeadlineExceeded}
		d, _ := runScenario(t, scenario{w: w, from: "container:shop-worker-1", to: "api:8080"})
		if strings.Contains(factTexts(d), "no container answers") {
			t.Errorf("claims api doesn't exist:\n%s", factTexts(d))
		}
		found := false
		for _, g := range d.Gaps {
			found = found || (g.What == "container metadata of shop-api-1" && g.Why == "timeout")
		}
		if !found {
			t.Errorf("want a timeout gap for api's metadata: %+v", d.Gaps)
		}
	})

	t.Run("the source's extra_hosts beat a stopped container elsewhere", func(t *testing.T) {
		w := shopWorld()
		w.containers[0].ExtraHosts = []string{"db:192.168.1.50"}
		db := ctr("d", "other-db-1", "other", "db", "other_default", "172.30.0.9", 0)
		db.State = evidence.StateExited
		w.containers = append(w.containers, db)
		w.tcp["192.168.1.50:5432"] = evidence.OutcomeConnected
		w.dns["db"] = []string{"192.168.1.50"}
		d, ex := runScenario(t, scenario{w: w, from: "container:shop-worker-1", to: "db:5432", probes: true})
		if d.Verdict != VerdictNoProblem || len(ex.ran) != 1 {
			t.Errorf("verdict %s, probe batches %d; want the probes to run and connect\n%+v", d.Verdict, len(ex.ran), d.Findings)
		}
		if !strings.Contains(factTexts(d), "extra_hosts map") {
			t.Errorf("want a fact about the extra_hosts mapping:\n%s", factTexts(d))
		}
	})

	t.Run("a stopped container elsewhere doesn't stop the probes", func(t *testing.T) {
		w := shopWorld()
		db := ctr("d", "other-db-1", "other", "db", "other_default", "172.30.0.9", 0)
		db.State = evidence.StateExited
		w.containers = append(w.containers, db)
		_, ex := runScenario(t, scenario{w: w, from: "container:shop-worker-1", to: "db:5432", probes: true})
		if len(ex.ran) != 1 {
			t.Errorf("probe batches = %d, want 1", len(ex.ran))
		}
	})

	t.Run("no tier-2b gap when the destination is down", func(t *testing.T) {
		w := shopWorld()
		w.containers[1].State, w.containers[1].Pid = evidence.StateExited, 0
		d, _ := runScenario(t, scenario{w: w, from: "container:shop-worker-1", to: "api:8080"})
		for _, g := range d.Gaps {
			if strings.Contains(g.HowToEnable, "probe_containers") {
				t.Errorf("asks for probe containers although no probe would run: %+v", g)
			}
		}
		if p := d.Primary(); p == nil || p.RuleID != "WR008" {
			t.Errorf("primary = %+v, want WR008", p)
		}
	})

	t.Run("WR004 on a default-bridge destination advises a user-defined network", func(t *testing.T) {
		w := shopWorld()
		redis := ctr("r", "redis", "", "", "bridge", "172.17.0.5", 300)
		redis.Compose = nil
		redis.Networks[0].Names = nil
		w.containers = append(w.containers, redis)
		d, _ := runScenario(t, scenario{w: w, from: "container:shop-worker-1", to: "redis:6379"})
		p := d.Primary()
		if p == nil || p.RuleID != "WR004" || !strings.Contains(p.Fix, "docker network connect shop_default redis") {
			t.Errorf("primary = %+v", p)
		}
	})

	t.Run("WR002 when the source is the destination itself", func(t *testing.T) {
		w := shopWorld()
		w.sockets[200] = []string{"127.0.0.1:8080"}
		w.tcp["172.22.0.3:8080"] = evidence.OutcomeRefused
		d, _ := runScenario(t, scenario{w: w, from: "container:shop-api-1", to: "api:8080", probes: true})
		if p := d.Primary(); p == nil || p.RuleID != "WR002" {
			t.Errorf("verdict %s, primary %+v; want WR002\n%s", d.Verdict, p, factTexts(d))
		}
	})

	t.Run("WR002 from the host", func(t *testing.T) {
		w := shopWorld()
		w.sockets[200] = []string{"127.0.0.1:8080"}
		w.tcp["172.22.0.3:8080"] = evidence.OutcomeRefused
		d, _ := runScenario(t, scenario{w: w, from: "host", to: "172.22.0.3:8080"})
		if p := d.Primary(); p == nil || p.RuleID != "WR002" || d.Verdict != VerdictCause {
			t.Errorf("verdict %s, primary %+v; want WR002\n%s", d.Verdict, p, factTexts(d))
		}
	})
}
