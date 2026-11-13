package evidence

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// netipOpts lets go-cmp compare netip values, whose fields are unexported.
var netipOpts = cmpopts.EquateComparable(netip.Addr{}, netip.AddrPort{})

func TestEvidenceJSONRoundTrip(t *testing.T) {
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	tests := []Evidence{
		{
			Kind: KindTCP, Context: ContextRef{Kind: ContextContainer, Container: "a3d380d0831a", Name: "worker", Executor: ExecutorProbeContainer},
			Subject: "api:8080", Status: StatusOK, ObservedAt: at, Duration: 3 * time.Millisecond,
			Data: TCPProbe{
				Target: "api:8080", Addr: netip.MustParseAddrPort("172.22.0.3:8080"), Via: ViaDNS,
				Outcome: OutcomeRefused, Errno: "ECONNREFUSED", RTT: 250 * time.Microsecond,
			},
			Source: "TCP connect from worker's netns",
		},
		{
			Kind: KindDNS, Context: Host(), Subject: "api", Status: StatusOK, ObservedAt: at,
			Data: DNSProbe{
				Name: "api", Via: ViaDNS, Server: "127.0.0.11:53", Rcode: "NOERROR",
				Answers:  []netip.Addr{netip.MustParseAddr("172.22.0.3")},
				Attempts: []DNSAttempt{{Query: "api", Type: "A", Rcode: "NOERROR", N: 1}},
			},
		},
		{
			Kind: KindListeners, Context: ContextRef{Kind: ContextContainer, Container: "36bf89fd2b24", Name: "api"},
			Subject: "listeners", Status: StatusOK, ObservedAt: at,
			Data: Listeners{Sockets: []Socket{{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.1:8080")}}},
		},
		{
			Kind: KindContainer, Context: ContextRef{Kind: ContextContainer, Container: "36bf89fd2b24", Name: "api"},
			Subject: "container:api", Status: StatusOK, ObservedAt: at,
			Data: Container{
				ID: "36bf89fd2b244a7a", Name: "shop-api-1", State: StateRunning, Pid: 42,
				StartedAt: at.Add(-time.Hour), Compose: &ComposeRef{Project: "shop", Service: "api"},
				NetworkMode: "shop_default",
				Networks: []NetAttachment{{
					Network: "shop_default", IPv4: netip.MustParseAddr("172.22.0.3"),
					Names: []string{"api", "shop-api-1"},
				}},
			},
		},
		{
			Kind: KindDockerVersion, Context: Host(), Subject: "docker", Status: StatusOK, ObservedAt: at,
			Data: DockerVersion{Version: "29.9.3", APIVersion: "1.56", Os: "linux", Arch: "amd64", LinuxEngine: true},
		},
		{
			Kind: KindTCP, Context: Host(), Subject: "api:8080", Status: StatusPermissionDenied, ObservedAt: at,
			Err: &Error{Code: CodePermissionDenied, Message: "probe containers are off"},
		},
	}
	for _, want := range tests {
		t.Run(string(want.Kind)+"/"+string(want.Status), func(t *testing.T) {
			b, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			var got Evidence
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshal %s: %v", b, err)
			}
			if diff := cmp.Diff(want, got, netipOpts); diff != "" {
				t.Errorf("round trip mismatch (-want +got):\n%s\njson: %s", diff, b)
			}
		})
	}
}

func TestEvidenceUnmarshalUnknownKind(t *testing.T) {
	var e Evidence
	err := json.Unmarshal([]byte(`{"kind":"probe.icmp","data":{"x":1}}`), &e)
	if err == nil {
		t.Fatal("want an error for an unknown kind with a payload")
	}
}

func TestStoreFinalizeIsCanonical(t *testing.T) {
	a := Evidence{Kind: KindTCP, Context: Host(), Subject: "api:8080", Status: StatusOK,
		Data: TCPProbe{Addr: netip.MustParseAddrPort("10.0.0.2:8080"), Via: ViaDNS}}
	b := Evidence{Kind: KindTCP, Context: Host(), Subject: "api:8080", Status: StatusOK,
		Data: TCPProbe{Addr: netip.MustParseAddrPort("10.0.0.1:8080"), Via: ViaDNS}}
	c := Evidence{Kind: KindContainer, Context: ContextRef{Kind: ContextContainer, Name: "api"}, Subject: "container:api", Status: StatusOK}
	d := Evidence{Kind: KindDockerVersion, Context: Host(), Subject: "docker", Status: StatusOK}

	var s1, s2 Store
	s1.Add(a, b, c, d)
	s2.Add(d, c)
	s2.Add(b)
	s2.Add(a)
	got1, got2 := s1.Finalize(), s2.Finalize()
	if diff := cmp.Diff(got1, got2, netipOpts); diff != "" {
		t.Fatalf("insertion order changed the result (-s1 +s2):\n%s", diff)
	}
	wantSubjects := []string{"docker", "container:api", "api:8080", "api:8080"}
	for i, e := range got1 {
		if e.Subject != wantSubjects[i] {
			t.Errorf("record %d subject = %q, want %q", i, e.Subject, wantSubjects[i])
		}
		if want := []string{"ev-01", "ev-02", "ev-03", "ev-04"}[i]; e.ID != want {
			t.Errorf("record %d ID = %q, want %q", i, e.ID, want)
		}
	}
	if got := got1[2].Data.(TCPProbe).Addr.String(); got != "10.0.0.1:8080" {
		t.Errorf("TCP probes not ordered by address: first is %s", got)
	}
}

func TestClassifyHost(t *testing.T) {
	tests := []struct {
		host      string
		wantClass string
		wantAddr  string
	}{
		{"api", TargetName, ""},
		{"API.example.com", TargetName, ""},
		{"host.docker.internal", TargetName, ""},
		{"localhost", TargetLoopback, ""},
		{"LOCALHOST.", TargetLoopback, ""},
		{"ip6-localhost", TargetLoopback, ""},
		{"app.localhost", TargetLoopback, ""},
		{"127.0.0.1", TargetLoopback, "127.0.0.1"},
		{"127.8.9.10", TargetLoopback, "127.8.9.10"},
		{"::1", TargetLoopback, "::1"},
		{"0.0.0.0", TargetLoopback, "0.0.0.0"},
		{"::ffff:127.0.0.1", TargetLoopback, "127.0.0.1"},
		{"172.22.0.3", TargetIP, "172.22.0.3"},
		{"fd00::5", TargetIP, "fd00::5"},
	}
	for _, tt := range tests {
		class, addr := ClassifyHost(tt.host)
		gotAddr := ""
		if addr.IsValid() {
			gotAddr = addr.String()
		}
		if class != tt.wantClass || gotAddr != tt.wantAddr {
			t.Errorf("ClassifyHost(%q) = %s %q, want %s %q", tt.host, class, gotAddr, tt.wantClass, tt.wantAddr)
		}
	}
}

func TestTargetString(t *testing.T) {
	tests := []struct {
		t    Target
		want string
	}{
		{Target{Host: "api", Port: 8080}, "api:8080"},
		{Target{Host: "::1", Port: 80, Addr: netip.MustParseAddr("::1")}, "[::1]:80"},
		{Target{Host: "10.0.0.1", Port: 5432, Addr: netip.MustParseAddr("10.0.0.1")}, "10.0.0.1:5432"},
	}
	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestListenersHelpers(t *testing.T) {
	l := Listeners{Sockets: []Socket{
		{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.11:38765")},
		{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.1:8080")},
		{Proto: "tcp6", Local: netip.MustParseAddrPort("[::1]:8080")},
		{Proto: "tcp", Local: netip.MustParseAddrPort("0.0.0.0:9090")},
		{Proto: "tcp6", Local: netip.MustParseAddrPort("[::ffff:127.0.0.1]:7070")},
	}}
	if got := len(l.OnPort(38765)); got != 0 {
		t.Errorf("OnPort included Docker's DNS listener")
	}
	if !l.AcceptsLoopback(8080) || l.AcceptsRemote(8080) {
		t.Errorf("8080 is loopback-only: AcceptsLoopback=%v AcceptsRemote=%v", l.AcceptsLoopback(8080), l.AcceptsRemote(8080))
	}
	if !l.AcceptsLoopback(9090) || !l.AcceptsRemote(9090) {
		t.Errorf("0.0.0.0:9090 accepts both")
	}
	if l.AcceptsRemote(7070) {
		t.Errorf("::ffff:127.0.0.1 is loopback")
	}
	if l.AcceptsLoopback(1) || l.AcceptsRemote(1) {
		t.Errorf("nothing listens on port 1")
	}
}

func container(id, name, project, service string, nets ...NetAttachment) Container {
	c := Container{ID: id, Name: name, State: StateRunning, Networks: nets, NetworkMode: "bridge"}
	if project != "" {
		c.Compose = &ComposeRef{Project: project, Service: service}
	}
	return c
}

func att(network, ip string, names ...string) NetAttachment {
	a := NetAttachment{Network: network, Names: names}
	if ip != "" {
		a.IPv4 = netip.MustParseAddr(ip)
	}
	return a
}

func viewWith(q Question, cs ...Container) View {
	var s Store
	for _, c := range cs {
		s.Add(Evidence{Kind: KindContainer, Context: InContainer(c), Subject: "container:" + c.Name, Status: StatusOK, Data: c})
	}
	return NewView(q, s.Finalize())
}

func TestDestinations(t *testing.T) {
	worker := container("wwwwwwwwwwwwwwww", "shop-worker-1", "shop", "worker", att("shop_default", "172.22.0.2", "worker"))
	api := container("aaaaaaaaaaaaaaaa", "shop-api-1", "shop", "api", att("shop_default", "172.22.0.3", "api", "apialias"))
	otherAPI := container("bbbbbbbbbbbbbbbb", "billing-api-1", "billing", "api", att("billing_default", "172.30.0.3", "api"))
	sidecar := container("ssssssssssssssss", "sidecar", "", "", att("shop_default", "172.22.0.9"))
	sidecar.NetworkMode = "container:" + worker.ID

	q := func(from string, host string) Question {
		class, addr := ClassifyHost(host)
		return Question{
			From: Source{Kind: SourceContainer, ContainerID: from},
			To:   Target{Host: host, Port: 8080, Proto: "tcp", Class: class, Addr: addr},
		}
	}
	names := func(ms []Match) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.C.Name)
		}
		return out
	}
	tests := []struct {
		name          string
		v             View
		wantOn, wantE []string
	}{
		{"service name on the shared network", viewWith(q(worker.ID, "api"), worker, api, otherAPI), []string{"shop-api-1"}, []string{"billing-api-1"}},
		{"alias", viewWith(q(worker.ID, "APIALIAS"), worker, api), []string{"shop-api-1"}, nil},
		{"container name", viewWith(q(worker.ID, "billing-api-1"), worker, api, otherAPI), nil, []string{"billing-api-1"}},
		{"address on the shared network", viewWith(q(worker.ID, "172.22.0.3"), worker, api), []string{"shop-api-1"}, nil},
		{"address elsewhere", viewWith(q(worker.ID, "172.30.0.3"), worker, otherAPI), nil, []string{"billing-api-1"}},
		{"no match", viewWith(q(worker.ID, "db"), worker, api), nil, nil},
		{"loopback has no destination", viewWith(q(worker.ID, "localhost"), worker, api), nil, nil},
		{"container: network mode uses the owner's networks", viewWith(q(sidecar.ID, "api"), worker, api, sidecar), []string{"shop-api-1"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.v.Destinations()
			if diff := cmp.Diff(tt.wantOn, names(d.OnSourceNets)); diff != "" {
				t.Errorf("OnSourceNets (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantE, names(d.Elsewhere)); diff != "" {
				t.Errorf("Elsewhere (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDestinationsPrefersSourceProject(t *testing.T) {
	worker := container("wwwwwwwwwwwwwwww", "shop-worker-1", "shop", "worker", att("shop_back", "172.22.0.2"))
	a := container("aaaaaaaaaaaaaaaa", "aaa-api-1", "aaa", "api", att("aaa_default", "172.30.0.3", "api"))
	b := container("bbbbbbbbbbbbbbbb", "shop-api-1", "shop", "api", att("shop_front", "172.31.0.3", "api"))
	v := viewWith(Question{
		From: Source{Kind: SourceContainer, ContainerID: worker.ID},
		To:   Target{Host: "api", Port: 8080, Class: TargetName},
	}, worker, a, b)
	got := v.Destinations().Elsewhere
	if len(got) != 2 || got[0].C.Name != "shop-api-1" {
		t.Fatalf("want the source's own project first, got %+v", got)
	}
}
