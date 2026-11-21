package evidence

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
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
		{
			Kind: KindHostAddrs, Context: Host(), Subject: "interfaces", Status: StatusOK, ObservedAt: at,
			Data: HostAddrs{Interfaces: []Interface{{Name: "docker0", Up: true, MTU: 1500, Addrs: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}}}},
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
			if diff := cmp.Diff(want, got, netipOpts, cmpopts.EquateComparable(netip.Prefix{})); diff != "" {
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

func TestSocketAccepts(t *testing.T) {
	v4, v6 := netip.MustParseAddr("172.22.0.3"), netip.MustParseAddr("fd00::3")
	for _, tt := range []struct {
		local  string
		addr   netip.Addr
		accept bool
	}{
		{"0.0.0.0:8080", v4, true},
		{"0.0.0.0:8080", v6, false},
		{"[::]:8080", v4, true}, // unless IPV6_V6ONLY, which /proc doesn't show
		{"[::]:8080", v6, true},
		{"172.22.0.3:8080", v4, true},
		{"[::ffff:172.22.0.3]:8080", v4, true},
		{"172.22.0.4:8080", v4, false},
		{"127.0.0.1:8080", v4, false},
	} {
		s := Socket{Local: netip.MustParseAddrPort(tt.local)}
		if got := s.Accepts(tt.addr); got != tt.accept {
			t.Errorf("%s accepts %s: %v, want %v", tt.local, tt.addr, got, tt.accept)
		}
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

func TestDestinationsEdgeCases(t *testing.T) {
	worker := container("wwwwwwwwwwwwwwww", "shop-worker-1", "shop", "worker", att("shop_default", "172.22.0.2", "worker"))
	q := func(src Container, host string) Question {
		class, addr := ClassifyHost(host)
		return Question{From: Source{Kind: SourceContainer, ContainerID: src.ID}, To: Target{Host: host, Port: 6379, Class: class, Addr: addr}}
	}

	// A container started with docker run on the default bridge: its name
	// identifies it, but resolves on no network, and it shares none with worker.
	redis := container("rrrrrrrrrrrrrrrr", "redis", "", "", att(NetworkBridge, "172.17.0.5"))
	d := viewWith(q(worker, "redis"), worker, redis).Destinations()
	if len(d.Elsewhere) != 1 || len(d.Elsewhere[0].Networks) != 0 || len(d.Elsewhere[0].Shared) != 0 {
		t.Errorf("bridge-only redis: %+v", d)
	}

	// Two containers on the default bridge share it: not WR004's case.
	other := container("oooooooooooooooo", "other", "", "", att(NetworkBridge, "172.17.0.6"))
	d = viewWith(q(other, "redis"), other, redis).Destinations()
	if len(d.OnSourceNets) != 1 || d.OnSourceNets[0].Shared[0] != NetworkBridge {
		t.Errorf("both on the default bridge: %+v", d)
	}

	// worker's own extra_hosts win over a same-named container elsewhere.
	db := container("dddddddddddddddd", "other-db-1", "other", "db", att("other_default", "172.30.0.9", "db"))
	mapped := worker
	mapped.ExtraHosts = []string{"db:192.168.1.50"}
	d = viewWith(q(mapped, "db"), mapped, db).Destinations()
	if d.HostsEntry != "192.168.1.50" || len(d.All()) != 0 {
		t.Errorf("extra_hosts mapping: %+v", d)
	}
	mapped.ExtraHosts = []string{"db=172.30.0.9"}
	d = viewWith(q(mapped, "db"), mapped, db).Destinations()
	if len(d.Elsewhere) != 1 || d.Elsewhere[0].C.Name != "other-db-1" {
		t.Errorf("extra_hosts pointing at a container's address: %+v", d)
	}
	mapped.ExtraHosts = []string{"db:host-gateway"}
	d = viewWith(q(mapped, "db"), mapped, db).Destinations()
	if d.HostsEntry != "host-gateway" || len(d.All()) != 0 {
		t.Errorf("host-gateway: %+v", d)
	}

	// A destination in network_mode container:X is reachable on X's networks.
	proxy := container("pppppppppppppppp", "shop-proxy-1", "shop", "proxy", att("shop_default", "172.22.0.7", "proxy"))
	sidecar := container("ssssssssssssssss", "shop-sidecar-1", "shop", "sidecar")
	sidecar.NetworkMode = "container:" + proxy.ID
	d = viewWith(q(worker, "sidecar"), worker, proxy, sidecar).Destinations()
	if len(d.OnSourceNets) != 1 || d.OnSourceNets[0].C.Name != "shop-sidecar-1" {
		t.Errorf("container: destination: %+v", d)
	}
}

// A stopped container's fixed address makes it the destination of a
// connection to that address, unless a container that is up holds it:
// Docker hands a stopped container's fixed address to others (measured on
// Engine 29.9.3). A created container shows its fixed address as its
// address, which it doesn't hold either.
func TestDestinationsFixedAddress(t *testing.T) {
	worker := container("wwwwwwwwwwwwwwww", "shop-worker-1", "shop", "worker", att("shop_default", "172.22.0.2", "worker"))
	stopped := func(id, name, state, shown string) Container {
		c := container(id, name, "shop", strings.TrimSuffix(strings.TrimPrefix(name, "shop-"), "-1"), att("shop_default", shown))
		c.State = state
		c.Networks[0].FixedIPv4 = netip.MustParseAddr("172.22.0.11")
		return c
	}
	db := stopped("dddddddddddddddd", "shop-db-1", StateExited, "")
	created := stopped("nnnnnnnnnnnnnnnn", "shop-new-1", StateCreated, "172.22.0.11")
	cache := container("cccccccccccccccc", "shop-cache-1", "shop", "cache", att("shop_default", "172.22.0.11", "cache"))
	paused := cache
	paused.State = StatePaused
	dynamic := container("oooooooooooooooo", "shop-old-1", "shop", "old", att("shop_default", ""))
	dynamic.State = StateExited
	q := Question{From: Source{Kind: SourceContainer, ContainerID: worker.ID}, To: Target{Host: "172.22.0.11", Port: 5432, Class: TargetIP, Addr: netip.MustParseAddr("172.22.0.11")}}
	mapped := worker
	mapped.ExtraHosts = []string{"db:172.22.0.11"}
	byHosts := Question{From: Source{Kind: SourceContainer, ContainerID: worker.ID}, To: Target{Host: "db", Port: 5432, Class: TargetName}}
	tests := []struct {
		name string
		v    View
		want []string
	}{
		{"a stopped container's fixed address", viewWith(q, worker, db), []string{"shop-db-1"}},
		{"through extra_hosts", viewWith(byHosts, mapped, db), []string{"shop-db-1"}},
		{"a created container's", viewWith(q, worker, created), []string{"shop-new-1"}},
		{"taken by a running container", viewWith(q, worker, db, created, cache), []string{"shop-cache-1"}},
		{"taken by a paused one", viewWith(q, worker, db, paused), []string{"shop-cache-1"}},
		{"a dynamic address isn't kept", viewWith(q, worker, dynamic), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, m := range tt.v.Destinations().All() {
				got = append(got, m.C.Name)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("destinations (-want +got):\n%s", diff)
			}
		})
	}
}

func TestViewContainerByReference(t *testing.T) {
	c := container(strings.Repeat("ab", 32), "shop-api-1", "shop", "api", att("shop_default", "172.22.0.3"))
	v := viewWith(Question{}, c)
	for _, ref := range []string{c.ID, c.ID[:12], c.ID[:20], "shop-api-1", "/shop-api-1"} {
		if _, ok := v.Container(ref); !ok {
			t.Errorf("Container(%q) not found", ref)
		}
	}
	for _, ref := range []string{"", c.ID[:6], "api", "shop-api"} {
		if _, ok := v.Container(ref); ok {
			t.Errorf("Container(%q) found, want no match", ref)
		}
	}
}

func TestHostsEntry(t *testing.T) {
	c := Container{ExtraHosts: []string{"db:192.168.1.50", "cache=10.0.0.7", "v6:::1", "host.docker.internal:host-gateway", "[bracket]:[fd00::1]"}}
	tests := map[string]string{"db": "192.168.1.50", "DB.": "192.168.1.50", "cache": "10.0.0.7", "v6": "::1", "host.docker.internal": "host-gateway"}
	for name, want := range tests {
		if got, ok := c.HostsEntry(name); !ok || got != want {
			t.Errorf("HostsEntry(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	if _, ok := c.HostsEntry("api"); ok {
		t.Error("HostsEntry(api) matched")
	}
}

// hostView is viewWith plus the host's interfaces and extra records.
func hostView(q Question, extra []Evidence, cs ...Container) View {
	var s Store
	for _, c := range cs {
		s.Add(Evidence{Kind: KindContainer, Context: InContainer(c), Subject: "container:" + c.Name, Status: StatusOK, Data: c})
	}
	s.Add(Evidence{Kind: KindHostAddrs, Context: Host(), Subject: "interfaces", Status: StatusOK, Data: HostAddrs{Interfaces: []Interface{
		{Name: "docker0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
		{Name: "eth0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}},
		{Name: "lo", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
	}}})
	s.Add(extra...)
	return NewView(q, s.Finalize())
}

func TestHostTarget(t *testing.T) {
	worker := container("wwwwwwwwwwwwwwww", "shop-worker-1", "shop", "worker", att("shop_default", "172.22.0.2", "worker"))
	gw := worker
	gw.ExtraHosts = []string{"host.docker.internal:host-gateway"}
	hostnet := container("hhhhhhhhhhhhhhhh", "agent", "", "")
	hostnet.NetworkMode = "host"
	api := container("aaaaaaaaaaaaaaaa", "shop-api-1", "shop", "api", att("shop_default", "172.22.0.3", "api"))

	fromC := func(src Container, host string) Question {
		class, addr := ClassifyHost(host)
		return Question{From: Source{Kind: SourceContainer, ContainerID: src.ID}, To: Target{Host: host, Port: 5432, Class: class, Addr: addr}}
	}
	fromHost := func(host string) Question {
		class, addr := ClassifyHost(host)
		return Question{From: Source{Kind: SourceHost, Ref: "host"}, To: Target{Host: host, Port: 5432, Class: class, Addr: addr}}
	}
	resolved := func(ctx ContextRef, name, addr string) Evidence {
		return Evidence{Kind: KindDNS, Context: ctx, Subject: name, Status: StatusOK, Data: DNSProbe{Name: name, Answers: []netip.Addr{netip.MustParseAddr(addr)}}}
	}
	tests := []struct {
		name     string
		v        View
		ok       bool
		via      string
		addr     string
		iface    string
		hostsRef bool
	}{
		{"localhost from the host", hostView(fromHost("localhost"), nil), true, HostViaLoopback, "", "", false},
		{"127.0.0.1 from the host", hostView(fromHost("127.0.0.1"), nil), true, HostViaLoopback, "127.0.0.1", "", false},
		{"the host's LAN address from the host", hostView(fromHost("192.168.1.10"), nil), true, HostViaAddress, "192.168.1.10", "eth0", false},
		{"a container address from the host", hostView(fromHost("172.22.0.3"), nil, api), false, "", "", "", false},
		{"a container name from the host", hostView(fromHost("api"), nil, api), false, "", "", "", false},
		{"localhost from a host-network container", hostView(fromC(hostnet, "localhost"), nil, hostnet), true, HostViaLoopback, "", "", false},
		{"localhost from a container is the container", hostView(fromC(worker, "localhost"), nil, worker), false, "", "", "", false},
		{"host.docker.internal mapped to host-gateway", hostView(fromC(gw, "host.docker.internal"), nil, gw), true, HostViaGateway, "172.17.0.1", "docker0", true},
		{"host-gateway as the source resolved it", hostView(fromC(gw, "host.docker.internal"), []Evidence{resolved(InContainer(gw), "host.docker.internal", "172.17.0.1")}, gw), true, HostViaGateway, "172.17.0.1", "docker0", true},
		{"host.docker.internal without a mapping", hostView(fromC(worker, "host.docker.internal"), nil, worker), true, HostViaName, "", "", false},
		{"the docker0 address from a container", hostView(fromC(worker, "172.17.0.1"), nil, worker), true, HostViaAddress, "172.17.0.1", "docker0", false},
		{"a name that resolves to the host", hostView(fromC(worker, "db.lan"), []Evidence{resolved(InContainer(worker), "db.lan", "192.168.1.10")}, worker), true, HostViaAddress, "192.168.1.10", "eth0", false},
		{"a container name from a container", hostView(fromC(worker, "api"), nil, worker, api), false, "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.v.HostTarget()
			if ok != tt.ok {
				t.Fatalf("HostTarget() ok = %v, want %v (%+v)", ok, tt.ok, got)
			}
			if !ok {
				return
			}
			addr := ""
			if got.Addr.IsValid() {
				addr = got.Addr.String()
			}
			if got.Via != tt.via || addr != tt.addr || got.Iface != tt.iface {
				t.Errorf("HostTarget() = %+v, want via %s addr %q iface %q", got, tt.via, tt.addr, tt.iface)
			}
			if d := tt.v.Destinations(); d.Host == nil || (d.HostsEntry != "") != tt.hostsRef {
				t.Errorf("Destinations() = %+v", d)
			}
		})
	}
}

func TestPublishedDestinations(t *testing.T) {
	web := container("eeeeeeeeeeeeeeee", "shop-web-1", "shop", "web", att("shop_default", "172.22.0.4", "web"))
	web.Ports = []PortMap{
		{ContainerPort: 8080, Proto: "tcp", HostIP: "0.0.0.0", HostPort: 18080},
		{ContainerPort: 8080, Proto: "tcp", HostIP: "::", HostPort: 18080},
	}
	lo := container("llllllllllllllll", "shop-admin-1", "shop", "admin", att("shop_default", "172.22.0.5", "admin"))
	lo.Ports = []PortMap{{ContainerPort: 9000, Proto: "tcp", HostIP: "127.0.0.1", HostPort: 19000}}
	worker := container("wwwwwwwwwwwwwwww", "shop-worker-1", "shop", "worker", att("shop_default", "172.22.0.2", "worker"))
	worker.ExtraHosts = []string{"host.docker.internal:host-gateway"}

	q := func(src Source, host string, port uint16) Question {
		class, addr := ClassifyHost(host)
		return Question{From: src, To: Target{Host: host, Port: port, Class: class, Addr: addr}}
	}
	hostSrc := Source{Kind: SourceHost, Ref: "host"}
	workerSrc := Source{Kind: SourceContainer, ContainerID: worker.ID}
	tests := []struct {
		name string
		q    Question
		want string // "name:port" of the published match, or ""
	}{
		{"localhost from the host", q(hostSrc, "localhost", 18080), "shop-web-1:8080"},
		{"the LAN address from the host", q(hostSrc, "192.168.1.10", 18080), "shop-web-1:8080"},
		{"loopback-only binding from the host", q(hostSrc, "127.0.0.1", 19000), "shop-admin-1:9000"},
		{"loopback-only binding through the LAN address", q(hostSrc, "192.168.1.10", 19000), ""},
		{"host-gateway from a container", q(workerSrc, "host.docker.internal", 18080), "shop-web-1:8080"},
		{"loopback-only binding through host-gateway", q(workerSrc, "host.docker.internal", 19000), ""},
		{"an unpublished port", q(hostSrc, "localhost", 8080), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := hostView(tt.q, nil, web, lo, worker).Destinations()
			got := ""
			if len(d.Published) > 0 {
				m := d.Published[0]
				got = m.C.Name + ":" + strconv.Itoa(int(m.Port))
				if m.Published == nil || len(d.All()) == 0 {
					t.Errorf("match without its binding: %+v", m)
				}
			}
			if got != tt.want {
				t.Errorf("published = %q, want %q (%+v)", got, tt.want, d)
			}
		})
	}
}

func TestPortMapCovers(t *testing.T) {
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	tests := []struct {
		hostIP string
		addr   string
		want   bool
	}{
		{"", "127.0.0.1", true},
		{"0.0.0.0", "192.168.1.10", true},
		{"0.0.0.0", "::1", false},
		{"::", "::1", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1", "172.17.0.1", false},
		{"192.168.1.10", "192.168.1.10", true},
	}
	for _, tt := range tests {
		if got := (PortMap{HostIP: tt.hostIP, HostPort: 1}).Covers(a(tt.addr)); got != tt.want {
			t.Errorf("Covers(%q, %s) = %v, want %v", tt.hostIP, tt.addr, got, tt.want)
		}
	}
	if !(PortMap{HostIP: "127.0.0.1"}).LoopbackOnly() || (PortMap{HostIP: "0.0.0.0"}).LoopbackOnly() || (PortMap{}).LoopbackOnly() {
		t.Error("LoopbackOnly")
	}
	if got := (PortMap{HostIP: "::", HostPort: 80}).HostAddr(); got != "[::]:80" {
		t.Errorf("HostAddr = %s", got)
	}
}
