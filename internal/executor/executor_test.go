package executor

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// fakeAPI is a scripted Docker probe API.
type fakeAPI struct {
	mu        sync.Mutex
	calls     []string
	version   docker.Version
	images    map[string]docker.Image
	imported  []byte
	stdout    []byte
	exitCode  int
	startErr  error
	waitBlock bool
	leftovers []docker.Summary
	removed   []string
	created   []docker.ProbeSpec
}

func (f *fakeAPI) call(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeAPI) Negotiate(context.Context) (docker.Version, error) {
	f.call("negotiate")
	return f.version, nil
}

func (f *fakeAPI) ImageInspect(_ context.Context, ref string) (docker.Image, error) {
	f.call("inspect " + ref)
	if img, ok := f.images[ref]; ok {
		return img, nil
	}
	return docker.Image{}, &docker.APIError{Status: 404, Message: "No such image"}
}

func (f *fakeAPI) ImageImport(_ context.Context, tag string, r io.Reader, changes []string) error {
	f.call("import " + tag + " " + strings.Join(changes, "|"))
	b, err := io.ReadAll(r)
	f.imported = b
	return err
}

func (f *fakeAPI) Create(_ context.Context, spec docker.ProbeSpec) (string, error) {
	f.call("create " + spec.Image + " netns=" + spec.NetnsOf)
	f.created = append(f.created, spec)
	return "probe-id", nil
}

func (f *fakeAPI) Start(context.Context, string) error {
	f.call("start")
	return f.startErr
}

func (f *fakeAPI) Wait(ctx context.Context, _ string) (int, error) {
	f.call("wait")
	if f.waitBlock {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	return f.exitCode, nil
}

func (f *fakeAPI) Logs(context.Context, string, int) ([]byte, []byte, error) {
	f.call("logs")
	return f.stdout, []byte("probe stderr"), nil
}

func (f *fakeAPI) Remove(_ context.Context, id string) error {
	f.call("remove " + id)
	f.removed = append(f.removed, id)
	return nil
}

func (f *fakeAPI) Leftovers(context.Context, time.Time) ([]docker.Summary, error) {
	f.call("leftovers")
	return f.leftovers, nil
}

// fakeELF writes a minimal ELF64 executable header for the running
// architecture; dynamic adds a PT_INTERP program header.
func fakeELF(t *testing.T, dynamic bool) string {
	t.Helper()
	machine := map[string]uint16{"amd64": 62, "arm64": 183}[runtime.GOARCH]
	if machine == 0 {
		t.Skip("no fake ELF for " + runtime.GOARCH)
	}
	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	le := binary.LittleEndian
	w := func(v any) { _ = binary.Write(&b, le, v) }
	phnum, phoff := uint16(0), uint64(0)
	if dynamic {
		phnum, phoff = 1, 64
	}
	w(uint16(2))       // e_type EXEC
	w(machine)         // e_machine
	w(uint32(1))       // e_version
	w(uint64(0x40000)) // e_entry
	w(phoff)           // e_phoff
	w(uint64(0))       // e_shoff
	w(uint32(0))       // e_flags
	w(uint16(64))      // e_ehsize
	w(uint16(56))      // e_phentsize
	w(phnum)           // e_phnum
	w(uint16(64))      // e_shentsize
	w(uint16(0))       // e_shnum
	w(uint16(0))       // e_shstrndx
	if dynamic {
		w(uint32(3)) // p_type PT_INTERP
		w(uint32(4)) // p_flags
		for range 6 {
			w(uint64(0))
		}
	}
	path := filepath.Join(t.TempDir(), "whyreach")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func probeOutput(t *testing.T, evs ...evidence.Evidence) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, ev := range evs {
		if err := json.NewEncoder(&b).Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

var worker = evidence.ContextRef{Kind: evidence.ContextContainer, Container: "a3d380d0831a", Name: "worker"}

func TestProbeContainerRun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the probe container needs a Linux whyreach")
	}
	bin := fakeELF(t, false)
	api := &fakeAPI{
		version: docker.Version{Os: "linux", Arch: runtime.GOARCH},
		stdout: probeOutput(t, evidence.Evidence{
			Kind: evidence.KindTCP, Subject: "api:8080", Status: evidence.StatusOK,
			Context: evidence.ContextRef{NetnsID: 4026532512},
			Data:    evidence.TCPProbe{Target: "api:8080", Addr: netip.MustParseAddrPort("172.22.0.3:8080"), Via: evidence.ViaDNS, Outcome: evidence.OutcomeRefused},
			Source:  "TCP connect, then close (no payload)",
		}),
		leftovers: []docker.Summary{{ID: "stale", Names: []string{"/wr-probe-stale"}}},
	}
	pc := NewProbeContainer(api, bin, "0.1.0-dirty", nil)
	specs := []probe.Spec{{Kind: probe.SpecTCP, Host: "api", Port: 8080}}
	evs, err := pc.Run(context.Background(), worker, specs)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d records", len(evs))
	}
	got := evs[0]
	if got.Context.Container != worker.Container || got.Context.Name != "worker" ||
		got.Context.Executor != evidence.ExecutorProbeContainer || got.Context.NetnsID != 4026532512 {
		t.Errorf("context = %+v", got.Context)
	}
	if !strings.Contains(got.Source, "via probe container wr-probe-") {
		t.Errorf("source = %q", got.Source)
	}
	// The image was imported once, as a one-file tar of the binary.
	tr := tar.NewReader(bytes.NewReader(api.imported))
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "whyreach" || hdr.Mode != 0o555 {
		t.Fatalf("imported tar: %+v, %v", hdr, err)
	}
	if !strings.HasPrefix(api.created[0].Image, "whyreach-probe:0.1.0-dirty-") || api.created[0].NetnsOf != worker.Container {
		t.Errorf("created %+v", api.created[0])
	}
	if api.removed[len(api.removed)-1] != "probe-id" {
		t.Errorf("probe container not removed: %v", api.removed)
	}
	effects := strings.Join(pc.SideEffects(), "\n")
	for _, want := range []string{"removed 1 leftover probe container", "imported image whyreach-probe:0.1.0-dirty-", "(removed)"} {
		if !strings.Contains(effects, want) {
			t.Errorf("side effects %q lack %q", effects, want)
		}
	}
	// A second run reuses the image and does not sweep again.
	api.calls = nil
	api.images = map[string]docker.Image{}
	if _, err := pc.Run(context.Background(), worker, specs); err != nil {
		t.Fatal(err)
	}
	for _, c := range api.calls {
		if strings.HasPrefix(c, "import") || c == "leftovers" || c == "negotiate" {
			t.Errorf("second run repeated %q", c)
		}
	}
}

func TestProbeContainerCleansUpOnEveryPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the probe container needs a Linux whyreach")
	}
	bin := fakeELF(t, false)
	specs := []probe.Spec{{Kind: probe.SpecDNS, Host: "api"}, {Kind: probe.SpecTCP, Host: "api", Port: 8080}}
	tests := []struct {
		name       string
		api        *fakeAPI
		ctx        func() (context.Context, context.CancelFunc)
		wantStatus evidence.Status
	}{
		{
			name:       "the target is not running",
			api:        &fakeAPI{startErr: &docker.APIError{Status: 409, Message: "cannot join network namespace of a non running container"}},
			wantStatus: evidence.StatusFailed,
		},
		{
			name: "the diagnosis deadline passes while waiting",
			api:  &fakeAPI{waitBlock: true},
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			wantStatus: evidence.StatusTimeout,
		},
		{
			name:       "the probe fails internally",
			api:        &fakeAPI{exitCode: 4},
			wantStatus: evidence.StatusError,
		},
		{
			name:       "the probe prints garbage",
			api:        &fakeAPI{stdout: []byte("not json\n")},
			wantStatus: evidence.StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.api.version = docker.Version{Os: "linux", Arch: runtime.GOARCH}
			ctx, cancel := context.WithCancel(context.Background())
			if tt.ctx != nil {
				ctx, cancel = tt.ctx()
			}
			defer cancel()
			pc := NewProbeContainer(tt.api, bin, "dev", nil)
			evs, err := pc.Run(ctx, worker, specs)
			if err == nil {
				t.Fatal("want an error")
			}
			if len(evs) != len(specs) {
				t.Fatalf("got %d records, want one per spec", len(evs))
			}
			for _, ev := range evs {
				if ev.Status != tt.wantStatus || ev.Err == nil || ev.Context.Executor != evidence.ExecutorProbeContainer {
					t.Errorf("record %+v, want status %s with an error", ev, tt.wantStatus)
				}
			}
			if len(tt.api.removed) == 0 || tt.api.removed[len(tt.api.removed)-1] != "probe-id" {
				t.Errorf("the probe container was not removed: calls %v", tt.api.calls)
			}
		})
	}
}

func TestProbeContainerRefusesUnusableBinaries(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the probe container needs a Linux whyreach")
	}
	notELF := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(notELF, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		bin    string
		daemon docker.Version
	}{
		{"dynamically linked", fakeELF(t, true), docker.Version{Os: "linux", Arch: runtime.GOARCH}},
		{"not an ELF", notELF, docker.Version{Os: "linux", Arch: runtime.GOARCH}},
		{"another architecture", fakeELF(t, false), docker.Version{Os: "linux", Arch: "riscv64"}},
		{"a Windows daemon", fakeELF(t, false), docker.Version{Os: "windows", Arch: runtime.GOARCH}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeAPI{version: tt.daemon}
			evs, err := NewProbeContainer(api, tt.bin, "dev", nil).Run(context.Background(), worker, []probe.Spec{{Kind: probe.SpecListeners}})
			if !errors.Is(err, probe.ErrUnsupported) {
				t.Fatalf("err = %v, want ErrUnsupported", err)
			}
			if evs[0].Status != evidence.StatusUnsupported {
				t.Errorf("status = %s", evs[0].Status)
			}
			for _, c := range api.calls {
				if strings.HasPrefix(c, "create") || strings.HasPrefix(c, "import") {
					t.Errorf("made a Docker write: %s", c)
				}
			}
		})
	}
}

func TestProbeContainerOnlyJoinsContainers(t *testing.T) {
	api := &fakeAPI{}
	_, err := NewProbeContainer(api, "x", "dev", nil).Run(context.Background(), evidence.Host(), []probe.Spec{{Kind: probe.SpecListeners}})
	if err == nil || len(api.calls) != 0 {
		t.Errorf("err = %v, calls %v", err, api.calls)
	}
}

func TestImageTag(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	tests := map[string]string{
		"0.1.0":                  "0.1.0-abababababab",
		"b721ad9-dirty":          "b721ad9-dirty-abababababab",
		"v0.1.0+meta/x":          "v0.1.0-meta-x-abababababab",
		"":                       "dev-abababababab",
		".hidden":                "hidden-abababababab",
		strings.Repeat("x", 100): strings.Repeat("x", 64) + "-abababababab",
	}
	for v, want := range tests {
		if got := ImageTag(v, digest); got != want {
			t.Errorf("ImageTag(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestDecodeEvidenceRejectsUnexpectedKinds(t *testing.T) {
	out := probeOutput(t, evidence.Evidence{Kind: evidence.KindContainer, Status: evidence.StatusOK, Data: evidence.Container{ID: "x"}})
	if _, err := decodeEvidence(out); err == nil {
		t.Error("a probe must not be able to report Docker metadata")
	}
}

func TestHostRun(t *testing.T) {
	h := &Host{Env: probe.Env{ProcDir: "/proc", Resolver: &probe.Resolver{HostsPath: "/nonexistent", ResolvPath: "/nonexistent"}}}
	evs, err := h.Run(context.Background(), evidence.Host(), []probe.Spec{{Kind: probe.SpecTCP, Host: "169.254.169.254", Port: 80}})
	if err != nil || len(evs) != 1 {
		t.Fatalf("evs %v err %v", evs, err)
	}
	if evs[0].Context.Kind != evidence.ContextHost || evs[0].Context.Executor != evidence.ExecutorHost {
		t.Errorf("context = %+v", evs[0].Context)
	}
	if evs[0].Status != evidence.StatusSkipped {
		t.Errorf("a blocked address must not be dialed: %+v", evs[0])
	}
}
