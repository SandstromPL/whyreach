package executor

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// Probe container timings (INITIAL.md §4.4).
const (
	ProbeTimeout   = 8 * time.Second  // one probe container run, from create to logs
	cleanupTimeout = 3 * time.Second  // removal, under its own context
	leftoverAge    = 2 * time.Minute  // older labeled probes belong to no running whyreach
	stdoutLimit    = 1 << 20          // bytes of probe output read
	stderrLimit    = 16 << 10         // bytes of probe diagnostics read
	importTimeout  = 30 * time.Second // the one-time image import
)

// ProbeAPI is the part of docker.ProbeClient the executor uses.
type ProbeAPI interface {
	Negotiate(ctx context.Context) (docker.Version, error)
	ImageInspect(ctx context.Context, ref string) (docker.Image, error)
	ImageImport(ctx context.Context, tag string, tar io.Reader, changes []string) error
	Create(ctx context.Context, spec docker.ProbeSpec) (string, error)
	Start(ctx context.Context, id string) error
	Wait(ctx context.Context, id string) (int, error)
	Logs(ctx context.Context, id string, limit int) (stdout, stderr []byte, err error)
	Remove(ctx context.Context, id string) error
	Leftovers(ctx context.Context, cutoff time.Time) ([]docker.Summary, error)
}

// ProbeContainer runs probes in a hardened, short-lived container that joins
// the target container's network namespace, so the probe sees exactly what
// the app sees: its resolv.conf, its /etc/hosts, its sockets (ADR 0001).
// The image is whyreach's own static binary, imported FROM scratch; nothing
// is pulled from a registry. Every container is removed after its logs are
// read, on every path.
type ProbeContainer struct {
	API     ProbeAPI
	Binary  string // whyreach's own executable, imported as the probe image
	Version string // whyreach's version, part of the image tag
	Logger  *slog.Logger

	prepMu   sync.Mutex // serializes the sweep and the image check
	swept    bool
	imageRef string // set once the image is known to exist

	mu      sync.Mutex
	effects []string
}

// NewProbeContainer returns a probe-container executor that imports binary.
func NewProbeContainer(api ProbeAPI, binary, version string, logger *slog.Logger) *ProbeContainer {
	return &ProbeContainer{API: api, Binary: binary, Version: version, Logger: logger}
}

// Name is "probe-container".
func (p *ProbeContainer) Name() string { return evidence.ExecutorProbeContainer }

// SideEffects lists the Docker writes made so far, for the diagnosis's
// side_effects (INITIAL.md §3.3).
func (p *ProbeContainer) SideEffects() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.effects...)
}

func (p *ProbeContainer) record(effect string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.effects = append(p.effects, effect)
}

func (p *ProbeContainer) logger() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// Run executes specs in one probe container joined to where's network
// namespace. where must be a container.
func (p *ProbeContainer) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	fail := func(status evidence.Status, code string, err error) ([]evidence.Evidence, error) {
		return Failed(where, p.Name(), specs, status, &evidence.Error{Code: code, Message: err.Error()}), err
	}
	if where.Kind != evidence.ContextContainer || where.Container == "" {
		return fail(evidence.StatusError, evidence.CodeInternal, errors.New("a probe container can only join a container"))
	}
	ref, err := p.prepare(ctx)
	if err != nil {
		status, code := evidence.StatusFailed, evidence.CodeDockerUnavailable
		if errors.Is(err, probe.ErrUnsupported) {
			status, code = evidence.StatusUnsupported, evidence.CodeUnsupported
		}
		return fail(status, code, err)
	}
	specJSON, err := probe.EncodeSpecs(specs)
	if err != nil {
		return fail(evidence.StatusError, evidence.CodeInternal, err)
	}
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	name := "wr-probe-" + randomHex(4)
	id, err := p.API.Create(ctx, docker.ProbeSpec{
		Name: name, Image: ref, NetnsOf: where.Container,
		Cmd: []string{"--spec", specJSON},
	})
	if err != nil {
		return fail(statusOf(ctx, err), evidence.CodeDockerUnavailable, fmt.Errorf("create probe container: %w", err))
	}
	defer p.remove(ctx, id, name)

	if err := p.API.Start(ctx, id); err != nil {
		// Joining a container that isn't running fails here (ADR 0001).
		return fail(statusOf(ctx, err), evidence.CodeDockerUnavailable, fmt.Errorf("start probe container in %s: %w", where, err))
	}
	code, err := p.API.Wait(ctx, id)
	if err != nil {
		return fail(statusOf(ctx, err), evidence.CodeTimeout, fmt.Errorf("wait for probe container: %w", err))
	}
	stdout, stderr, err := p.API.Logs(ctx, id, stdoutLimit)
	if err != nil {
		return fail(statusOf(ctx, err), evidence.CodeDockerUnavailable, fmt.Errorf("read probe output: %w", err))
	}
	if code != 0 {
		return fail(evidence.StatusError, evidence.CodeInternal, fmt.Errorf("probe exited with status %d: %s", code, tail(stderr, stderrLimit)))
	}
	evs, err := decodeEvidence(stdout)
	if err != nil {
		return fail(evidence.StatusError, evidence.CodeInternal, err)
	}
	for i := range evs {
		netns := evs[i].Context.NetnsID
		evs[i].Context = where
		evs[i].Context.Executor = p.Name()
		evs[i].Context.NetnsID = netns
		evs[i].Source = strings.TrimSpace(evs[i].Source + " via probe container " + name)
	}
	return evs, nil
}

// statusOf tells a deadline from other failures.
func statusOf(ctx context.Context, err error) evidence.Status {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return evidence.StatusTimeout
	}
	return evidence.StatusFailed
}

// remove deletes the probe container under its own context, so a cancelled
// diagnosis still cleans up (INITIAL.md §4.7).
func (p *ProbeContainer) remove(ctx context.Context, id, name string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if err := p.API.Remove(rctx, id); err != nil {
		p.logger().Warn("could not remove probe container", "name", name, "err", err)
		p.record(fmt.Sprintf("ephemeral probe container %s (removal failed: %v; it is labeled %s=1 and the next run removes it)", name, err, docker.ProbeLabel))
		return
	}
	p.record("ephemeral probe container " + name + " (removed)")
}

func decodeEvidence(stdout []byte) ([]evidence.Evidence, error) {
	var out []evidence.Evidence
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 64<<10), stdoutLimit)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev evidence.Evidence
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("decode probe output: %w", err)
		}
		switch ev.Kind {
		case evidence.KindDNS, evidence.KindTCP, evidence.KindListeners:
		default:
			return nil, fmt.Errorf("probe output has unexpected kind %q", ev.Kind)
		}
		ev.ID = ""
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read probe output: %w", err)
	}
	return out, nil
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.TrimSpace(string(b))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b)
}

// prepare removes labeled leftovers of crashed runs (once per process) and
// makes sure the probe image exists, importing it if needed. Success is
// remembered; a failure is retried by the next run.
func (p *ProbeContainer) prepare(ctx context.Context) (string, error) {
	p.prepMu.Lock()
	defer p.prepMu.Unlock()
	if p.imageRef != "" {
		return p.imageRef, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	if !p.swept {
		p.sweep(ctx)
		p.swept = true
	}
	ref, err := p.ensureImage(ctx)
	if err != nil {
		return "", err
	}
	p.imageRef = ref
	return ref, nil
}

func (p *ProbeContainer) sweep(ctx context.Context) {
	left, err := p.API.Leftovers(ctx, time.Now().Add(-leftoverAge))
	if err != nil {
		p.logger().Warn("could not list leftover probe containers", "err", err)
		return
	}
	n := 0
	for _, s := range left {
		if err := p.API.Remove(ctx, s.ID); err != nil {
			p.logger().Warn("could not remove leftover probe container", "name", s.Name(), "err", err)
			continue
		}
		n++
	}
	if n > 0 {
		p.record(fmt.Sprintf("removed %d leftover probe container(s) from an earlier run", n))
	}
}

func (p *ProbeContainer) ensureImage(ctx context.Context) (string, error) {
	v, err := p.API.Negotiate(ctx)
	if err != nil {
		return "", err
	}
	if v.Os != "linux" || v.Arch != runtime.GOARCH || runtime.GOOS != "linux" {
		return "", fmt.Errorf("the daemon runs %s/%s and this whyreach is %s/%s; probe binaries for other platforms arrive in v0.3: %w",
			v.Os, v.Arch, runtime.GOOS, runtime.GOARCH, probe.ErrUnsupported)
	}
	digest, err := checkBinary(p.Binary)
	if err != nil {
		return "", err
	}
	tag := ImageTag(p.Version, digest)
	ref := docker.ProbeImageRepo + ":" + tag
	img, err := p.API.ImageInspect(ctx, ref)
	if err == nil && img.Config.Labels[docker.ProbeLabel] == "1" {
		return ref, nil
	}
	if err != nil && !errors.Is(err, docker.ErrNotFound) {
		return "", fmt.Errorf("inspect %s: %w", ref, err)
	}
	if err := p.importImage(ctx, tag); err != nil {
		return "", err
	}
	p.record("imported image " + ref)
	return ref, nil
}

// checkBinary verifies that the executable can run on scratch: a static
// Linux ELF for this architecture. It returns the file's SHA-256.
func checkBinary(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s is not a Linux executable: %w: %w", path, probe.ErrUnsupported, err)
	}
	defer func() { _ = f.Close() }()
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			return "", fmt.Errorf("%s is dynamically linked; the probe image needs a static build (CGO_ENABLED=0): %w", path, probe.ErrUnsupported)
		}
	}
	want := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH]
	if want != 0 && f.Machine != want {
		return "", fmt.Errorf("%s is built for %s, not %s: %w", path, f.Machine, runtime.GOARCH, probe.ErrUnsupported)
	}
	h := sha256.New()
	raw, err := os.Open(path) //nolint:gosec // G304: path is whyreach's own executable
	if err != nil {
		return "", err
	}
	defer func() { _ = raw.Close() }()
	if _, err := io.Copy(h, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var tagUnsafe = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

// ImageTag names the probe image after whyreach's version and the binary's
// digest: "0.1.0-3f2a9c1d0b7e". The digest makes development builds, which
// share a version string, import their own image instead of running a stale
// probe.
func ImageTag(version, digest string) string {
	v := strings.Trim(tagUnsafe.ReplaceAllString(version, "-"), ".-")
	if v == "" {
		v = "dev"
	}
	if len(v) > 64 {
		v = v[:64]
	}
	return v + "-" + digest[:min(12, len(digest))]
}

// importImage streams a one-file tar of the binary to the daemon as a
// FROM-scratch image.
func (p *ProbeContainer) importImage(ctx context.Context, tag string) error {
	f, err := os.Open(p.Binary)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		err := tw.WriteHeader(&tar.Header{Name: "whyreach", Mode: 0o555, Size: st.Size(), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg})
		if err == nil {
			_, err = io.Copy(tw, f)
		}
		if err == nil {
			err = tw.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	changes := []string{
		`ENTRYPOINT ["/whyreach", "__probe"]`,
		"LABEL " + docker.ProbeLabel + "=1",
		"USER 65534:65534",
	}
	if err := p.API.ImageImport(ctx, tag, pr, changes); err != nil {
		_ = pr.CloseWithError(err)
		return fmt.Errorf("import the probe image: %w", err)
	}
	return nil
}
