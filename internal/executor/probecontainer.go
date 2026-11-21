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
	Reclaim(ctx context.Context, name string) (bool, error)
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
	imageRef string // set once the image is known to exist; forgotten when a create can't find it
}

// NewProbeContainer returns a probe-container executor that imports binary.
func NewProbeContainer(api ProbeAPI, binary, version string, logger *slog.Logger) *ProbeContainer {
	return &ProbeContainer{API: api, Binary: binary, Version: version, Logger: logger}
}

// Name is "probe-container".
func (p *ProbeContainer) Name() string { return evidence.ExecutorProbeContainer }

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
	failPrepare := func(err error) ([]evidence.Evidence, error) {
		status, code := evidence.StatusFailed, evidence.CodeDockerUnavailable
		if errors.Is(err, probe.ErrUnsupported) {
			status, code = evidence.StatusUnsupported, evidence.CodeUnsupported
		}
		return fail(status, code, err)
	}
	ref, err := p.prepare(ctx)
	if err != nil {
		return failPrepare(err)
	}
	specJSON, err := probe.EncodeSpecs(specs)
	if err != nil {
		return fail(evidence.StatusError, evidence.CodeInternal, err)
	}
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	name := "wr-probe-" + randomHex(4)
	cmd := append([]string{"--spec", specJSON, "--budget", probeBudget(ctx).String()}, probe.LimitsFrom(ctx).ProbeArgs()...)
	spec := docker.ProbeSpec{Name: name, Image: ref, NetnsOf: where.Container, Cmd: cmd}
	id, err := p.API.Create(ctx, spec)
	if errors.Is(err, docker.ErrNotFound) {
		// The image may be gone since prepare found it (docker image prune
		// -a during an MCP session): check for it again, importing it if
		// need be, and create once more within this run's deadline. A
		// target container that is gone fails the second create as well.
		p.forget(ref)
		if spec.Image, err = p.prepare(ctx); err != nil {
			return failPrepare(err)
		}
		id, err = p.API.Create(ctx, spec)
	}
	if err != nil {
		// The daemon may have created the container although its answer was
		// lost, for instance when the diagnosis was cancelled mid-request.
		p.reclaim(ctx, name)
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

// Bounds of the probe process's own time budget.
const (
	probeOverhead  = 1500 * time.Millisecond // create, start, wait, logs and remove around the probe
	minProbeBudget = 500 * time.Millisecond
)

// probeBudget is how long the probe process may take: what is left of ctx
// after the container's own overhead, capped at probe.Budget. A probe that
// outlived the executor's wait would lose results it had already gathered.
func probeBudget(ctx context.Context) time.Duration {
	budget := probe.Budget
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline)-probeOverhead)
	}
	return max(budget, minProbeBudget).Round(time.Millisecond)
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
		RecordSideEffect(ctx, fmt.Sprintf("ephemeral probe container %s (removal failed: %v; it is labeled %s=1 and a later run removes it)", name, err, docker.ProbeLabel))
		return
	}
	RecordSideEffect(ctx, "ephemeral probe container "+name+" (removed)")
}

// reclaim removes a probe container whose create request failed but may
// have succeeded on the daemon's side. It only touches a container with this
// exact name and the probe label.
func (p *ProbeContainer) reclaim(ctx context.Context, name string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	found, err := p.API.Reclaim(rctx, name)
	switch {
	case err != nil:
		p.logger().Warn("could not check for a half-created probe container", "name", name, "err", err)
		RecordSideEffect(ctx, fmt.Sprintf("ephemeral probe container %s may exist (its creation was interrupted; it is labeled %s=1 and a later run removes it)", name, docker.ProbeLabel))
	case found:
		RecordSideEffect(ctx, "ephemeral probe container "+name+" (creation interrupted; removed)")
	}
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

// prepare removes labeled leftovers of crashed runs (once per process, or
// until a sweep succeeds) and makes sure the probe image exists, importing
// it if needed. Success is remembered; a failure is retried by the next run.
func (p *ProbeContainer) prepare(ctx context.Context) (string, error) {
	p.prepMu.Lock()
	defer p.prepMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	if !p.swept {
		p.swept = p.sweep(ctx)
	}
	if p.imageRef != "" {
		return p.imageRef, nil
	}
	ref, err := p.ensureImage(ctx)
	if err != nil {
		return "", err
	}
	p.imageRef = ref
	return ref, nil
}

// forget drops the remembered image, so the next prepare checks for it
// again.
func (p *ProbeContainer) forget(ref string) {
	p.prepMu.Lock()
	defer p.prepMu.Unlock()
	if p.imageRef == ref {
		p.imageRef = ""
	}
}

// sweep removes labeled probes that a crashed or killed whyreach left
// behind. It reports whether the listing worked, so a failed sweep is
// retried by the next run.
func (p *ProbeContainer) sweep(ctx context.Context) bool {
	left, err := p.API.Leftovers(ctx, time.Now().Add(-leftoverAge))
	if err != nil {
		p.logger().Warn("could not list leftover probe containers", "err", err)
		return false
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
		RecordSideEffect(ctx, fmt.Sprintf("removed %d leftover probe container(s) from an earlier run", n))
	}
	return true
}

// ensureImage returns the probe image's reference, importing the image
// first if the daemon doesn't have it.
func (p *ProbeContainer) ensureImage(ctx context.Context) (string, error) {
	ref, tag, imported, err := p.image(ctx)
	if err != nil {
		return "", err
	}
	if imported {
		return ref, nil
	}
	if err := p.importImage(ctx, tag); err != nil {
		return "", err
	}
	RecordSideEffect(ctx, "imported image "+ref)
	return ref, nil
}

// image checks that the daemon's platform matches and that the binary can
// run on scratch, names the probe image after them, and asks the daemon
// whether it has that image: an image under the tag without the probe
// label isn't whyreach's, so it counts as not imported. ref and tag are set
// once the binary checks out, even when the inspect fails.
func (p *ProbeContainer) image(ctx context.Context) (ref, tag string, imported bool, err error) {
	v, err := p.API.Negotiate(ctx)
	if err != nil {
		return "", "", false, err
	}
	if v.Os != "linux" || v.Arch != runtime.GOARCH || runtime.GOOS != "linux" {
		return "", "", false, fmt.Errorf("the daemon runs %s/%s and this whyreach is %s/%s; probe binaries for other platforms arrive in v0.3: %w",
			v.Os, v.Arch, runtime.GOOS, runtime.GOARCH, probe.ErrUnsupported)
	}
	digest, err := checkBinary(p.Binary)
	if err != nil {
		return "", "", false, err
	}
	tag = ImageTag(p.Version, digest)
	ref = docker.ProbeImageRepo + ":" + tag
	img, err := p.API.ImageInspect(ctx, ref)
	switch {
	case err == nil:
		return ref, tag, img.Config.Labels[docker.ProbeLabel] == "1", nil
	case errors.Is(err, docker.ErrNotFound):
		return ref, tag, false, nil
	default:
		return ref, tag, false, fmt.Errorf("inspect %s: %w", ref, err)
	}
}

// Readiness is what running a probe container needs, checked without any
// Docker write: for whyreach doctor.
type Readiness struct {
	Image    string `json:"image"`    // whyreach-probe:<version>-<digest>
	Imported bool   `json:"imported"` // the image exists; otherwise the first probe imports it
}

// Readiness checks that the daemon's platform matches, that the binary is a
// static ELF that can run on scratch, and whether the image is imported. It
// never imports, sweeps or creates anything.
func (p *ProbeContainer) Readiness(ctx context.Context) (Readiness, error) {
	ref, _, imported, err := p.image(ctx)
	return Readiness{Image: ref, Imported: imported}, err
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
