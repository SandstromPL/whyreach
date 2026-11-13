package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Probe containers: their image and the label that marks every Docker
// resource whyreach creates (tier 2b, INITIAL.md §3.3).
const (
	ProbeLabel     = "io.whyreach.probe"
	ProbeImageRepo = "whyreach-probe"
)

// Hardening of every probe container (INITIAL.md §3.3).
const (
	probeUser      = "65534:65534"
	probePidsLimit = 32
	probeMemory    = 32 << 20
)

// ProbeRoutes is the probe client's own allowlist: the probe container's
// lifecycle and the probe image, nothing else (INITIAL.md §4.8). GET
// /containers/json is there for the startup sweep of leftovers.
func ProbeRoutes() []Route {
	return []Route{
		route(http.MethodGet, "/version"),
		route(http.MethodGet, "/containers/json"),
		route(http.MethodPost, "/containers/create"),
		route(http.MethodPost, "/containers/{id}/start"),
		route(http.MethodPost, "/containers/{id}/wait"),
		route(http.MethodGet, "/containers/{id}/logs"),
		route(http.MethodDelete, "/containers/{id}"),
		{Method: http.MethodGet, Path: regexp.MustCompile(`^/images/` + ProbeImageRepo + `:[a-zA-Z0-9_.-]{1,128}/json$`)},
		{Method: http.MethodPost, Path: regexp.MustCompile(`^/images/create$`), Query: importOnly},
	}
}

// importOnly allows POST /images/create only as an import of the probe
// image from the request body: never a registry pull.
func importOnly(q url.Values) error {
	switch {
	case q.Has("fromImage"):
		return errors.New("registry pulls are not allowed")
	case q.Get("fromSrc") != "-":
		return errors.New("only imports from the request body are allowed")
	case q.Get("repo") != ProbeImageRepo:
		return fmt.Errorf("only the %s image may be imported", ProbeImageRepo)
	}
	return nil
}

// ProbeClient creates, runs and removes probe containers. It is constructed
// separately from the metadata client, with its own allowlist, and it only
// ever removes containers it created or that carry the probe label.
type ProbeClient struct {
	c     *Client
	mu    sync.Mutex
	owned map[string]bool
}

// NewProbeClient returns a probe client for a unix:// endpoint.
func NewProbeClient(endpoint string) (*ProbeClient, error) {
	c, err := New(endpoint, ProbeRoutes())
	if err != nil {
		return nil, err
	}
	return &ProbeClient{c: c, owned: map[string]bool{}}, nil
}

// Negotiate settles the API version.
func (p *ProbeClient) Negotiate(ctx context.Context) (Version, error) { return p.c.Negotiate(ctx) }

// Image is the part of an image inspect whyreach uses.
type Image struct {
	ID           string `json:"Id"`
	Os           string `json:"Os"`
	Architecture string `json:"Architecture"`
	Config       struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

// ImageInspect looks up a probe image ("whyreach-probe:<tag>").
func (p *ProbeClient) ImageInspect(ctx context.Context, ref string) (Image, error) {
	var img Image
	err := p.c.do(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil, "", &img)
	return img, err
}

// ImageImport imports a tar stream as the probe image tag, applying
// Dockerfile-style changes (ENTRYPOINT, LABEL). The daemon answers with a
// JSON progress stream, which is checked for an error.
func (p *ProbeClient) ImageImport(ctx context.Context, tag string, tar io.Reader, changes []string) error {
	q := url.Values{"fromSrc": {"-"}, "repo": {ProbeImageRepo}, "tag": {tag}, "changes": changes}
	resp, err := p.c.send(ctx, http.MethodPost, "/images/create", q, tar, "application/x-tar")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBody))
	for {
		var msg struct {
			Error       string `json:"error"`
			ErrorDetail *struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&msg); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("import %s:%s: read progress: %w", ProbeImageRepo, tag, err)
		}
		if msg.Error != "" {
			return fmt.Errorf("import %s:%s: %s", ProbeImageRepo, tag, msg.Error)
		}
	}
}

// ProbeSpec is what a probe container runs and where.
type ProbeSpec struct {
	Name    string            // container name, "wr-probe-…"
	Image   string            // "whyreach-probe:<tag>"
	Cmd     []string          // arguments for the image's entrypoint
	NetnsOf string            // full ID of the container whose network namespace to join
	Labels  map[string]string // extra labels; the probe label is always set
}

// Create creates a hardened probe container (INITIAL.md §3.3): uid 65534,
// no capabilities, read-only rootfs, no-new-privileges, pids and memory
// limits, no mounts, no environment, and no AutoRemove, so its logs survive
// until whyreach has read them (ADR 0001, amendment). The hardening is not
// configurable by callers.
func (p *ProbeClient) Create(ctx context.Context, spec ProbeSpec) (string, error) {
	if !strings.HasPrefix(spec.Image, ProbeImageRepo+":") {
		return "", fmt.Errorf("image %q is not a probe image: %w", spec.Image, ErrNotAllowed)
	}
	if spec.NetnsOf == "" {
		return "", errors.New("a probe container must join a container's network namespace")
	}
	labels := map[string]string{ProbeLabel: "1"}
	for k, v := range spec.Labels {
		if k != ProbeLabel {
			labels[k] = v
		}
	}
	body := map[string]any{
		"Image":           spec.Image,
		"Cmd":             spec.Cmd,
		"User":            probeUser,
		"Env":             []string{},
		"Labels":          labels,
		"Tty":             false,
		"AttachStdin":     false,
		"OpenStdin":       false,
		"NetworkDisabled": false,
		"HostConfig": map[string]any{
			"NetworkMode":    "container:" + spec.NetnsOf,
			"AutoRemove":     false,
			"CapDrop":        []string{"ALL"},
			"ReadonlyRootfs": true,
			"SecurityOpt":    []string{"no-new-privileges"},
			"PidsLimit":      probePidsLimit,
			"Memory":         probeMemory,
			"MemorySwap":     probeMemory,
			"Privileged":     false,
			"Binds":          []string{},
			"Mounts":         []any{},
			"RestartPolicy":  map[string]any{"Name": "no"},
			"LogConfig":      map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "1m"}},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"Id"`
	}
	q := url.Values{"name": {spec.Name}}
	if err := p.c.do(ctx, http.MethodPost, "/containers/create", q, strings.NewReader(string(b)), "application/json", &out); err != nil {
		return "", err
	}
	p.own(out.ID)
	return out.ID, nil
}

func (p *ProbeClient) own(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.owned[id] = true
}

func (p *ProbeClient) owns(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.owned[id]
}

// Start starts a probe container this client created.
func (p *ProbeClient) Start(ctx context.Context, id string) error {
	if !p.owns(id) {
		return fmt.Errorf("start %s: not a probe container of this process: %w", id, ErrNotAllowed)
	}
	return p.c.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil, "", nil)
}

// Wait blocks until the container stops and returns its exit code.
func (p *ProbeClient) Wait(ctx context.Context, id string) (int, error) {
	var out struct {
		StatusCode int `json:"StatusCode"`
		Error      *struct {
			Message string `json:"Message"`
		} `json:"Error"`
	}
	q := url.Values{"condition": {"not-running"}}
	if err := p.c.do(ctx, http.MethodPost, "/containers/"+id+"/wait", q, nil, "", &out); err != nil {
		return -1, err
	}
	if out.Error != nil && out.Error.Message != "" {
		return out.StatusCode, fmt.Errorf("wait %s: %s", id, out.Error.Message)
	}
	return out.StatusCode, nil
}

// Logs reads a stopped container's stdout and stderr, each up to limit
// bytes. Without a TTY the stream is multiplexed with 8-byte frame headers.
func (p *ProbeClient) Logs(ctx context.Context, id string, limit int) (stdout, stderr []byte, err error) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}}
	resp, err := p.c.send(ctx, http.MethodGet, "/containers/"+id+"/logs", q, nil, "")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return Demux(resp.Body, limit)
}

// Demux splits Docker's multiplexed log stream into stdout and stderr, each
// truncated at limit bytes.
func Demux(r io.Reader, limit int) (stdout, stderr []byte, err error) {
	br := bufio.NewReader(r)
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return stdout, stderr, nil
			}
			return stdout, stderr, fmt.Errorf("read log frame header: %w", err)
		}
		size := int64(binary.BigEndian.Uint32(hdr[4:]))
		var dst *[]byte
		switch hdr[0] {
		case 0, 1:
			dst = &stdout
		case 2:
			dst = &stderr
		default:
			return stdout, stderr, fmt.Errorf("log stream is not multiplexed (frame type %d)", hdr[0])
		}
		room := int64(max(limit-len(*dst), 0))
		chunk, err := io.ReadAll(io.LimitReader(br, min(size, room)))
		if err != nil {
			return stdout, stderr, fmt.Errorf("read log frame: %w", err)
		}
		*dst = append(*dst, chunk...)
		if rest := size - int64(len(chunk)); rest > 0 {
			if _, err := io.CopyN(io.Discard, br, rest); err != nil {
				return stdout, stderr, fmt.Errorf("skip log frame: %w", err)
			}
		}
	}
}

// Remove force-removes a probe container: one this client created, or a
// labeled leftover found by Leftovers. Anything else is refused.
func (p *ProbeClient) Remove(ctx context.Context, id string) error {
	if !p.owns(id) {
		return fmt.Errorf("remove %s: not a probe container: %w", id, ErrNotAllowed)
	}
	q := url.Values{"force": {"1"}}
	err := p.c.do(ctx, http.MethodDelete, "/containers/"+id, q, nil, "", nil)
	if errors.Is(err, ErrNotFound) {
		err = nil // already gone
	}
	if err == nil {
		p.mu.Lock()
		delete(p.owned, id)
		p.mu.Unlock()
	}
	return err
}

// Leftovers lists probe containers that a whyreach process which crashed or
// was killed left behind, and marks them removable: stopped ones created
// before cutoff. A running or younger probe may belong to a whyreach process
// that is still using it.
func (p *ProbeClient) Leftovers(ctx context.Context, cutoff time.Time) ([]Summary, error) {
	list, err := p.c.ListContainers(ctx, true, ProbeLabel+"=1")
	if err != nil {
		return nil, err
	}
	var out []Summary
	for _, s := range list {
		if s.Labels[ProbeLabel] != "1" || s.State == "running" || !time.Unix(s.Created, 0).Before(cutoff) {
			continue
		}
		p.own(s.ID)
		out = append(out, s)
	}
	return out, nil
}

// Reclaim removes the probe container with exactly this name, if one
// exists: the remains of a create request whose answer was lost. Only a
// container carrying the probe label is touched. It reports whether one was
// found.
func (p *ProbeClient) Reclaim(ctx context.Context, name string) (bool, error) {
	list, err := p.c.ListContainers(ctx, true, ProbeLabel+"=1")
	if err != nil {
		return false, err
	}
	for _, s := range list {
		if s.Name() == name && s.Labels[ProbeLabel] == "1" {
			p.own(s.ID)
			return true, p.Remove(ctx, s.ID)
		}
	}
	return false, nil
}
