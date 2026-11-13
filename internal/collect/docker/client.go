// Package docker is whyreach's Docker Engine API client: hand-written, over
// the daemon's unix socket, and restricted to an allowlist of method + path
// patterns. "GET only" would not be enough (GET /containers/{id}/export
// dumps a whole filesystem), so every request must match a listed route
// before it is sent. There is no Docker SDK (INITIAL.md §4.8).
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// API versions whyreach speaks. It negotiates the lower of MaxAPIVersion and
// the daemon's version, and refuses daemons older than MinAPIVersion.
const (
	MinAPIVersion = "1.41" // Docker Engine 20.10
	MaxAPIVersion = "1.56" // Docker Engine 29.x, the version the lab runs on
)

// DefaultSocket is Docker Engine's socket on Linux.
const DefaultSocket = "/var/run/docker.sock"

// Errors callers branch on.
var (
	ErrUnavailable = errors.New("the Docker API is unavailable")
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("conflict")
	ErrNotAllowed  = errors.New("request is not on whyreach's Docker API allowlist")
	ErrUnsupported = errors.New("unsupported Docker API")
)

// APIError is a non-2xx answer from the daemon.
type APIError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("docker %s %s: %d %s", e.Method, e.Path, e.Status, e.Message)
}

// Is lets callers test errors.Is(err, ErrNotFound) and errors.Is(err, ErrConflict).
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Status == http.StatusNotFound
	case ErrConflict:
		return e.Status == http.StatusConflict
	}
	return false
}

// Route is one allowed request: an HTTP method and a pattern for the path
// without the /v1.xx prefix. Query, if set, must accept the query string.
type Route struct {
	Method string
	Path   *regexp.Regexp
	Query  func(url.Values) error
}

// idPattern matches container IDs and names.
const idPattern = `[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}`

func route(method, path string) Route {
	return Route{Method: method, Path: regexp.MustCompile("^" + strings.ReplaceAll(path, "{id}", idPattern) + "$")}
}

// ReadRoutes is the default allowlist: metadata reads only (INITIAL.md §4.8).
func ReadRoutes() []Route {
	return []Route{
		route(http.MethodGet, "/version"),
		route(http.MethodGet, "/containers/json"),
		route(http.MethodGet, "/containers/{id}/json"),
		route(http.MethodGet, "/networks"),
		route(http.MethodGet, "/networks/{id}"),
	}
}

// Client talks to one Docker endpoint through an allowlist.
type Client struct {
	http     *http.Client
	endpoint string // "unix:///var/run/docker.sock"
	version  string // negotiated; empty until Negotiate
}

// Endpoint picks the daemon to talk to: DOCKER_HOST when set, otherwise
// Docker Engine's default socket. Only unix sockets are supported for now.
func Endpoint(getenv func(string) string) (string, error) {
	host := getenv("DOCKER_HOST")
	if host == "" {
		return "unix://" + DefaultSocket, nil
	}
	if _, ok := strings.CutPrefix(host, "unix://"); ok {
		return host, nil
	}
	return "", fmt.Errorf("DOCKER_HOST=%s: only unix:// endpoints are supported: %w", host, ErrUnsupported)
}

// New returns a client for a unix:// endpoint that only sends requests
// matching routes.
func New(endpoint string, routes []Route) (*Client, error) {
	path, ok := strings.CutPrefix(endpoint, "unix://")
	if !ok || path == "" {
		return nil, fmt.Errorf("endpoint %q: %w", endpoint, ErrUnsupported)
	}
	dialer := &net.Dialer{}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", path)
		},
		DisableCompression: true,
		MaxIdleConns:       4,
	}
	return &Client{
		http:     &http.Client{Transport: &allowlist{next: tr, routes: routes}},
		endpoint: endpoint,
	}, nil
}

// Endpoint is the endpoint this client talks to.
func (c *Client) Endpoint() string { return c.endpoint }

// APIVersion is the negotiated version, or "" before Negotiate.
func (c *Client) APIVersion() string { return c.version }

// allowlist refuses any request that matches no route, before it is sent.
type allowlist struct {
	next   http.RoundTripper
	routes []Route
}

var versionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+(/|$)`)

func (a *allowlist) RoundTrip(req *http.Request) (*http.Response, error) {
	path := versionPrefix.ReplaceAllString(req.URL.Path, "/")
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, ErrNotAllowed)
	}
	for _, r := range a.routes {
		if r.Method != req.Method || !r.Path.MatchString(path) {
			continue
		}
		if r.Query != nil {
			if err := r.Query(req.URL.Query()); err != nil {
				return nil, fmt.Errorf("%s %s: %w: %w", req.Method, path, ErrNotAllowed, err)
			}
		}
		return a.next.RoundTrip(req)
	}
	return nil, fmt.Errorf("%s %s: %w", req.Method, path, ErrNotAllowed)
}

// Version is the part of GET /version whyreach uses.
type Version struct {
	Platform struct {
		Name string `json:"Name"`
	} `json:"Platform"`
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	Os            string `json:"Os"`
	Arch          string `json:"Arch"`
	KernelVersion string `json:"KernelVersion"`
}

// Desktop reports a Docker Desktop daemon, whose containers live in a VM.
func (v Version) Desktop() bool { return strings.Contains(v.Platform.Name, "Desktop") }

// Negotiate asks the daemon for its version (an unversioned request) and
// settles the API version for later calls.
func (c *Client) Negotiate(ctx context.Context) (Version, error) {
	var v Version
	if err := c.do(ctx, http.MethodGet, "/version", nil, nil, "", &v); err != nil {
		return Version{}, err
	}
	if v.APIVersion == "" {
		return v, fmt.Errorf("daemon reported no API version: %w", ErrUnsupported)
	}
	if compareVersions(v.APIVersion, MinAPIVersion) < 0 {
		return v, fmt.Errorf("daemon API %s is older than %s: %w", v.APIVersion, MinAPIVersion, ErrUnsupported)
	}
	c.version = MaxAPIVersion
	if compareVersions(v.APIVersion, MaxAPIVersion) < 0 {
		c.version = v.APIVersion
	}
	return v, nil
}

// compareVersions compares "major.minor" API versions.
func compareVersions(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersion(s string) [2]int {
	major, minor, _ := strings.Cut(s, ".")
	a, _ := strconv.Atoi(major)
	b, _ := strconv.Atoi(minor)
	return [2]int{a, b}
}

// maxBody bounds any JSON answer whyreach reads.
const maxBody = 32 << 20

// do sends one request and decodes a JSON answer into out (if not nil).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string, out any) error {
	resp, err := c.send(ctx, method, path, query, body, contentType)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
		return fmt.Errorf("docker %s %s: decode: %w", method, path, err)
	}
	return nil
}

// send performs a request and returns the response of a 2xx answer; the
// caller closes its body.
func (c *Client) send(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string) (*http.Response, error) {
	u := url.URL{Scheme: "http", Host: "docker", Path: path, RawQuery: query.Encode()}
	if c.version != "" {
		u.Path = "/v" + c.version + path
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrNotAllowed) || ctx.Err() != nil {
			return nil, err
		}
		return nil, unavailable(c.endpoint, err)
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var m struct {
		Message string `json:"message"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if json.Unmarshal(b, &m) != nil || m.Message == "" {
		m.Message = strings.TrimSpace(string(b))
	}
	return nil, &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: m.Message}
}

// unavailable wraps a transport error so callers can test for
// ErrUnavailable while the errno (EACCES, ENOENT, ECONNREFUSED) survives.
func unavailable(endpoint string, err error) error {
	hint := ""
	switch {
	case errors.Is(err, syscall.EACCES), errors.Is(err, os.ErrPermission):
		hint = " (permission denied: is the user in the docker group?)"
	case errors.Is(err, syscall.ENOENT), errors.Is(err, os.ErrNotExist):
		hint = " (no socket: is Docker running?)"
	}
	return fmt.Errorf("%s%s: %w: %w", endpoint, hint, ErrUnavailable, err)
}
