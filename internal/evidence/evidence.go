// Package evidence holds what whyreach observed: typed evidence records, the
// store that numbers them, and the read-only View that rules evaluate.
//
// Evidence is a fact with provenance (where it was observed, by which
// executor, from which source). Findings are hypotheses built on top of it;
// they live in package rules and cite evidence by ID.
package evidence

import (
	"encoding/json"
	"fmt"
	"time"
)

// Status says whether a check produced an observation. It describes the
// collection, not the network: a refused TCP connect is an observation
// (StatusOK with Outcome "refused").
type Status string

// Collection statuses (INITIAL.md §4.2).
const (
	StatusOK               Status = "ok"                // observed; the payload holds the result
	StatusFailed           Status = "failed"            // attempted, but the environment prevented an observation
	StatusTimeout          Status = "timeout"           // ran out of time before observing anything
	StatusUnsupported      Status = "unsupported"       // impossible on this platform or runtime
	StatusPermissionDenied Status = "permission_denied" // needs a permission tier or OS privilege that is off
	StatusSkipped          Status = "skipped"           // not attempted because a precondition failed
	StatusError            Status = "error"             // internal error
)

// Kind names the type of an evidence record and of its payload.
type Kind string

// Evidence kinds and their payload types.
const (
	KindDockerVersion Kind = "docker.version"   // DockerVersion
	KindContainer     Kind = "docker.container" // Container
	KindListeners     Kind = "netns.listeners"  // Listeners
	KindDNS           Kind = "probe.dns"        // DNSProbe
	KindTCP           Kind = "probe.tcp"        // TCPProbe
	KindHostAddrs     Kind = "host.addrs"       // HostAddrs
)

// kindOrder fixes the order in which evidence is numbered, so that the same
// evidence always gets the same IDs.
var kindOrder = map[Kind]int{
	KindDockerVersion: 0,
	KindContainer:     1,
	KindHostAddrs:     2,
	KindListeners:     3,
	KindDNS:           4,
	KindTCP:           5,
}

// Context kinds and executor names for ContextRef.
const (
	ContextHost      = "host"
	ContextContainer = "container"

	ExecutorHost           = "host"
	ExecutorProbeContainer = "probe-container"
	ExecutorNetns          = "netns"
)

// ContextRef says where a check ran: in which network namespace, and how
// whyreach got there. Every address in output is qualified by one of these.
type ContextRef struct {
	Kind      string `json:"kind"`                // "host" or "container"
	Container string `json:"container,omitempty"` // short container ID; empty for the host
	Name      string `json:"name,omitempty"`      // display name: Compose service or container name
	NetnsID   uint64 `json:"netns_id,omitempty"`  // netns inode, when readable: proves two checks shared a netns
	Executor  string `json:"executor,omitempty"`  // how a probe ran there; empty for metadata and host-read data
}

// Host is the ContextRef of the machine whyreach runs on.
func Host() ContextRef { return ContextRef{Kind: ContextHost, Name: "host"} }

// InContainer is the ContextRef of a container's network namespace.
func InContainer(c Container) ContextRef {
	return ContextRef{Kind: ContextContainer, Container: ShortID(c.ID), Name: c.DisplayName()}
}

// String is the name used in prose: "worker", "host".
func (c ContextRef) String() string {
	if c.Name != "" {
		return c.Name
	}
	if c.Container != "" {
		return c.Container
	}
	return c.Kind
}

// Error describes why a check has no observation. Errno keeps the syscall
// error name (ECONNREFUSED, EACCES, …) because rules depend on it.
type Error struct {
	Code    string `json:"code"` // one of the Code* constants
	Message string `json:"message"`
	Errno   string `json:"errno,omitempty"`
}

// Error codes (INITIAL.md §4.14).
const (
	CodeInvalidArgument   = "invalid_argument"
	CodePolicyDenied      = "policy_denied"
	CodeDockerUnavailable = "docker_unavailable"
	CodePermissionDenied  = "permission_denied"
	CodeNotFound          = "not_found"
	CodeTimeout           = "timeout"
	CodeUnsupported       = "unsupported"
	CodeInternal          = "internal"
)

// Evidence is one observation with its provenance.
type Evidence struct {
	ID          string        // "ev-07", assigned by Store.Finalize
	Kind        Kind          // selects the payload type
	Context     ContextRef    // where the check ran or what it describes
	Subject     string        // what was checked: "api:8080", "container:worker"
	Status      Status        // whether there is an observation
	ObservedAt  time.Time     // when the check finished
	Duration    time.Duration // how long it took
	Data        any           // the payload: a value of the type listed for Kind
	Err         *Error        // why there is no observation; nil when Status is ok
	Limitations []string      // caveats a reader must know, e.g. "the app's libc may order addresses differently"
	Source      string        // provenance: "docker GET /containers/{id}/json", "/proc/<pid>/net/tcp{,6} read from the host"
}

// OK reports whether the record holds an observation.
func (e Evidence) OK() bool { return e.Status == StatusOK }

// wire is Evidence's JSON shape. Durations are reported in milliseconds.
type wire struct {
	ID          string          `json:"id"`
	Kind        Kind            `json:"kind"`
	Context     ContextRef      `json:"context"`
	Subject     string          `json:"subject"`
	Status      Status          `json:"status"`
	ObservedAt  time.Time       `json:"observed_at"`
	DurationMS  float64         `json:"duration_ms"`
	Data        json.RawMessage `json:"data,omitempty"`
	Err         *Error          `json:"error,omitempty"`
	Limitations []string        `json:"limitations,omitempty"`
	Source      string          `json:"source,omitempty"`
}

// MarshalJSON encodes the record with its payload under "data".
func (e Evidence) MarshalJSON() ([]byte, error) {
	w := wire{
		ID: e.ID, Kind: e.Kind, Context: e.Context, Subject: e.Subject, Status: e.Status,
		ObservedAt: e.ObservedAt, DurationMS: Millis(e.Duration), Err: e.Err,
		Limitations: e.Limitations, Source: e.Source,
	}
	if e.Data != nil {
		raw, err := json.Marshal(e.Data)
		if err != nil {
			return nil, fmt.Errorf("encode %s payload: %w", e.Kind, err)
		}
		w.Data = raw
	}
	return json.Marshal(w)
}

// UnmarshalJSON decodes a record and its payload into the type for its Kind.
// The probe container sends evidence to whyreach this way.
func (e *Evidence) UnmarshalJSON(b []byte) error {
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*e = Evidence{
		ID: w.ID, Kind: w.Kind, Context: w.Context, Subject: w.Subject, Status: w.Status,
		ObservedAt: w.ObservedAt, Duration: time.Duration(w.DurationMS * float64(time.Millisecond)),
		Err: w.Err, Limitations: w.Limitations, Source: w.Source,
	}
	if len(w.Data) == 0 || string(w.Data) == "null" {
		return nil
	}
	data, err := decodePayload(w.Kind, w.Data)
	if err != nil {
		return fmt.Errorf("decode %s payload: %w", w.Kind, err)
	}
	e.Data = data
	return nil
}

func decodePayload(k Kind, raw json.RawMessage) (any, error) {
	switch k {
	case KindDockerVersion:
		return decodeAs[DockerVersion](raw)
	case KindContainer:
		return decodeAs[Container](raw)
	case KindListeners:
		return decodeAs[Listeners](raw)
	case KindDNS:
		return decodeAs[DNSProbe](raw)
	case KindTCP:
		return decodeAs[TCPProbe](raw)
	case KindHostAddrs:
		return decodeAs[HostAddrs](raw)
	default:
		return nil, fmt.Errorf("unknown evidence kind %q", k)
	}
}

func decodeAs[T any](raw json.RawMessage) (T, error) {
	var v T
	err := json.Unmarshal(raw, &v)
	return v, err
}

// Millis converts a duration to milliseconds with microsecond precision.
func Millis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// ShortID is the 12-character form of a container ID.
func ShortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
