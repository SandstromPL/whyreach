package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/SandstromPL/whyreach/internal/target"
)

// Entry is one line of the audit log: a tool call, its sanitized arguments,
// how long it took, how it ended and what it changed (INITIAL.md §4.9).
type Entry struct {
	Time            time.Time         `json:"time"`
	Client          string            `json:"client"` // cli or mcp
	Tool            string            `json:"tool"`
	Args            map[string]string `json:"args,omitempty"`
	Status          string            `json:"status"` // ok, an error code, or approved/declined for consent
	Error           string            `json:"error,omitempty"`
	DurationMS      float64           `json:"duration_ms"`
	Verdict         string            `json:"verdict,omitempty"`
	Primary         string            `json:"primary,omitempty"` // the primary finding's rule
	DiagnosisID     string            `json:"diagnosis_id,omitempty"`
	ProbeContainers bool              `json:"probe_containers"` // tier 2b was in effect
	ProbesSent      int               `json:"probes_sent"`
	ProbesDenied    int               `json:"probes_denied,omitempty"`
	SideEffects     []string          `json:"side_effects"`
}

// Audit appends entries to a JSON Lines file in whyreach's state directory.
// The directory is 0700 and the file 0600; past MaxBytes the file is
// rotated once, to <path>.1.
type Audit struct {
	path     string
	maxBytes int64
	mu       sync.Mutex
}

// DefaultAuditMax is where the audit log rotates.
const DefaultAuditMax = 10 << 20

// maxArg bounds each logged argument.
const maxArg = 256

// NewAudit returns an audit log at path.
func NewAudit(path string) *Audit { return &Audit{path: path, maxBytes: DefaultAuditMax} }

// Path is the log's location.
func (a *Audit) Path() string { return a.path }

// Write appends one entry.
func (a *Audit) Write(e Entry) error {
	for k, v := range e.Args {
		if v == "" {
			delete(e.Args, k)
			continue
		}
		e.Args[k] = sanitize(target.MaskArg(k, v))
	}
	e.Error = sanitize(target.MaskArg("error", e.Error))
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode audit entry: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	if st, err := os.Stat(a.path); err == nil && st.Size()+int64(len(b)) > a.maxBytes {
		if err := os.Rename(a.path, a.path+".1"); err != nil {
			return fmt.Errorf("rotate the audit log: %w", err)
		}
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// sanitize keeps arguments printable and short: they come from an agent
// and may carry anything. Write masks credentials first.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || unicode.Is(unicode.Cf, r) {
			return '�'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxArg {
		s = string(slices.Clip(r[:maxArg])) + "…"
	}
	return s
}
