package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/SandstromPL/whyreach/internal/engine"
)

// BundleSchema is the version of a report bundle's layout.
const BundleSchema = 1

// SaveOptions say where and how to write a report bundle.
type SaveOptions struct {
	Dir           string // the reports directory: $XDG_DATA_HOME/whyreach/reports
	Redact        bool
	RedactPrivate bool
	Home          string // replaced by ~ when redacting
	Version       string // whyreach's version, for the manifest
	Now           func() time.Time
}

// Saved describes a written bundle.
type Saved struct {
	Path     string         `json:"path"`
	Redacted bool           `json:"redacted"`
	Replaced map[string]int `json:"replaced" jsonschema:"how many values of each kind were replaced by pseudonyms"`
	Files    []string       `json:"files"`
}

// manifest is the bundle's manifest.json.
type manifest struct {
	Whyreach    string            `json:"whyreach"`
	Schema      int               `json:"schema"`
	DiagnosisID string            `json:"diagnosis_id"`
	CreatedAt   time.Time         `json:"created_at"`
	Redaction   redactionInfo     `json:"redaction"`
	SHA256      map[string]string `json:"sha256"`
}

type redactionInfo struct {
	Enabled     bool           `json:"enabled"`
	PrivateKept bool           `json:"private_addresses_kept"`
	Replaced    map[string]int `json:"replaced"`
}

var diagnosisID = regexp.MustCompile(`^dg-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$`)

// Save writes a diagnosis as a report bundle (INITIAL.md §4.12):
// manifest.json, diagnosis.json (without the evidence), evidence.jsonl and
// report.md, in a 0700 directory named after the diagnosis ID, which starts
// with its UTC time. Files are 0600. Saving the same diagnosis again with the
// same redaction returns the bundle already there.
func Save(d *engine.Diagnosis, o SaveOptions) (Saved, error) {
	if !diagnosisID.MatchString(d.ID) {
		return Saved{}, fmt.Errorf("diagnosis ID %q is not one whyreach made", d.ID)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	name := d.ID
	if !o.Redact {
		name += "-unredacted"
	}
	dir := filepath.Join(o.Dir, name)
	if prev, err := readSaved(dir); err == nil {
		return prev, nil
	}

	r := NewRedactor(o.RedactPrivate, o.Home)
	clean := func(s string) string { return s }
	if o.Redact {
		r.Learn(d)
		clean = r.Apply
	}
	diagJSON, err := redactJSON(d, clean, true, "evidence")
	if err != nil {
		return Saved{}, err
	}
	var evs bytes.Buffer
	for _, e := range d.Evidence {
		b, err := redactJSON(e, clean, false)
		if err != nil {
			return Saved{}, err
		}
		evs.Write(b)
		evs.WriteByte('\n')
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# whyreach diagnosis %s\n\n", d.ID)
	fmt.Fprintf(&md, "%s\n\n```\n", d.Summary)
	// Unsanitized here: redaction must see the values as learned, and
	// Sanitize runs once on the redacted whole below.
	renderText(&md, d)
	md.WriteString("```\n\n## Evidence\n\n")
	for _, e := range d.Evidence {
		fmt.Fprintf(&md, "- `%s` %s\n", e.ID, EvidenceLine(e))
	}
	if o.Redact {
		md.WriteString("\nPublic addresses, host names and container IDs are replaced by pseudonyms (ip-…, host-…, ctr-…) that are stable within this report only.\n")
	}
	files := map[string][]byte{
		"diagnosis.json": diagJSON,
		"evidence.jsonl": evs.Bytes(),
		"report.md":      []byte(Sanitize(clean(md.String()))),
	}
	m := manifest{
		Whyreach: o.Version, Schema: BundleSchema, DiagnosisID: d.ID, CreatedAt: o.Now().UTC(),
		Redaction: redactionInfo{Enabled: o.Redact, PrivateKept: !o.RedactPrivate, Replaced: r.Counts()},
		SHA256:    map[string]string{},
	}
	for f, b := range files {
		sum := sha256.Sum256(b)
		m.SHA256[f] = hex.EncodeToString(sum[:])
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Saved{}, err
	}
	files["manifest.json"] = append(mb, '\n')

	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return Saved{}, err
	}
	tmp, err := os.MkdirTemp(o.Dir, ".tmp-"+name+"-")
	if err != nil {
		return Saved{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }() // gone after the rename; cleans up a failed write
	for f, b := range files {
		if err := os.WriteFile(filepath.Join(tmp, f), b, 0o600); err != nil {
			return Saved{}, err
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		if prev, perr := readSaved(dir); perr == nil {
			return prev, nil // saved concurrently
		}
		return Saved{}, err
	}
	return savedOf(dir, m), nil
}

func savedOf(dir string, m manifest) Saved {
	files := []string{"diagnosis.json", "evidence.jsonl", "manifest.json", "report.md"}
	replaced := m.Redaction.Replaced
	if replaced == nil {
		replaced = map[string]int{}
	}
	return Saved{Path: dir, Redacted: m.Redaction.Enabled, Replaced: replaced, Files: files}
}

// readSaved describes a bundle that already exists.
func readSaved(dir string) (Saved, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json")) //nolint:gosec // G304: dir is whyreach's own reports directory plus a validated diagnosis ID
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Saved{}, err
		}
		return Saved{}, fmt.Errorf("read %s: %w", dir, err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Saved{}, fmt.Errorf("read %s: %w", dir, err)
	}
	return savedOf(dir, m), nil
}

// redactJSON encodes v, drops the top-level keys in drop, and passes every
// string value through clean. Redacted addresses are no longer addresses, so
// a redacted bundle decodes as plain JSON, not into whyreach's types.
func redactJSON(v any, clean func(string) string, indent bool, drop ...string) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	if m, ok := tree.(map[string]any); ok {
		for _, k := range drop {
			delete(m, k)
		}
	}
	tree = walk(tree, clean)
	if indent {
		out, err := json.MarshalIndent(tree, "", "  ")
		return append(out, '\n'), err
	}
	return json.Marshal(tree)
}

func walk(v any, clean func(string) string) any {
	switch t := v.(type) {
	case string:
		return clean(t)
	case []any:
		for i := range t {
			t[i] = walk(t[i], clean)
		}
		return t
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			t[k] = walk(t[k], clean)
		}
		return t
	default:
		return v
	}
}
