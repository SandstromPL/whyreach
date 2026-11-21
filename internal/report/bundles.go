package report

import (
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
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
	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Bundle is a saved report bundle, as `whyreach report list` shows it.
type Bundle struct {
	ID        string    `json:"id"` // the diagnosis ID
	Path      string    `json:"path"`
	Redacted  bool      `json:"redacted"`
	CreatedAt time.Time `json:"created_at"`
	Verdict   string    `json:"verdict"`
	Primary   string    `json:"primary,omitempty"` // the primary finding's rule
	From      string    `json:"from"`
	To        string    `json:"to"`
}

// bundleName is a bundle directory's name: a diagnosis ID, with
// "-unredacted" for a bundle saved without redaction.
var bundleName = regexp.MustCompile(`^(dg-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6})(-unredacted)?$`)

// ErrNoBundle is a bundle that isn't in the reports directory.
var ErrNoBundle = errors.New("no such report bundle")

// ListBundles lists the bundles in the reports directory, newest first. A
// missing directory has none; a directory that isn't a readable bundle is
// left out.
func ListBundles(dir string) ([]Bundle, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Bundle
	for _, e := range entries {
		if !e.IsDir() || !bundleName.MatchString(e.Name()) {
			continue
		}
		if b, err := readBundle(filepath.Join(dir, e.Name())); err == nil {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b Bundle) int {
		return cmp.Or(strings.Compare(b.ID, a.ID), cmp.Compare(boolInt(a.Redacted), boolInt(b.Redacted)))
	})
	return out, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ErrBadID is a reference that is neither a diagnosis ID nor a bundle
// directory's name: the caller's mistake, like ErrNoBundle.
var ErrBadID = errors.New("not a diagnosis ID")

// FindBundle returns the bundle that ref names: a diagnosis ID, or a bundle
// directory's name. A diagnosis saved both ways gives the unredacted
// bundle, which holds everything.
func FindBundle(dir, ref string) (Bundle, error) {
	ref = strings.TrimSpace(ref)
	m := bundleName.FindStringSubmatch(ref)
	if m == nil {
		return Bundle{}, fmt.Errorf("%q is %w such as dg-20261113T101500Z-3f2a9c", ref, ErrBadID)
	}
	names := []string{ref}
	if m[2] == "" {
		names = []string{ref + unredactedSuffix, ref}
	}
	for _, n := range names {
		b, err := readBundle(filepath.Join(dir, n))
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return Bundle{}, err
		}
	}
	return Bundle{}, fmt.Errorf("%w: %s in %s (whyreach report list shows the saved ones)", ErrNoBundle, ref, dir)
}

// readBundle describes the bundle in dir from its manifest and diagnosis.
// The ID comes from the directory's name, which the ID grammar validates;
// a manifest that names another diagnosis, or says otherwise about
// redaction, makes the bundle unreadable: its ID goes into file names and
// archive entries.
func readBundle(dir string) (Bundle, error) {
	name := bundleName.FindStringSubmatch(filepath.Base(dir))
	if name == nil {
		return Bundle{}, fmt.Errorf("%s is not a report bundle's directory", dir)
	}
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json")) //nolint:gosec // G304: dir is whyreach's reports directory plus a validated bundle name
	if err != nil {
		return Bundle{}, err
	}
	var m manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return Bundle{}, fmt.Errorf("read %s: %w", dir, err)
	}
	if m.DiagnosisID != name[1] || m.Redaction.Enabled == (name[2] != "") {
		return Bundle{}, fmt.Errorf("read %s: its manifest doesn't match the directory's name", dir)
	}
	db, err := os.ReadFile(filepath.Join(dir, "diagnosis.json")) //nolint:gosec // G304: as above
	if err != nil {
		return Bundle{}, err
	}
	// Decoded loosely: a redacted bundle's addresses are pseudonyms.
	var d struct {
		Verdict  string `json:"verdict"`
		Question struct {
			From struct {
				Ref string `json:"ref"`
			} `json:"from"`
			To struct {
				Host string `json:"host"`
				Port int    `json:"port"`
			} `json:"to"`
		} `json:"question"`
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(db, &d); err != nil {
		return Bundle{}, fmt.Errorf("read %s: %w", dir, err)
	}
	b := Bundle{
		ID: name[1], Path: dir, Redacted: m.Redaction.Enabled, CreatedAt: m.CreatedAt, Verdict: d.Verdict,
		From: d.Question.From.Ref, To: d.Question.To.Host + ":" + fmt.Sprint(d.Question.To.Port),
	}
	if strings.Contains(d.Question.To.Host, ":") {
		b.To = "[" + d.Question.To.Host + "]:" + fmt.Sprint(d.Question.To.Port)
	}
	if len(d.Findings) > 0 {
		b.Primary = d.Findings[0].RuleID
	}
	return b, nil
}

// ReadReport returns a bundle's report.md.
func ReadReport(b Bundle) ([]byte, error) {
	return os.ReadFile(filepath.Join(b.Path, "report.md"))
}

// ExportOptions say how to export a bundle.
type ExportOptions struct {
	Dir           string // the reports directory, where the archive goes
	RedactPrivate bool   // replace private (RFC 1918) addresses too
	Home          string // replaced by ~
	Version       string
	Now           func() time.Time
}

// Exported describes an export archive.
type Exported struct {
	Path          string         `json:"path"`
	From          string         `json:"from"` // the bundle it was made from
	PrivateKept   bool           `json:"private_addresses_kept"`
	Replaced      map[string]int `json:"replaced"`
	AlreadyMasked bool           `json:"already_redacted"` // the bundle was redacted when saved
}

// Export writes a redacted copy of a bundle, to attach to an issue, as
// <id>.tar.gz in the reports directory (INITIAL.md §4.12): the four files
// under a directory named after the diagnosis. An unredacted bundle is
// redacted afresh, under a new key; a bundle that was redacted when saved
// (save_report) is copied, with its private addresses replaced too when
// RedactPrivate asks for it. Nothing is written outside whyreach's data
// directory.
func Export(b Bundle, o ExportOptions) (Exported, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	var files map[string][]byte
	var m manifest
	var err error
	if b.Redacted {
		files, m, err = reRedact(b, o)
	} else {
		var d *engine.Diagnosis
		if d, err = LoadDiagnosis(b); err == nil {
			files, m, err = render(d, SaveOptions{Redact: true, RedactPrivate: o.RedactPrivate, Home: o.Home, Version: o.Version, Now: o.Now})
		}
	}
	if err != nil {
		return Exported{}, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// Whole seconds, truncated: tar rounds to the nearest one otherwise,
	// and a time in the future makes tar warn when it is extracted at once.
	mtime := m.CreatedAt.Truncate(time.Second)
	names := []string{"manifest.json", "diagnosis.json", "evidence.jsonl", "report.md"}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: b.ID + "/", Mode: 0o755, ModTime: mtime}); err != nil {
		return Exported{}, err
	}
	for _, n := range names {
		data := files[n]
		h := &tar.Header{Typeflag: tar.TypeReg, Name: b.ID + "/" + n, Mode: 0o644, Size: int64(len(data)), ModTime: mtime}
		if err := tw.WriteHeader(h); err != nil {
			return Exported{}, err
		}
		if _, err := tw.Write(data); err != nil {
			return Exported{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Exported{}, err
	}
	if err := gz.Close(); err != nil {
		return Exported{}, err
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return Exported{}, err
	}
	path := filepath.Join(o.Dir, b.ID+".tar.gz")
	tmp, err := os.CreateTemp(o.Dir, ".tmp-"+b.ID+"-*.tar.gz")
	if err != nil {
		return Exported{}, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone after the rename
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return Exported{}, err
	}
	if err := tmp.Close(); err != nil {
		return Exported{}, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return Exported{}, err
	}
	replaced := m.Redaction.Replaced
	if replaced == nil {
		replaced = map[string]int{}
	}
	return Exported{Path: path, From: b.Path, PrivateKept: m.Redaction.PrivateKept, Replaced: replaced, AlreadyMasked: b.Redacted}, nil
}

// LoadDiagnosis reads an unredacted bundle back into a diagnosis, evidence
// included. A redacted bundle doesn't decode into whyreach's types: its
// addresses are pseudonyms.
func LoadDiagnosis(b Bundle) (*engine.Diagnosis, error) {
	if b.Redacted {
		return nil, fmt.Errorf("%s is redacted: its addresses are pseudonyms", b.Path)
	}
	db, err := os.ReadFile(filepath.Join(b.Path, "diagnosis.json"))
	if err != nil {
		return nil, err
	}
	var d engine.Diagnosis
	if err := json.Unmarshal(db, &d); err != nil {
		return nil, fmt.Errorf("read %s: %w", b.Path, err)
	}
	f, err := os.Open(filepath.Join(b.Path, "evidence.jsonl"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		var e evidence.Evidence
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("read %s: evidence: %w", b.Path, err)
		}
		d.Evidence = append(d.Evidence, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if d.ID != b.ID {
		return nil, fmt.Errorf("%s holds diagnosis %q", b.Path, d.ID)
	}
	return &d, nil
}

// reRedact copies a bundle that was redacted when saved. Its host names and
// container IDs are pseudonyms already; when o.RedactPrivate asks for it and
// the bundle kept private addresses, those are replaced now, in every file.
func reRedact(b Bundle, o ExportOptions) (map[string][]byte, manifest, error) {
	files := map[string][]byte{}
	for _, n := range []string{"manifest.json", "diagnosis.json", "evidence.jsonl", "report.md"} {
		data, err := os.ReadFile(filepath.Join(b.Path, n)) //nolint:gosec // G304: a bundle FindBundle validated
		if err != nil {
			return nil, manifest{}, err
		}
		files[n] = data
	}
	var m manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		return nil, manifest{}, fmt.Errorf("read %s: %w", b.Path, err)
	}
	if !o.RedactPrivate || !m.Redaction.PrivateKept {
		return files, m, nil
	}
	r := NewRedactor(true, o.Home)
	for _, n := range []string{"diagnosis.json", "evidence.jsonl", "report.md"} {
		r.ipText(string(files[n]))
	}
	clean := func(s string) string { return r.Apply(s) }
	dj, err := cleanJSON(files["diagnosis.json"], clean, true)
	if err != nil {
		return nil, manifest{}, err
	}
	var evs bytes.Buffer
	for _, line := range bytes.Split(bytes.TrimSpace(files["evidence.jsonl"]), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		cl, err := cleanJSON(line, clean, false)
		if err != nil {
			return nil, manifest{}, err
		}
		evs.Write(cl)
		evs.WriteByte('\n')
	}
	out := map[string][]byte{"diagnosis.json": dj, "evidence.jsonl": evs.Bytes(), "report.md": []byte(clean(string(files["report.md"])))}
	m.Redaction.PrivateKept = false
	if m.Redaction.Replaced == nil {
		m.Redaction.Replaced = map[string]int{}
	}
	for k, v := range r.Counts() {
		m.Redaction.Replaced[k] += v
	}
	if err := m.seal(out); err != nil {
		return nil, manifest{}, err
	}
	return out, m, nil
}

// cleanJSON drops the top-level keys in drop from an encoded JSON value and
// passes every string value left through clean, indented or not.
func cleanJSON(b []byte, clean func(string) string, indent bool, drop ...string) ([]byte, error) {
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
