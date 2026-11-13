package report

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// readArchive returns the files of an export archive by name.
func readArchive(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = string(b)
	}
}

func TestBundlesListFindExport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	if got, err := ListBundles(dir); err != nil || len(got) != 0 {
		t.Fatalf("a missing directory has no bundles: %v, %v", got, err)
	}
	d := identifying()
	now := func() time.Time { return time.Date(2026, 11, 13, 10, 0, 1, 0, time.UTC) }
	raw, err := Save(d, SaveOptions{Dir: dir, Redact: false, Version: "test", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Save(d, SaveOptions{Dir: dir, Redact: true, Home: "/home/someone", Version: "test", Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".tmp-dg-x"), 0o700); err != nil {
		t.Fatal(err)
	}

	list, err := ListBundles(dir)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		ID, Verdict, Primary, From, To string
		Redacted                       bool
	}
	var got []row
	for _, b := range list {
		got = append(got, row{b.ID, b.Verdict, b.Primary, b.From, b.To, b.Redacted})
	}
	want := []row{
		{d.ID, "cause_identified", "WR020", "container:shop-worker-1", "api.corp.example:443", false},
		{d.ID, "cause_identified", "WR020", "container:shop-worker-1", "host-" + strings.TrimPrefix(list[1].To, "host-"), true},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("list (-want +got):\n%s", diff)
	}
	if strings.Contains(list[1].To, "corp.example") {
		t.Errorf("a redacted bundle's question is redacted: %q", list[1].To)
	}

	// The diagnosis ID finds the unredacted bundle, which holds everything.
	b, err := FindBundle(dir, d.ID)
	if err != nil || b.Path != raw.Path {
		t.Fatalf("FindBundle = %+v, %v", b, err)
	}
	if r, err := FindBundle(dir, d.ID+"-unredacted"); err != nil || r.Redacted {
		t.Errorf("by directory name: %+v, %v", r, err)
	}
	for _, bad := range []string{"../etc", "dg-20261113T100000Z-a1b2c3/../x", "dg-20261113T100000Z-zzzzzz"} {
		if _, err := FindBundle(dir, bad); err == nil {
			t.Errorf("FindBundle(%q) accepted it", bad)
		}
	}
	if _, err := FindBundle(dir, "dg-20991231T000000Z-abcdef"); !errors.Is(err, ErrNoBundle) {
		t.Errorf("a missing bundle: %v", err)
	}

	// The unredacted bundle reads back into the diagnosis it was made from.
	back, err := LoadDiagnosis(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != d.ID || len(back.Evidence) != len(d.Evidence) || back.Question != d.Question {
		t.Errorf("loaded %+v", back)
	}

	// Export redacts it afresh, into the reports directory only.
	ex, err := Export(b, ExportOptions{Dir: dir, Home: "/home/someone", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if ex.Path != filepath.Join(dir, d.ID+".tar.gz") || !ex.PrivateKept || ex.Replaced[ClassIP] == 0 {
		t.Errorf("exported %+v", ex)
	}
	files := readArchive(t, ex.Path)
	if len(files) != 5 { // the directory and its four files
		t.Errorf("archive holds %d entries", len(files))
	}
	all := strings.Join(mapValues(files), "\n")
	for _, secret := range []string{"203.0.113.7", "2001:db8::7", "api.corp.example", "/home/someone", strings.Repeat("3f", 6), "registry.corp.example"} {
		if strings.Contains(all, secret) {
			t.Errorf("the export leaks %q", secret)
		}
	}
	if !strings.Contains(all, "172.22.0.2") {
		t.Error("private addresses are kept unless asked")
	}
	if fi, err := os.Stat(ex.Path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("archive mode: %v, %v", fi, err)
	}

	ex, err = Export(b, ExportOptions{Dir: dir, RedactPrivate: true, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if all := strings.Join(mapValues(readArchive(t, ex.Path)), "\n"); strings.Contains(all, "172.22.0.2") || strings.Contains(all, "10.0.0.5") || ex.PrivateKept {
		t.Error("--redact-private must replace private addresses")
	}
}

// A bundle saved redacted through MCP is exported as it is, or with its
// private addresses replaced too when asked.
func TestExportRedactedBundle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	d := identifying()
	saved, err := Save(d, SaveOptions{Dir: dir, Redact: true, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := FindBundle(dir, d.ID)
	if err != nil || !b.Redacted || b.Path != saved.Path {
		t.Fatalf("FindBundle = %+v, %v", b, err)
	}
	if _, err := LoadDiagnosis(b); err == nil {
		t.Error("a redacted bundle doesn't decode into whyreach's types")
	}
	ex, err := Export(b, ExportOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	files := readArchive(t, ex.Path)
	orig, _ := os.ReadFile(filepath.Join(saved.Path, "report.md"))
	if files[d.ID+"/report.md"] != string(orig) || !ex.AlreadyMasked {
		t.Error("a redacted bundle is exported as saved")
	}
	ex, err = Export(b, ExportOptions{Dir: dir, RedactPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	files = readArchive(t, ex.Path)
	all := strings.Join(mapValues(files), "\n")
	if strings.Contains(all, "172.22.0.2") || strings.Contains(all, "10.0.0.5") || ex.PrivateKept {
		t.Errorf("private addresses survived: %+v", ex)
	}
	if !strings.Contains(files[d.ID+"/manifest.json"], `"private_addresses_kept": false`) {
		t.Errorf("manifest: %s", files[d.ID+"/manifest.json"])
	}
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// A bundle's ID goes into file names and archive entries: one whose
// manifest disagrees with its directory's name is refused, and left out of
// the list (M4 safety review).
func TestTamperedManifestIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	d := identifying()
	saved, err := Save(d, SaveOptions{Dir: dir, Redact: false, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(saved.Path, "manifest.json")
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tamper := range []func(string) string{
		func(m string) string { return strings.Replace(m, d.ID, "..", 1) },
		func(m string) string { return strings.Replace(m, d.ID, "", 1) },
		func(m string) string { return strings.Replace(m, d.ID, "dg-20261113T100000Z-ffffff", 1) },
		func(m string) string { return strings.Replace(m, `"enabled": false`, `"enabled": true`, 1) },
	} {
		if err := os.WriteFile(path, []byte(tamper(string(orig))), 0o600); err != nil {
			t.Fatal(err)
		}
		if b, err := FindBundle(dir, d.ID); err == nil {
			t.Errorf("a tampered manifest was accepted: %+v", b)
		}
		if list, _ := ListBundles(dir); len(list) != 0 {
			t.Errorf("a tampered bundle is listed: %+v", list)
		}
	}
}
