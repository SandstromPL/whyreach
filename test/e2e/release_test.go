//go:build lab

package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// buildRelease builds what .goreleaser.yaml would for this machine's
// architecture: the static binary with the given version, the archive
// with LICENSE, README.md and demo/compose.yaml at its root, and
// checksums.txt.
func buildRelease(t *testing.T, root, dir, archive, version string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "whyreach")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-trimpath", "-ldflags", "-s -w -X main.version="+version, "-o", bin, "./cmd/whyreach")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name, src string
		mode      int64
	}{
		{"whyreach", bin, 0o755}, {"LICENSE", filepath.Join(root, "LICENSE"), 0o644},
		{"README.md", filepath.Join(root, "README.md"), 0o644}, {"demo/compose.yaml", filepath.Join(root, "demo", "compose.yaml"), 0o644},
	} {
		data, err := os.ReadFile(f.src)
		if err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(data)), ModTime: time.Now().Truncate(time.Second), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, archive), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+"  "+archive+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fromArchive returns a file from a release archive.
func fromArchive(t *testing.T, archive, name string) []byte {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("no %s in %s: %v", name, archive, err)
		}
		if h.Name == name {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
