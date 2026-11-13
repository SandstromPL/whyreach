package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/SandstromPL/whyreach/internal/cli"
)

// TestWiring checks that main's options reach the CLI; internal/cli tests
// the commands themselves.
func TestWiring(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute(context.Background(), []string{"version"}, cli.Options{Version: version, Stdout: &stdout, Stderr: &stderr})
	if code != cli.ExitNoProblem || !strings.Contains(stdout.String(), "whyreach dev") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}
