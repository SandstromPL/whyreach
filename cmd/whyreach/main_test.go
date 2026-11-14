package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/internal/cli"
)

// TestMain lets the test binary stand in for whyreach: run with
// WHYREACH_TEST_MAIN=1, it is main, with its own arguments.
func TestMain(m *testing.M) {
	if os.Getenv("WHYREACH_TEST_MAIN") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// TestWiring checks that main's options reach the CLI; internal/cli tests
// the commands themselves.
func TestWiring(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute(context.Background(), []string{"version"}, cli.Options{Version: version, Stdout: &stdout, Stderr: &stderr})
	if code != cli.ExitNoProblem || !strings.Contains(stdout.String(), "whyreach dev") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

// serve starts this binary as `whyreach mcp serve`, with its config, state
// and data in a temporary home and a Docker socket that doesn't exist, so
// nothing outside the test is read or touched.
func serve(t *testing.T) (*exec.Cmd, *os.File, *bufio.Reader, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	cmd := exec.CommandContext(context.Background(), os.Args[0], "mcp", "serve", "--log-level", "info")
	cmd.Env = []string{
		"WHYREACH_TEST_MAIN=1", "HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "XDG_STATE_HOME=" + filepath.Join(home, "state"),
		"XDG_DATA_HOME=" + filepath.Join(home, "data"), "DOCKER_HOST=unix://" + filepath.Join(home, "no-docker.sock"),
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return cmd, in.(*os.File), bufio.NewReader(out), &stderr
}

// exitsPromptly waits for the server to exit on its own, within limit.
func exitsPromptly(t *testing.T, cmd *exec.Cmd, stderr *bytes.Buffer, limit time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Errorf("exit %d after stdin closed; stderr:\n%s", ee.ExitCode(), stderr)
		} else if err != nil {
			t.Error(err)
		}
		t.Logf("exited %s after stdin closed", time.Since(start).Round(time.Millisecond))
	case <-time.After(limit):
		_ = cmd.Process.Kill()
		t.Fatalf("still running %s after stdin closed; stderr:\n%s", limit, stderr)
	}
}

// TestMCPServeExitsOnStdinEOF: an MCP client on Windows runs the server
// through wsl.exe (INITIAL.md §3.7, item 6), and when the client goes away
// all the server sees is its input ending. It must then exit at once, with
// status 0, rather than linger in the distro: before any request, and in
// the middle of a session.
func TestMCPServeExitsOnStdinEOF(t *testing.T) {
	t.Run("before any request", func(t *testing.T) {
		cmd, in, _, stderr := serve(t)
		_ = in.Close()
		exitsPromptly(t, cmd, stderr, 3*time.Second)
	})
	t.Run("after initialize", func(t *testing.T) {
		cmd, in, out, stderr := serve(t)
		req := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"eof-test","version":"1"}}}` + "\n"
		if _, err := in.WriteString(req); err != nil {
			t.Fatal(err)
		}
		line, err := out.ReadBytes('\n')
		if err != nil {
			t.Fatalf("no answer to initialize: %v; stderr:\n%s", err, stderr)
		}
		var resp struct {
			ID     int `json:"id"`
			Result struct {
				ServerInfo struct{ Name string } `json:"serverInfo"`
			} `json:"result"`
		}
		if err := json.Unmarshal(line, &resp); err != nil || resp.ID != 1 || resp.Result.ServerInfo.Name != "whyreach" {
			t.Fatalf("initialize answered %s (%v)", line, err)
		}
		_ = in.Close()
		exitsPromptly(t, cmd, stderr, 3*time.Second)
	})
}
