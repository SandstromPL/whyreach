//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
)

// hidden are covered with empty file systems inside the sandbox: the
// owner's files, other users' runtime directories and sockets, removable
// media, logs and crash reports, and the shared temporary directories.
var hidden = []string{"/home", "/root", "/run/user", "/run/media", "/run/log", "/media", "/mnt", "/srv", "/var/tmp", "/var/log", "/var/crash", "/var/mail", "/var/spool"}

// dropEnv are environment variables that never reach a command, whatever
// the harness passed: sockets and credentials of the owner's session.
var dropEnv = []string{"SSH_AUTH_SOCK", "SSH_AGENT_PID", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "GPG_AGENT_INFO", "CLAUDE_CODE_MESSAGING_SOCKET", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"}

var dropEnvSuffix = []string{"_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_API_KEY"}

type shellRecord struct {
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Exit    int       `json:"exit"`
	Command string    `json:"command"`
	Error   string    `json:"error,omitempty"`
}

func shell(args []string) int {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	root := fs.String("root", "", "the sandbox: the only writable directory")
	var ro listFlag
	fs.Var(&ro, "ro", "a directory to show read-only (repeatable)")
	dockerHost := fs.String("docker-host", "", "DOCKER_HOST inside the sandbox: the read-only proxy")
	logPath := fs.String("log", "", "append a JSON line per command here")
	bwrap := fs.String("bwrap", "/usr/bin/bwrap", "bubblewrap")
	if err := fs.Parse(args); err != nil {
		return 126
	}
	if fs.NArg() != 1 || *root == "" || *dockerHost == "" {
		fmt.Fprintln(os.Stderr, "benchguard shell: want --root, --docker-host and one command string")
		return 126
	}
	command := fs.Arg(0)
	rec := shellRecord{Start: time.Now().UTC(), Command: command}
	code, err := runSandboxed(*bwrap, *root, ro, *dockerHost, command)
	rec.End, rec.Exit = time.Now().UTC(), code
	if err != nil {
		rec.Error = err.Error()
		fmt.Fprintln(os.Stderr, "benchguard shell:", err)
	}
	if *logPath != "" {
		if b, err := json.Marshal(rec); err == nil {
			if f, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
				_, _ = f.Write(append(b, '\n'))
				_ = f.Close()
			}
		}
	}
	return code
}

func runSandboxed(bwrap, root string, ro []string, dockerHost, command string) (int, error) {
	filter, err := seccompFilter(runtime.GOARCH)
	if err != nil {
		return 126, err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return 126, err
	}
	defer func() { _ = pr.Close() }()
	if _, err := pw.Write(filter); err != nil {
		_ = pw.Close()
		return 126, err
	}
	_ = pw.Close()

	cwd, _ := os.Getwd()
	if cwd != root && !strings.HasPrefix(cwd, root+"/") {
		cwd = filepath.Join(root, "work")
	}
	a := []string{
		"--die-with-parent", "--new-session",
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
		"--hostname", "whyreach-bench",
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
	}
	for _, h := range hidden {
		if fi, err := os.Stat(h); err == nil && fi.IsDir() {
			a = append(a, "--tmpfs", h)
		}
	}
	// The Docker socket, wherever /var/run points: the seccomp filter
	// refuses Unix sockets anyway.
	var socks []string
	for _, s := range []string{"/run/docker.sock", "/var/run/docker.sock"} {
		if real, err := filepath.EvalSymlinks(s); err == nil && !slices.Contains(socks, real) {
			socks = append(socks, real)
			a = append(a, "--ro-bind", "/dev/null", real)
		}
	}
	a = append(a, "--bind", root, root)
	for _, d := range ro {
		a = append(a, "--ro-bind", d, d)
	}
	a = append(a,
		"--bind", filepath.Join(root, "tmp"), "/tmp",
		"--chdir", cwd,
		"--setenv", "DOCKER_HOST", dockerHost,
		"--cap-drop", "ALL",
		"--seccomp", "3",
		"--", "/bin/bash", "-c", command,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bwrap, a...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{pr} // fd 3
	cmd.Env = sandboxEnv(os.Environ(), dockerHost)
	if err := cmd.Start(); err != nil {
		return 126, fmt.Errorf("start bwrap: %w", err)
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	signal.Stop(sigs)
	close(sigs)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if st, ok := ee.Sys().(syscall.WaitStatus); ok && st.Signaled() {
			return 128 + int(st.Signal()), nil
		}
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 126, err
	}
	return 0, nil
}

func sandboxEnv(env []string, dockerHost string) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		drop := k == "DOCKER_HOST"
		for _, d := range dropEnv {
			drop = drop || k == d
		}
		for _, s := range dropEnvSuffix {
			drop = drop || strings.HasSuffix(k, s)
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return append(out, "DOCKER_HOST="+dockerHost)
}

// A classic BPF program for seccomp, as bwrap --seccomp reads it: an array
// of struct sock_filter in host byte order.
type sockFilter struct {
	code   uint16
	jt, jf uint8
	k      uint32
}

const (
	bpfLdWAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJgeK   = 0x35 // BPF_JMP | BPF_JGE | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K

	retAllow = 0x7fff0000
	retErrno = 0x00050000 // | errno
	retKill  = 0x80000000 // SECCOMP_RET_KILL_PROCESS

	afUnix = 1
	eperm  = 1
)

// seccompFilter refuses Unix sockets (the Docker socket, the owner's
// session bus and desktop), io_uring (which would get around the socket
// rule) and the kernel key rings, and kills anything on another syscall
// ABI.
func seccompFilter(goarch string) ([]byte, error) {
	var arch, sysSocket uint32
	var keys []uint32
	switch goarch {
	case "amd64":
		arch, sysSocket = 0xc000003e, 41 // AUDIT_ARCH_X86_64
		keys = []uint32{248, 249, 250}   // add_key, request_key, keyctl
	case "arm64":
		arch, sysSocket = 0xc00000b7, 198 // AUDIT_ARCH_AARCH64
		keys = []uint32{217, 218, 219}
	default:
		return nil, fmt.Errorf("no seccomp filter for %s: refusing to run unconfined", goarch)
	}
	denied := append([]uint32{425, 426, 427}, keys...) // io_uring_setup, _enter, _register

	// Layout: a header of 4, one jump per denied syscall, 3 for the socket
	// check, then the three returns.
	var p []sockFilter
	n := 4 + len(denied) + 3 // instructions before the returns
	idxAllow, idxErrno, idxKill := n, n+1, n+2
	jmp := func(at, to int) uint8 { return uint8(to - at - 1) }
	p = append(p,
		sockFilter{bpfLdWAbs, 0, 0, 4}, // arch
		sockFilter{bpfJeqK, 0, jmp(1, idxKill), arch},
		sockFilter{bpfLdWAbs, 0, 0, 0},                      // syscall number
		sockFilter{bpfJgeK, jmp(3, idxKill), 0, 0x40000000}, // x32 ABI
	)
	for _, nr := range denied {
		at := len(p)
		p = append(p, sockFilter{bpfJeqK, jmp(at, idxErrno), 0, nr})
	}
	at := len(p)
	p = append(p, sockFilter{bpfJeqK, 0, jmp(at, idxAllow), sysSocket})
	p = append(p,
		sockFilter{bpfLdWAbs, 0, 0, 16}, // args[0], low 32 bits
		sockFilter{bpfJeqK, jmp(len(p)+1, idxErrno), 0, afUnix},
	)
	p = append(p,
		sockFilter{bpfRetK, 0, 0, retAllow},
		sockFilter{bpfRetK, 0, 0, retErrno | eperm},
		sockFilter{bpfRetK, 0, 0, retKill},
	)
	// The socket check falls through to allow.
	if len(p) != n+3 {
		return nil, fmt.Errorf("seccomp program has %d instructions, want %d", len(p), n+3)
	}
	var buf bytes.Buffer
	for _, ins := range p {
		_ = binary.Write(&buf, binary.NativeEndian, ins.code)
		buf.WriteByte(ins.jt)
		buf.WriteByte(ins.jf)
		_ = binary.Write(&buf, binary.NativeEndian, ins.k)
	}
	return buf.Bytes(), nil
}
