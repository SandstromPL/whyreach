//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// TestReadInRootStaysInside: a container's files are read as the container
// sees them, and no symlink in it leads to the host's files.
func TestReadInRootStaysInside(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(filepath.Join(etc, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(etc, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("hosts", "10.0.0.1 api\n")
	write("big", strings.Repeat("x", 65))
	for link, target := range map[string]string{
		"absolute": "/etc/hosts",                 // means the container's own /etc/hosts
		"escape":   "../../../../../etc/passwd",  // ".." stops at the container's root
		"magic":    "/proc/self/root/etc/passwd", // whyreach's own root, through procfs
	} {
		if err := os.Symlink(target, filepath.Join(etc, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mkfifo(filepath.Join(etc, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()

	tests := []struct {
		path    string
		want    string // content; empty means an error containing errText
		errText string
	}{
		{path: "/etc/hosts", want: "10.0.0.1 api\n"},
		{path: "etc/hosts", want: "10.0.0.1 api\n"},
		{path: "/etc/absolute", want: "10.0.0.1 api\n"},
		{path: "/etc/escape", errText: "no such file"},
		{path: "/../../../etc/passwd", errText: "no such file"},
		{path: "/etc/magic", errText: "/etc/magic"},
		{path: "/etc/fifo", errText: "not a regular file"},
		{path: "/etc/dir", errText: "not a regular file"},
		{path: "/etc/big", errText: "larger than 64 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			done := make(chan struct{})
			var b []byte
			var err error
			go func() {
				defer close(done)
				b, err = readInRoot(fd, tt.path, 64)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("readInRoot blocked")
			}
			if tt.want != "" {
				if err != nil || string(b) != tt.want {
					t.Errorf("got %q, %v; want %q", b, err, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.errText) {
				t.Errorf("got %q, %v; want an error with %q", b, err, tt.errText)
			}
		})
	}
}

func withID(c evidence.ContextRef, id string) evidence.ContextRef {
	c.ID = id
	return c
}

type fakeInspector struct {
	c   evidence.Container
	err error
}

func (f fakeInspector) InspectContainer(context.Context, string) (evidence.Container, error) {
	return f.c, f.err
}

// TestNetnsRunRefusesWhatItCannotEnter: every way the executor can't get
// into the namespace comes back as one record per check that says why, and
// nothing runs.
func TestNetnsRunRefusesWhatItCannotEnter(t *testing.T) {
	id := strings.Repeat("ab", 32)
	where := evidence.ContextRef{Kind: evidence.ContextContainer, Container: id[:12], Name: "worker"}
	running := evidence.Container{ID: id, Name: "worker", State: evidence.StateRunning, Pid: os.Getpid()}
	tests := []struct {
		name       string
		where      evidence.ContextRef
		inspector  fakeInspector
		wantStatus evidence.Status
		wantCode   string
		wantText   string
	}{
		{
			name: "not a container", where: evidence.Host(),
			wantStatus: evidence.StatusError, wantCode: evidence.CodeInternal, wantText: "only enter a container",
		},
		{
			name: "container gone", where: where, inspector: fakeInspector{err: &docker.APIError{Status: 404, Message: "No such container"}},
			wantStatus: evidence.StatusFailed, wantCode: evidence.CodeNotFound, wantText: "no longer exists",
		},
		{
			name: "Docker unreachable", where: where, inspector: fakeInspector{err: errors.New("connection refused")},
			wantStatus: evidence.StatusFailed, wantCode: evidence.CodeDockerUnavailable, wantText: "look up worker",
		},
		{
			name: "another container", where: where, inspector: fakeInspector{c: evidence.Container{ID: strings.Repeat("cd", 32), State: evidence.StateRunning, Pid: 1}},
			wantStatus: evidence.StatusError, wantCode: evidence.CodeInternal, wantText: "got cdcdcdcdcdcd",
		},
		{
			// The full ID is known: a container whose ID only shares the
			// short one (or that Docker found by a name equal to it) is
			// another container.
			name: "another container with the same short ID", where: withID(where, id),
			inspector:  fakeInspector{c: evidence.Container{ID: id[:12] + strings.Repeat("ef", 26), State: evidence.StateRunning, Pid: 1}},
			wantStatus: evidence.StatusError, wantCode: evidence.CodeInternal, wantText: "asked Docker for container",
		},
		{
			name: "stopped", where: where, inspector: fakeInspector{c: evidence.Container{ID: id, Name: "worker", State: evidence.StateExited}},
			wantStatus: evidence.StatusFailed, wantCode: evidence.CodeNotFound, wantText: "worker is exited",
		},
		{
			// Docker's PID is whyreach's own process, whose cgroup names no
			// container: the PID check refuses it before anything is opened.
			name: "PID of another process", where: where, inspector: fakeInspector{c: running},
			wantStatus: evidence.StatusFailed, wantCode: evidence.CodeNotFound, wantText: "does not name container",
		},
	}
	specs := []probe.Spec{{Kind: probe.SpecDNS, Host: "api"}, {Kind: probe.SpecTCP, Host: "api", Port: 8080}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNetns(tt.inspector, nil)
			evs, err := n.Run(context.Background(), tt.where, specs)
			if err == nil {
				t.Error("want an error")
			}
			if len(evs) != len(specs) {
				t.Fatalf("%d records, want one per spec", len(evs))
			}
			for _, ev := range evs {
				if ev.Status != tt.wantStatus || ev.Err == nil || ev.Err.Code != tt.wantCode || !strings.Contains(ev.Err.Message, tt.wantText) {
					t.Errorf("%s: status %s err %+v; want %s/%s with %q", ev.Kind, ev.Status, ev.Err, tt.wantStatus, tt.wantCode, tt.wantText)
				}
				if ev.Context.Executor != evidence.ExecutorNetns || ev.Context.NetnsID != 0 {
					t.Errorf("context %+v, want executor netns and no namespace", ev.Context)
				}
			}
		})
	}
}

// TestNetnsEnterNeedsThePrivilege: without CAP_SYS_ADMIN, setns fails, f
// never runs, and the error keeps the errno.
func TestNetnsEnterNeedsThePrivilege(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root setns works: TestNetnsEnterRunsInsideAndComesBack covers it")
	}
	fd, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	h := &netnsHandle{ns: fd, root: -1, logger: slog.New(slog.DiscardHandler)}
	defer h.close()
	ran := false
	err = h.enter(func() { ran = true })
	if !errors.Is(err, unix.EPERM) || ran {
		t.Errorf("enter = %v (ran %v), want EPERM and f not run", err, ran)
	}
	if status, e := probe.Classify(err); status != evidence.StatusPermissionDenied || e.Errno != "EPERM" {
		t.Errorf("classified as %s %+v, want permission_denied with EPERM", status, e)
	}
}

// TestNetnsEnterRunsInsideAndComesBack needs root (make lab-root runs it):
// a socket created through enter lives in the other namespace, and every
// thread whyreach runs on afterwards is back in its own.
func TestNetnsEnterRunsInsideAndComesBack(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: make lab-root runs it")
	}
	home := threadNetns(t)
	fd, inode := newNetns(t)
	if inode == home {
		t.Fatal("the new namespace is whyreach's own")
	}
	h := &netnsHandle{ns: fd, root: -1, inode: inode, logger: slog.New(slog.DiscardHandler)}
	defer h.close()

	// Reachable from whyreach's own namespace; in a new namespace even
	// loopback is down, so a connect from there finds no route.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", ln.Addr().String()); err != nil {
		// In a fresh network namespace (unshare -Urn) loopback starts down,
		// so a connect fails in both namespaces and proves nothing.
		t.Skipf("whyreach's own namespace can't reach its loopback (%v): bring lo up first, as in unshare -Urn sh -c 'ip link set lo up && …'", err)
	} else {
		_ = c.Close()
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			var inside uint64
			var dialErr error
			err := h.enter(func() {
				inside = currentNetns()
				var c net.Conn
				c, dialErr = (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", ln.Addr().String())
				if c != nil {
					_ = c.Close()
				}
			})
			if err != nil {
				t.Errorf("enter: %v", err)
				return
			}
			if inside != inode {
				t.Errorf("f ran in namespace %d, want %d", inside, inode)
			}
			if !errors.Is(dialErr, syscall.ENETUNREACH) {
				t.Errorf("connect from the new namespace: %v, want ENETUNREACH (the socket was created elsewhere)", dialErr)
			}
		})
	}
	wg.Wait()

	// Sample the threads in Go's pool: none may be left in the namespace.
	for range 64 {
		wg.Go(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if got := currentNetns(); got != home {
				t.Errorf("a thread is in namespace %d after enter returned, want %d", got, home)
			}
		})
	}
	wg.Wait()
	if c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String()); err != nil {
		t.Errorf("connect from whyreach's own namespace: %v", err)
	} else {
		_ = c.Close()
	}
}

// currentNetns is the namespace of the calling thread.
func currentNetns() uint64 {
	link, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "net:["), "]"), 10, 64)
	return n
}

func threadNetns(t *testing.T) uint64 {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return currentNetns()
}

// newNetns creates a network namespace and returns a descriptor that keeps
// it, and its inode. The thread that created it goes back home first.
func newNetns(t *testing.T) (int, uint64) {
	t.Helper()
	type result struct {
		fd    int
		inode uint64
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		home, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			ch <- result{err: err}
			return
		}
		defer func() { _ = unix.Close(home) }()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			ch <- result{err: err}
			return
		}
		fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		inode := currentNetns()
		if serr := unix.Setns(home, unix.CLONE_NEWNET); serr != nil {
			ch <- result{err: serr} // stays locked: the thread dies with the goroutine
			return
		}
		runtime.UnlockOSThread()
		ch <- result{fd: fd, inode: inode, err: err}
	}()
	r := <-ch
	if r.err != nil {
		t.Fatal(&fs.PathError{Op: "create a network namespace", Path: "/proc/thread-self/ns/net", Err: r.err})
	}
	return r.fd, r.inode
}

// TestReadInRootRefusesPseudoFiles: procfs and sysfs files pass a
// regular-file check, but reading them can drain or block (/proc/kmsg), so
// a container that points its resolver files there gets a refusal.
func TestReadInRootRefusesPseudoFiles(t *testing.T) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	for _, path := range []string{"/proc/version", "/sys/kernel/uevent_seqnum"} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		b, err := readInRoot(fd, path, 1<<20)
		if err == nil || !strings.Contains(err.Error(), "whyreach doesn't read") {
			t.Errorf("readInRoot(%s) = %q, %v; want a refusal", path, b, err)
		}
	}
}

// TestNetnsEnterNeverMovesTheMainThread needs root, or a user namespace
// (unshare -Urn): with every enter holding a thread inside another
// namespace for a while, /proc/self, which describes the main thread for
// every reader, must keep showing whyreach's own namespace, and no f may
// run on the main thread.
func TestNetnsEnterNeverMovesTheMainThread(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: make lab-root runs it")
	}
	home, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	fd, inode := newNetns(t)
	h := &netnsHandle{ns: fd, root: -1, inode: inode, logger: slog.New(slog.DiscardHandler)}
	defer h.close()

	// One P makes it likely that an enter goroutine is scheduled on the
	// main thread, which is where the bug was.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	stop := make(chan struct{})
	readerDone := make(chan int)
	go func() {
		moved := 0
		for {
			select {
			case <-stop:
				readerDone <- moved
				return
			default:
			}
			if link, err := os.Readlink("/proc/self/ns/net"); err == nil && link != home {
				moved++
			}
			if id := probe.SelfNetnsID(); id != 0 && id == inode {
				moved++ // a host-side reader stamped the container's namespace
			}
			runtime.Gosched()
		}
	}()
	// Whether a burst's goroutines land on the main thread depends on
	// which thread holds the one P at the time, so try many bursts.
	var onMain atomic.Int64
	for range 30 {
		var wg sync.WaitGroup
		for range 50 {
			wg.Go(func() {
				err := h.enter(func() {
					if unix.Gettid() == unix.Getpid() {
						onMain.Add(1)
					}
					time.Sleep(time.Millisecond) // stands for a connect being awaited
				})
				if err != nil {
					t.Errorf("enter: %v", err)
				}
			})
		}
		wg.Wait()
	}
	close(stop)
	if moved := <-readerDone; moved != 0 || onMain.Load() != 0 {
		t.Errorf("the main thread left whyreach's namespace: %d reads saw the container's, %d calls ran on it", moved, onMain.Load())
	}
}

// TestNetnsHandleReadsEachFileOncePerBatch: every lookup of a batch shares
// one read of each file, so a container that grows its /etc/hosts costs one
// copy in memory, not one per lookup.
func TestNetnsHandleReadsEachFileOncePerBatch(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	hosts := filepath.Join(root, "etc", "hosts")
	if err := os.WriteFile(hosts, []byte("10.0.0.1 api\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	h := &netnsHandle{ns: -1, root: fd, logger: slog.New(slog.DiscardHandler)}
	defer h.close()
	read := func() string {
		f, err := h.open(context.Background(), "/etc/hosts")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		var b strings.Builder
		if _, err := io.Copy(&b, f); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if got := read(); got != "10.0.0.1 api\n" {
				t.Errorf("read %q", got)
			}
		})
	}
	wg.Wait()
	// The file changes; the batch keeps the one copy it read.
	if err := os.WriteFile(hosts, []byte("10.0.0.2 api\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "10.0.0.1 api\n" {
		t.Errorf("a second read in the same batch got %q: the file was read twice", got)
	}
	if len(h.files) != 1 {
		t.Errorf("%d reads, want 1", len(h.files))
	}
}
