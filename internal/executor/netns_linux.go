//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// Bounds of the netns executor.
const (
	inspectTimeout  = 3 * time.Second // the container lookup before entering (INITIAL.md §4.4)
	maxResolverFile = 1 << 20         // bytes read of a container's /etc/hosts or /etc/resolv.conf
)

// Run executes specs inside the network namespace of where, a running
// container. First it looks the container up for its current PID, checks
// that /proc/<pid>/cgroup names the container, opens the PID's network
// namespace and root directory, and checks the cgroup again: what it opened
// belonged to the container, and the open descriptors keep pointing there
// whatever happens to the PID afterwards. Every socket is then created on a
// locked thread inside that namespace (probe.Enter), and the resolver reads
// the container's own /etc/hosts and /etc/resolv.conf through its root,
// since the mount namespace stays whyreach's.
func (n *Netns) Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	fail := func(status evidence.Status, e *evidence.Error, err error) ([]evidence.Evidence, error) {
		return Failed(where, n.Name(), specs, status, e), err
	}
	failWith := func(status evidence.Status, code string, err error) ([]evidence.Evidence, error) {
		return fail(status, &evidence.Error{Code: code, Message: err.Error()}, err)
	}
	if where.Kind != evidence.ContextContainer || where.Container == "" {
		return failWith(evidence.StatusError, evidence.CodeInternal, errors.New("the netns executor can only enter a container's network namespace"))
	}
	ictx, cancel := context.WithTimeout(ctx, inspectTimeout)
	c, err := n.Docker.InspectContainer(ictx, where.Container)
	cancel()
	switch {
	case errors.Is(err, docker.ErrNotFound):
		return failWith(evidence.StatusFailed, evidence.CodeNotFound, fmt.Errorf("%s no longer exists: %w", where, err))
	case err != nil:
		return failWith(statusOf(ctx, err), evidence.CodeDockerUnavailable, fmt.Errorf("look up %s before entering its network namespace: %w", where, err))
	case !strings.HasPrefix(c.ID, where.Container):
		return failWith(evidence.StatusError, evidence.CodeInternal, fmt.Errorf("asked Docker for container %s, got %s", where.Container, evidence.ShortID(c.ID)))
	case !c.Running() || c.Pid <= 0:
		return failWith(evidence.StatusFailed, evidence.CodeNotFound, fmt.Errorf("%s is %s, so nothing can be tested from its network namespace; start it first", c.DisplayName(), c.State))
	}
	ns, err := openNetns(c.Pid, c.ID, n.logger())
	if err != nil {
		status, e := probe.Classify(err)
		return fail(status, e, err)
	}
	defer ns.close()

	env := probe.Env{
		ProcDir:  "/proc/thread-self", // read inside the namespace: the thread's, not the process's
		Resolver: &probe.Resolver{HostsPath: "/etc/hosts", ResolvPath: "/etc/resolv.conf", Open: ns.open, Enter: ns.enter},
		Limits:   probe.LimitsFrom(ctx),
		Enter:    ns.enter,
	}
	evs := probe.Run(ctx, env, specs)
	for i := range evs {
		evs[i].Context = where
		evs[i].Context.Executor = n.Name()
		evs[i].Context.NetnsID = ns.inode
		src := "setns into the network namespace of " + where.String() + " (netns executor)"
		if evs[i].Kind == evidence.KindDNS {
			src += ", whose own files were read through /proc/<pid>/root"
		}
		if evs[i].Source != "" {
			src = evs[i].Source + "; " + src
		}
		evs[i].Source = src
	}
	return evs, nil
}

func (n *Netns) logger() *slog.Logger {
	if n.Logger != nil {
		return n.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// netnsHandle holds a container's network namespace and root directory
// open for one batch.
type netnsHandle struct {
	ns     int    // /proc/<pid>/ns/net: it keeps the namespace, whatever the PID does next
	root   int    // /proc/<pid>/root, opened O_PATH: the container's root directory
	inode  uint64 // the namespace's inode, which identifies it (ContextRef.NetnsID)
	logger *slog.Logger
}

// openNetns opens what a batch needs from the container's process between
// two checks that the PID belongs to the container (probe.CheckPID), so a
// PID the kernel reused in the meantime fails the second one. It then
// enters the namespace once, so a missing privilege shows before any probe
// depends on it.
func openNetns(pid int, id string, logger *slog.Logger) (*netnsHandle, error) {
	if len(id) != 64 {
		return nil, fmt.Errorf("container ID %q is not a full ID, which the PID check needs", id)
	}
	if err := probe.CheckPID(pid, id); err != nil {
		return nil, err
	}
	h := &netnsHandle{ns: -1, root: -1, logger: logger}
	dir := "/proc/" + strconv.Itoa(pid)
	err := h.openFrom(dir)
	if err == nil {
		if err = probe.CheckPID(pid, id); err != nil {
			err = fmt.Errorf("pid %d changed while whyreach opened its namespace: %w", pid, err)
		}
	}
	if err == nil {
		err = h.enter(func() {})
	}
	if err != nil {
		h.close()
		return nil, err
	}
	return h, nil
}

func (h *netnsHandle) openFrom(dir string) error {
	ns, err := unix.Open(dir+"/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &fs.PathError{Op: "open", Path: dir + "/ns/net", Err: err}
	}
	h.ns = ns
	var st unix.Stat_t
	if err := unix.Fstat(ns, &st); err != nil {
		return &fs.PathError{Op: "stat", Path: dir + "/ns/net", Err: err}
	}
	h.inode = st.Ino
	root, err := unix.Open(dir+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &fs.PathError{Op: "open", Path: dir + "/root", Err: err}
	}
	h.root = root
	return nil
}

func (h *netnsHandle) close() {
	for _, fd := range []int{h.ns, h.root} {
		if fd >= 0 {
			_ = unix.Close(fd) // read-only descriptors: a close error changes nothing
		}
	}
	h.ns, h.root = -1, -1
}

// enter runs f on a locked OS thread inside the container's network
// namespace (probe.Enter). Each call gets a goroutine of its own, so calls
// can run in parallel, each on its own thread. It returns an error only
// when f did not run.
func (h *netnsHandle) enter(f func()) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		errc <- h.onThread(f)
	}()
	return <-errc
}

// onThread is enter's work on the locked thread. The thread goes back to
// the namespace it came from before it is unlocked. If that fails, it stays
// locked: Go ends a thread whose goroutine exits while locked to it, so no
// other goroutine ever runs in the container's namespace.
func (h *netnsHandle) onThread(f func()) error {
	home, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread() // nothing changed yet
		return &fs.PathError{Op: "open", Path: "/proc/thread-self/ns/net", Err: err}
	}
	defer func() { _ = unix.Close(home) }()
	if err := unix.Setns(h.ns, unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread() // setns failed, so the thread is where it was
		return fmt.Errorf("enter the network namespace: %w", err)
	}
	defer func() {
		if err := unix.Setns(home, unix.CLONE_NEWNET); err != nil {
			// f's results stand: they were observed in the right place.
			h.logger.Error("could not leave a container's network namespace; the thread is retired", "err", err)
			return
		}
		runtime.UnlockOSThread()
	}()
	f()
	return nil
}

// open reads one of the container's resolver files (probe.Resolver.Open)
// through its root directory, as the container sees it.
func (h *netnsHandle) open(path string) (io.ReadCloser, error) {
	b, err := readInRoot(h.root, path, maxResolverFile)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// readInRoot reads path inside the directory root as if root were "/":
// openat2 with RESOLVE_IN_ROOT resolves every symlink and ".." inside it, so
// a link in a container can't lead whyreach, as root, to the host's files.
// Only a regular file of at most limit bytes is read; anything else, such
// as a FIFO or a device, is opened with O_PATH alone and never for reading.
func readInRoot(root int, path string, limit int64) ([]byte, error) {
	fd, err := unix.Openat2(root, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if errors.Is(err, unix.ENOSYS) {
		return nil, fmt.Errorf("reading %s inside a container needs openat2 (Linux 5.6 or later): %w", path, probe.ErrUnsupported)
	}
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	// Reopen, for reading, the very file the O_PATH descriptor holds.
	f, err := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}
