//go:build linux

package probe

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// ReadListeners returns the listening TCP sockets of the network namespace
// that procDir belongs to: "/proc" for the caller's own netns, "/proc/<pid>"
// for another process's. A missing tcp6 table (IPv6 disabled) is not an error.
func ReadListeners(procDir string) ([]evidence.Socket, error) {
	var out []evidence.Socket
	for _, proto := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(procDir, "net", proto)) //nolint:gosec // G304: procDir is "/proc" or "/proc/<pid>", built from an integer PID
		if err != nil {
			if proto == "tcp6" && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		socks, err := ParseListeners(f, proto)
		_ = f.Close() // read-only: a close error changes nothing
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", f.Name(), err)
		}
		out = append(out, socks...)
	}
	evidence.SortSockets(out)
	return out, nil
}

// ContainerListeners reads a container's listening sockets from the host
// through /proc/<pid>/net/tcp{,6}. This needs no root on Linux Docker Engine
// (ADR 0001). Before and after the read it checks that /proc/<pid>/cgroup
// names the container, so a reused PID can't make whyreach report another
// process's sockets.
func ContainerListeners(pid int, containerID string) ([]evidence.Socket, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("container %s has no process: %w", evidence.ShortID(containerID), ErrNoProcess)
	}
	if len(containerID) < 12 {
		return nil, fmt.Errorf("container ID %q is too short to verify the PID", containerID)
	}
	dir := "/proc/" + strconv.Itoa(pid)
	if err := checkCgroup(dir, containerID); err != nil {
		return nil, err
	}
	socks, err := ReadListeners(dir)
	if err != nil {
		return nil, err
	}
	if err := checkCgroup(dir, containerID); err != nil {
		return nil, fmt.Errorf("pid %d changed during the read: %w", pid, err)
	}
	return socks, nil
}

func checkCgroup(dir, containerID string) error {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup")) //nolint:gosec // G304: dir is "/proc/<pid>", built from an integer PID
	if err != nil {
		return err
	}
	if !bytes.Contains(b, []byte(containerID)) {
		return fmt.Errorf("%s/cgroup does not name container %s: %w", dir, evidence.ShortID(containerID), ErrNotContainer)
	}
	return nil
}

// SelfNetnsID returns the inode of the caller's network namespace, which
// identifies it: two checks with the same ID ran in the same netns.
func SelfNetnsID() uint64 {
	link, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return 0
	}
	// "net:[4026531833]"
	inner, ok := strings.CutPrefix(link, "net:[")
	if !ok {
		return 0
	}
	id, err := strconv.ParseUint(strings.TrimSuffix(inner, "]"), 10, 64)
	if err != nil {
		return 0
	}
	return id
}
