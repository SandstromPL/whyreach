//go:build linux

package platform

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Capability bits (capabilities(7)).
const (
	capSysPtrace = 19 // open another user's /proc/<pid>/ns/net and /proc/<pid>/root
	capSysAdmin  = 21 // setns(2) into a network namespace
)

// Detect reads /proc and the root of the filesystem. A WSL kernel string is
// only a hint (containers on a WSL2 kernel report it too), so WSL also
// needs the interop entry and no container (INITIAL.md §3.7, item 4).
func Detect() Info {
	i := Info{OS: runtime.GOOS, Arch: runtime.GOARCH, Root: os.Geteuid() == 0}
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} { // Docker's, Podman's
		if _, err := os.Stat(marker); err == nil {
			i.InContainer = true
		}
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil && (bytes.Contains(b, []byte("docker")) || bytes.Contains(b, []byte("containerd"))) {
		i.InContainer = true
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil && bytes.Contains(bytes.ToLower(b), []byte("microsoft")) {
		if _, err := os.Stat("/proc/sys/fs/binfmt_misc/WSLInterop"); err == nil && !i.InContainer {
			i.WSL = true
		}
	}
	if caps, ok := effectiveCaps(); ok {
		i.Netns = caps&(1<<capSysAdmin) != 0 && caps&(1<<capSysPtrace) != 0 && initialUserNS()
	}
	i.Openat2 = openat2Works()
	return i
}

// OwnContainerID returns the ID of the Docker container whyreach runs in,
// from the files Docker mounts into it, or "" outside one.
func OwnContainerID() string {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	return containerIDFrom(string(b))
}

// effectiveCaps reads whyreach's effective capability set.
func effectiveCaps() (uint64, bool) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for line := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return caps, err == nil
		}
	}
	return 0, false
}

// initUserNSInode is the initial user namespace's fixed inode number
// (PROC_USER_INIT_INO in the kernel).
const initUserNSInode = "user:[4026531837]"

// initialUserNS reports whether whyreach runs in the machine's own user
// namespace. Capabilities in a child namespace (rootless setups, unshare -r)
// stop at that namespace, so they can't enter Docker's containers; a full
// identity uid_map doesn't make a child namespace the initial one.
func initialUserNS() bool {
	link, err := os.Readlink("/proc/self/ns/user")
	return err == nil && link == initUserNSInode
}

// openat2Works reports whether openat2(2) with RESOLVE_IN_ROOT is there
// (Linux 5.6 or later, and not refused by a seccomp policy).
func openat2Works() bool {
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

// OwnedByOther reports whether path, or its nearest existing parent,
// belongs to a user other than whyreach's own: as root after sudo -E, the
// state and data directories still name the user's home, and root-owned
// files there would lock the user out of them.
func OwnedByOther(path string) bool {
	for p := path; ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err == nil {
			return int(st.Uid) != os.Geteuid()
		}
		if p == filepath.Dir(p) {
			return false
		}
	}
}
