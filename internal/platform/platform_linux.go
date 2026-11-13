//go:build linux

package platform

import (
	"bytes"
	"os"
	"runtime"
	"strconv"
	"strings"
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
	if _, err := os.Stat("/.dockerenv"); err == nil {
		i.InContainer = true
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
	return i
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

// initialUserNS reports whether whyreach runs in the machine's own user
// namespace. Capabilities in a child namespace (rootless setups, unshare -r)
// stop at that namespace, so they can't enter Docker's containers.
func initialUserNS() bool {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	f := strings.Fields(string(b))
	return len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295"
}
