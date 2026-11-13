//go:build linux

package platform

import (
	"bytes"
	"os"
	"runtime"
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
	return i
}
