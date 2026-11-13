//go:build !linux

package platform

import (
	"os"
	"runtime"
)

// Detect knows only the basics outside Linux: container and WSL detection
// read /proc, and no network namespace can be entered (Netns stays false).
func Detect() Info {
	return Info{OS: runtime.GOOS, Arch: runtime.GOARCH, Root: os.Geteuid() == 0}
}

// OwnedByOther needs Unix file ownership; elsewhere it reports false.
func OwnedByOther(string) bool { return false }

// OwnContainerID needs /proc; elsewhere it reports no container.
func OwnContainerID() string { return "" }
