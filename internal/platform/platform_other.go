//go:build !linux

package platform

import (
	"os"
	"runtime"
)

// Detect knows only the basics outside Linux: container and WSL detection
// read /proc.
func Detect() Info {
	return Info{OS: runtime.GOOS, Arch: runtime.GOARCH, Root: os.Geteuid() == 0}
}
