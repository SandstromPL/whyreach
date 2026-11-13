//go:build !linux

package probe

import (
	"fmt"
	"runtime"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// ReadListeners needs Linux's /proc/net. Elsewhere, container listeners are
// read inside a probe container instead (INITIAL.md §3.7).
func ReadListeners(string) ([]evidence.Socket, error) {
	return nil, fmt.Errorf("reading listeners from /proc on %s: %w", runtime.GOOS, ErrUnsupported)
}

// ContainerListeners needs Linux's /proc.
func ContainerListeners(int, string) ([]evidence.Socket, error) {
	return nil, fmt.Errorf("reading container listeners from /proc on %s: %w", runtime.GOOS, ErrUnsupported)
}

// CheckPID needs Linux's /proc.
func CheckPID(int, string) error {
	return fmt.Errorf("verifying a container's PID through /proc on %s: %w", runtime.GOOS, ErrUnsupported)
}

// SelfNetnsID is only known on Linux.
func SelfNetnsID() uint64 { return 0 }
