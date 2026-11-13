//go:build !linux

package executor

import (
	"context"
	"fmt"
	"runtime"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/probe"
)

// Run can't enter a network namespace outside Linux: every check comes back
// unsupported, so the gap says why.
func (n *Netns) Run(_ context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error) {
	err := fmt.Errorf("entering a network namespace on %s: %w", runtime.GOOS, probe.ErrUnsupported)
	return Failed(where, n.Name(), specs, evidence.StatusUnsupported, &evidence.Error{
		Code: evidence.CodeUnsupported, Message: err.Error(),
	}), err
}
