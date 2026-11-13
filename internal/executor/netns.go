package executor

import (
	"context"
	"log/slog"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Inspector reads a container's metadata. The netns executor looks the
// container up right before entering it, for its current PID.
type Inspector interface {
	InspectContainer(ctx context.Context, idOrName string) (evidence.Container, error)
}

// Netns runs probes inside a container's network namespace by entering it
// with setns(2) on a locked OS thread (INITIAL.md §3.3, §4.7). It needs root
// and makes no Docker write. It only works where Docker's PIDs are this
// machine's own (Linux Docker Engine on this host: linux-engine and
// wsl2-engine), and before entering it checks that the PID still belongs to
// the container. The probes are the same as the other executors' and obey
// the same limits.
//
// Outside Linux, Run answers every check with Status unsupported.
type Netns struct {
	Docker Inspector
	Logger *slog.Logger
}

// NewNetns returns a netns executor that looks containers up through d.
func NewNetns(d Inspector, logger *slog.Logger) *Netns {
	return &Netns{Docker: d, Logger: logger}
}

// Name is "netns".
func (n *Netns) Name() string { return evidence.ExecutorNetns }
