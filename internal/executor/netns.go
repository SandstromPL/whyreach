package executor

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Inspector reads a container's metadata. The netns executor looks the
// container up right before entering it, for its current PID.
type Inspector interface {
	InspectContainer(ctx context.Context, idOrName string) (evidence.Container, error)
}

// ErrCannotEnter is why a netns batch could not run although the container
// does: its PID failed the check (Docker's PIDs aren't this machine's), or a
// privilege is missing. The policy then uses a probe container instead, if
// the user allows them.
var ErrCannotEnter = errors.New("cannot enter the container's network namespace")

// CannotEnter reports a record of a netns batch that failed with
// ErrCannotEnter, for the gap's advice.
func CannotEnter(e *evidence.Error) bool {
	return e != nil && strings.HasPrefix(e.Message, ErrCannotEnter.Error())
}

// Netns runs probes inside a container's network namespace by entering it
// with setns(2) on a locked OS thread (INITIAL.md §3.3, §4.7). It needs root
// and makes no Docker write. It only works where Docker's PIDs are this
// machine's own (Linux Docker Engine on this host: linux-engine and
// wsl2-engine), and before entering it checks that the PID still belongs to
// the container. The probes are the same as the other executors' and obey
// the same limits.
//
// Outside Linux, Run and Check answer unsupported.
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
