// Package probe holds the checks whyreach runs inside a network namespace:
// TCP connects, DNS lookups as the source's resolver sees them, and listening
// sockets from /proc/net. The same code runs in-process for the host and
// inside the probe container, whose entrypoint (Main) is the hidden
// `whyreach __probe` subcommand.
//
// Probes only observe. A TCP probe connects and closes without sending a
// byte, a DNS probe sends ordinary queries, and every address passes the
// target policy first.
package probe

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"syscall"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Errors that callers map to evidence statuses.
var (
	ErrUnsupported  = errors.New("unsupported on this platform")
	ErrNoProcess    = errors.New("the container has no running process")
	ErrNotContainer = errors.New("the PID does not belong to the container")
)

// Refused is a check the probe policy kept from being sent: an outside name
// no one approved, or a nameserver on the block list. Its record is a
// skipped check with code policy_denied, so it becomes a policy gap.
type Refused struct{ Reason string }

func (r *Refused) Error() string { return r.Reason }

// Classify maps the error of a failed check to an evidence status and error.
func Classify(err error) (evidence.Status, *evidence.Error) {
	e := &evidence.Error{Message: err.Error(), Errno: errnoName(err)}
	var refused *Refused
	switch {
	case errors.As(err, &refused):
		e.Code, e.Message = evidence.CodePolicyDenied, refused.Reason
		return evidence.StatusSkipped, e
	case errors.Is(err, ErrUnsupported):
		e.Code = evidence.CodeUnsupported
		return evidence.StatusUnsupported, e
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		e.Code = evidence.CodePermissionDenied
		return evidence.StatusPermissionDenied, e
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		e.Code = evidence.CodeTimeout
		return evidence.StatusTimeout, e
	case errors.Is(err, os.ErrDeadlineExceeded):
		// An operation's own time limit, not the diagnosis's deadline: the
		// environment kept the observation from being made.
		e.Code = evidence.CodeTimeout
		return evidence.StatusFailed, e
	case errors.Is(err, ErrNoProcess), errors.Is(err, ErrNotContainer), errors.Is(err, fs.ErrNotExist):
		e.Code = evidence.CodeNotFound
		return evidence.StatusFailed, e
	default:
		e.Code = evidence.CodeInternal
		return evidence.StatusError, e
	}
}

// errnoName returns the symbolic errno in err ("ECONNREFUSED"), or "".
func errnoName(err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return ""
	}
	for _, n := range errnoNames {
		if errno == n.errno {
			return n.name
		}
	}
	return ""
}

var errnoNames = []struct {
	errno syscall.Errno
	name  string
}{
	{syscall.ECONNREFUSED, "ECONNREFUSED"},
	{syscall.ECONNRESET, "ECONNRESET"},
	{syscall.ETIMEDOUT, "ETIMEDOUT"},
	{syscall.EHOSTUNREACH, "EHOSTUNREACH"},
	{syscall.ENETUNREACH, "ENETUNREACH"},
	{syscall.EADDRNOTAVAIL, "EADDRNOTAVAIL"},
	{syscall.EACCES, "EACCES"},
	{syscall.EPERM, "EPERM"},
	{syscall.ENOENT, "ENOENT"},
}
