package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/target"
)

// DialTimeout bounds one TCP connect (INITIAL.md §4.4).
const DialTimeout = 2 * time.Second

// Dial connects to addr and closes the connection at once, without sending
// any payload. subject labels the evidence ("api:8080"); via says how addr was
// obtained. The record's Context is left for the caller to fill in.
func Dial(ctx context.Context, subject string, addr netip.AddrPort, via string) evidence.Evidence {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	ev := evidence.Evidence{
		Kind:    evidence.KindTCP,
		Subject: subject,
		Source:  "TCP connect, then close (no payload)",
	}
	p := evidence.TCPProbe{Target: subject, Addr: addr, Via: via}
	if reason, blocked := target.Blocked(addr.Addr()); blocked {
		p.Outcome = evidence.OutcomeBlocked
		ev.Status = evidence.StatusSkipped
		ev.Err = &evidence.Error{Code: evidence.CodePolicyDenied, Message: reason}
		ev.Data = p
		ev.ObservedAt = time.Now()
		return ev
	}
	d := net.Dialer{Timeout: DialTimeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	p.RTT = time.Since(start)
	ev.Duration = p.RTT
	ev.ObservedAt = time.Now()
	if err == nil {
		_ = conn.Close() // nothing was sent; a close error says nothing about reachability
		p.Outcome = evidence.OutcomeConnected
		ev.Status = evidence.StatusOK
		ev.Data = p
		return ev
	}
	if ctx.Err() != nil {
		// The diagnosis ran out of time; this is not an observation of the network.
		ev.Status = evidence.StatusTimeout
		ev.Err = &evidence.Error{Code: evidence.CodeTimeout, Message: "the diagnosis deadline passed during the connect"}
		ev.Data = p
		return ev
	}
	p.Outcome, p.Errno, p.Error = classifyDial(err), errnoName(err), err.Error()
	ev.Status = evidence.StatusOK
	ev.Data = p
	return ev
}

// classifyDial keeps refused, timeout and unreachable apart: they point at
// different causes.
func classifyDial(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return evidence.OutcomeRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return evidence.OutcomeUnreachable
	case errors.Is(err, syscall.ECONNRESET):
		return evidence.OutcomeReset
	case errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return evidence.OutcomeTimeout
	default:
		return evidence.OutcomeError
	}
}
