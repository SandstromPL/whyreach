package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// DialTimeout bounds one TCP connect (INITIAL.md §4.4).
const DialTimeout = 2 * time.Second

// AcceptWindow is how long a probe keeps a new connection open to see
// whether the peer closes it at once (OutcomeClosed). It never sends.
const AcceptWindow = 100 * time.Millisecond

// Dial connects to addr, waits up to AcceptWindow to see whether the peer
// closes the connection at once, and closes it, without sending any payload.
// subject labels the evidence ("api:8080"); via says how addr was obtained;
// lim is checked before dialing. The record's Context is left for the caller
// to fill in.
func Dial(ctx context.Context, subject string, addr netip.AddrPort, via string, lim Limits) evidence.Evidence {
	return dial(ctx, nil, subject, addr, via, lim)
}

// dial is Dial with the socket created through enter (Env.Enter). A dial to
// one literal address creates its socket on the calling goroutine, so the
// socket lives in the namespace enter put the thread in.
func dial(ctx context.Context, enter Enter, subject string, addr netip.AddrPort, via string, lim Limits) evidence.Evidence {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	ev := evidence.Evidence{
		Kind:    evidence.KindTCP,
		Subject: subject,
		Source:  "TCP connect, then close (no payload)",
	}
	p := evidence.TCPProbe{Target: subject, Addr: addr, Via: via}
	reason, ok := lim.CheckConnect(addr)
	if ok && lim.needsApproval(addr.Addr()) && !lim.allowance.take(addr) {
		reason, ok = AddrNotApproved, false // this batch used its approved connects
	}
	if !ok {
		p.Outcome = evidence.OutcomeBlocked
		ev.Status = evidence.StatusSkipped
		ev.Err = &evidence.Error{Code: evidence.CodePolicyDenied, Message: reason}
		ev.Data = p
		ev.ObservedAt = time.Now()
		return ev
	}
	d := net.Dialer{Timeout: DialTimeout}
	start := time.Now()
	var conn net.Conn
	var err error
	if eerr := enter.run(func() { conn, err = d.DialContext(ctx, "tcp", addr.String()) }); eerr != nil {
		// whyreach could not get into the namespace: nothing was observed.
		ev.Duration, ev.ObservedAt = time.Since(start), time.Now()
		ev.Status, ev.Err = Classify(eerr)
		return ev
	}
	p.RTT = time.Since(start)
	ev.Duration = p.RTT
	ev.ObservedAt = time.Now()
	if err == nil {
		p.Outcome = evidence.OutcomeConnected
		if closed, errno := closedAtOnce(ctx, conn); closed {
			p.Outcome, p.Errno = evidence.OutcomeClosed, errno
			p.Error = "the peer accepted the connection and closed it at once, without sending anything"
		}
		_ = conn.Close() // nothing was sent; a close error says nothing about reachability
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

// closedAtOnce waits up to AcceptWindow for the peer to end a connection it
// just accepted. Servers wait for the client to speak, or speak first, so
// either a timeout or data means the connection is open. An immediate EOF or
// reset is what docker-proxy does when the published container's port
// refuses, and what a server does that rejects the client right away.
func closedAtOnce(ctx context.Context, conn net.Conn) (bool, string) {
	deadline := time.Now().Add(AcceptWindow)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return false, ""
	}
	var b [1]byte
	n, err := conn.Read(b[:])
	switch {
	case n > 0:
		return false, ""
	case errors.Is(err, io.EOF):
		return true, ""
	case errors.Is(err, syscall.ECONNRESET):
		return true, "ECONNRESET"
	default:
		return false, ""
	}
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
