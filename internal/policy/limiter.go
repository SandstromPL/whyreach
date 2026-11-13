package policy

import (
	"sync"
	"time"
)

// limiter is a token bucket: perMinute probes a minute, with a burst of the
// same size (INITIAL.md §4.9). It starts full.
type limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newLimiter(perMinute int, now func() time.Time) *limiter {
	b := float64(perMinute)
	return &limiter{rate: b / 60, burst: b, tokens: b, last: now(), now: now}
}

// take spends one token, if there is one.
func (l *limiter) take() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	if elapsed := t.Sub(l.last).Seconds(); elapsed > 0 {
		l.tokens = min(l.burst, l.tokens+elapsed*l.rate)
	}
	l.last = t
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
