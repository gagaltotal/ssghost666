// Package ratelimiter bounds how fast and how concurrently SSGhost666 hits
// a target, so scans stay polite by default instead of behaving like a
// denial-of-service tool. Every HTTP call made by the crawler, discovery
// and scanner packages is expected to go through Limiter.Wait/Release.
package ratelimiter

import (
	"context"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// Limiter combines a requests-per-second token bucket with a bounded
// worker semaphore, and a hard cap on total requests for the whole run.
type Limiter struct {
	rl        *rate.Limiter
	sem       chan struct{}
	max       int64
	count     int64
	onLimit   func()
	once      sync.Once
	adapt     *Adaptive
	adaptOnce sync.Once
}

// New creates a Limiter allowing ratePerSec requests/sec, at most
// `concurrency` in flight at once, and at most `max` total requests
// across the whole scan (0 = unlimited).
func New(ratePerSec float64, concurrency, max int) *Limiter {
	return &Limiter{
		rl:  rate.NewLimiter(rate.Limit(ratePerSec), int(ratePerSec)+1),
		sem: make(chan struct{}, concurrency),
		max: int64(max),
	}
}

// OnLimitReached registers a callback invoked exactly once if the
// max-requests safety cap is hit, so main.go can print a warning.
func (l *Limiter) OnLimitReached(f func()) { l.onLimit = f }

// Acquire blocks until it is this caller's turn to make one HTTP request,
// respecting both the rate limit and the concurrency semaphore. It
// returns false if the total-request safety cap has already been hit, in
// which case the caller should skip the request entirely.
func (l *Limiter) Acquire(ctx context.Context) bool {
	if l.max > 0 {
		n := atomic.AddInt64(&l.count, 1)
		if n > l.max {
			l.once.Do(func() {
				if l.onLimit != nil {
					l.onLimit()
				}
			})
			return false
		}
	}
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	if err := l.rl.Wait(ctx); err != nil {
		<-l.sem
		return false
	}
	return true
}

// Release frees the concurrency slot taken by a successful Acquire. Every
// true-returning Acquire must be paired with exactly one Release.
func (l *Limiter) Release() { <-l.sem }

// Count returns the number of requests accounted so far.
func (l *Limiter) Count() int64 { return atomic.LoadInt64(&l.count) }

// CurrentLimit returns the limiter's current requests-per-second ceiling.
// It is safe to call concurrently and is used both by the adaptive
// controller and by status output.
func (l *Limiter) CurrentLimit() float64 { return float64(l.rl.Limit()) }

// SetLimit changes the requests-per-second ceiling at runtime. It is safe
// to call concurrently with Acquire (rate.Limiter is internally
// synchronised) and is how the adaptive controller throttles a scan up or
// down without recreating the limiter.
func (l *Limiter) SetLimit(ratePerSec float64) {
	if ratePerSec <= 0 {
		ratePerSec = 1
	}
	l.rl.SetLimit(rate.Limit(ratePerSec))
}

// EnableAdaptive attaches (once) an adaptive rate controller to this
// limiter and returns it. The controller watches request outcomes fed to
// Observe and tunes the rate accordingly. Safe to call multiple times; the
// first call wins.
func (l *Limiter) EnableAdaptive() *Adaptive {
	l.adaptOnce.Do(func() {
		l.adapt = NewAdaptive(l, l.CurrentLimit())
	})
	return l.adapt
}

// Observe feeds one request's outcome (elapsed milliseconds, HTTP status
// - 0 if none - and error) to the adaptive controller, if one is attached.
// It is a cheap no-op otherwise, so call sites can always call it.
func (l *Limiter) Observe(elapsedMs int64, status int, err error) {
	if l == nil || l.adapt == nil {
		return
	}
	l.adapt.Observe(elapsedMs, status, err)
}
