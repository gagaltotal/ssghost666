package ratelimiter

import (
	"math"
	"sync"
	"time"
)

// adaptiveConfig bounds how far the adaptive controller is allowed to move
// the configured rate, and how quickly it reacts. The floors/ceilings are
// deliberately conservative so an adaptive scan can never turn into a
// flood: even at full speed-up it stays within 2x of what the user asked
// for, and when the target looks stressed it backs off down to a fifth of
// it before giving up on going lower (and just waits).
type adaptiveConfig struct {
	base       float64 // the user's requested rate, the midpoint the controller returns to
	minRate    float64 // never go below this
	maxRate    float64 // never exceed this
	downFactor float64 // multiplicative back-off when the target looks stressed
	upStep     float64 // additive (per sec) recovery step when things look healthy
	window     time.Duration
	health     float64 // EWMA weight for the "recently healthy" signal
}

func newAdaptiveConfig(base float64) adaptiveConfig {
	minRate := base / 5.0
	if minRate < 0.5 {
		minRate = 0.5
	}
	maxRate := base * 2.0
	if maxRate < 1 {
		maxRate = 1
	}
	return adaptiveConfig{
		base:       base,
		minRate:    minRate,
		maxRate:    maxRate,
		downFactor: 0.6,
		upStep:     base * 0.10,
		window:     10 * time.Second,
		health:     0.5,
	}
}

// Enabler is the minimal interface the adaptive controller needs from the
// rate limiter it drives.
type Enabler interface {
	SetLimit(float64)
	CurrentLimit() float64
}

// Adaptive wraps a Limiter and continuously tunes its effective
// requests-per-second based on how the target is responding: if latency
// climbs well above the observed baseline (server under load) or the
// error/429 rate rises, the rate is throttled down; once requests look
// fast and clean again, it is stepped back up toward the user's requested
// rate. This keeps long scans polite to a struggling server without
// permanently penalising a healthy one.
type Adaptive struct {
	lim  Enabler
	cfg  adaptiveConfig
	stop chan struct{}
	once sync.Once

	mu       sync.Mutex
	baseMs   int64
	haveBase bool
	healthy  float64
	lastDown time.Time
}

// NewAdaptive starts an adaptive controller for lim, if the limiter
// supports runtime rate changes. Call Stop when the scan finishes. lim may
// be nil (adaptive limiting disabled), in which case a no-op Adaptive that
// still observes nothing is returned.
func NewAdaptive(l *Limiter, baseRate float64) *Adaptive {
	a := &Adaptive{
		cfg:      newAdaptiveConfig(baseRate),
		stop:     make(chan struct{}),
		healthy:  1.0,
		lastDown: time.Now().Add(-time.Hour),
	}
	if l != nil {
		a.lim = l
	}
	go a.loop()
	return a
}

// Enabled reports whether a real limiter is attached and the controller
// will actually do anything. It's used to gate status output in main.go.
func (a *Adaptive) Enabled() bool { return a != nil && a.lim != nil }

// Observe records the outcome of one real HTTP request. It is safe to call
// from many goroutines concurrently and is cheap (a few atomic-ish
// updates), so it can be called on every request without measurable cost.
func (a *Adaptive) Observe(elapsedMs int64, status int, err error) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.haveBase && err == nil && status > 0 {
		a.baseMs = elapsedMs
		a.haveBase = true
	} else if a.haveBase && err == nil && elapsedMs > 0 {
		// Slow-moving baseline so a single blip doesn't redefine "normal".
		a.baseMs = (a.baseMs*7 + elapsedMs) / 8
	}

	sample := healthSample(elapsedMs, status, err, a.baseMs, a.haveBase)
	a.healthy = 0.4*a.healthy + 0.6*sample
}

// CurrentRate returns the controller's current chosen rate (req/sec); used
// only for status output.
func (a *Adaptive) CurrentRate() float64 {
	if a == nil || a.lim == nil {
		return 0
	}
	return a.lim.CurrentLimit()
}

func (a *Adaptive) loop() {
	ticker := time.NewTicker(a.cfg.window)
	defer ticker.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-ticker.C:
			a.tune()
		}
	}
}

// Stop halts the background controller. Safe to call more than once.
func (a *Adaptive) Stop() {
	if a == nil {
		return
	}
	a.once.Do(func() { close(a.stop) })
}

func (a *Adaptive) tune() {
	if a.lim == nil {
		return
	}
	a.mu.Lock()
	h := a.healthy
	a.mu.Unlock()

	cur := a.lim.CurrentLimit()
	switch {
	case h < 0.5 && cur > a.cfg.minRate:
		// Target looks stressed (slow responses and/or errors): back off.
		next := cur * a.cfg.downFactor
		if next < a.cfg.minRate {
			next = a.cfg.minRate
		}
		a.lim.SetLimit(next)
		a.mu.Lock()
		a.lastDown = time.Now()
		a.mu.Unlock()
	case h > 0.85 && cur < a.cfg.base:
		// Healthy again: step back toward the user's requested rate, but
		// wait for the target to stay healthy for one full window first.
		a.mu.Lock()
		cooled := time.Since(a.lastDown) > a.cfg.window
		a.mu.Unlock()
		if cooled {
			next := cur + a.cfg.upStep
			if next > a.cfg.base {
				next = a.cfg.base
			}
			a.lim.SetLimit(next)
		}
	}
}

// healthSample converts one request's latency/status/error into a 0..1
// "how healthy was that" score. 1.0 is fast+clean, values below ~0.5 count
// as stress in tune().
func healthSample(elapsedMs int64, status int, err error, baseMs int64, haveBase bool) float64 {
	if err != nil {
		return 0.0
	}
	score := 1.0
	if status == 429 || status == 503 {
		score = 0.1
	} else if status >= 500 {
		score = 0.2
	} else if status >= 400 {
		score = 0.6
	}
	if haveBase && baseMs > 20 {
		ratio := float64(elapsedMs) / float64(baseMs)
		switch {
		case ratio >= 4:
			score = math.Min(score, 0.1)
		case ratio >= 2.5:
			score = math.Min(score, 0.2)
		case ratio >= 1.5:
			score = math.Min(score, 0.6)
		}
	}
	return score
}
