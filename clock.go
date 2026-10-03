package creds

import (
	"sync"
	"time"
)

// Clock abstracts time so tests can control expiry and window boundaries.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// ManualClock is a test-friendly clock advanced explicitly.
type ManualClock struct {
	mu sync.Mutex
	t  time.Time
}

func NewManualClock(t time.Time) *ManualClock { return &ManualClock{t: t} }

func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}
