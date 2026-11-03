package httpapi

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Bulkhead caps how many requests of a route run at once (Bulkhead pattern, Norma 5.3.10). A request that
// finds no free slot waits a short, bounded time and is then refused, so a slow dependency can hold at most
// limit database connections instead of draining the pool the other routes share. It belongs to the inbound
// adapter: the domain and the use cases know nothing about it.
type Bulkhead struct {
	slots chan struct{}
	wait  time.Duration
}

// NewBulkhead admits limit requests at once and makes the next ones wait at most wait.
func NewBulkhead(limit int, wait time.Duration) (*Bulkhead, error) {
	if limit < 1 {
		return nil, errors.New("the bulkhead limit must be at least 1")
	}
	if wait <= 0 {
		return nil, errors.New("the bulkhead wait must be positive")
	}
	return &Bulkhead{slots: make(chan struct{}, limit), wait: wait}, nil
}

// Limit is the number of requests admitted at once.
func (b *Bulkhead) Limit() int { return cap(b.slots) }

// Wait is the longest time a request waits for a slot.
func (b *Bulkhead) Wait() time.Duration { return b.wait }

// Acquire takes a slot, waiting at most Wait. It returns the function that gives the slot back (safe to
// call more than once) and whether the request was admitted. A cancelled ctx stops the wait at once.
func (b *Bulkhead) Acquire(ctx context.Context) (release func(), admitted bool) {
	select {
	case b.slots <- struct{}{}:
		return b.releaser(), true
	default:
	}
	timer := time.NewTimer(b.wait)
	defer timer.Stop()
	select {
	case b.slots <- struct{}{}:
		return b.releaser(), true
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

func (b *Bulkhead) releaser() func() {
	var once sync.Once
	return func() { once.Do(func() { <-b.slots }) }
}
