package security

import (
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// BoundedPasswordHasher decorates an out.PasswordHasher so that only maxConcurrent hashes or comparisons run at once, whatever
// the route that asks (Bulkhead, Norma 5.3.10). bcrypt is CPU work on purpose, so a flood of logins or registrations from many
// addresses would otherwise take every core. A call that finds no free slot waits at most queueTimeout and is then refused
// with model.ErrPasswordHasherBusy, without reaching bcrypt.
type BoundedPasswordHasher struct {
	inner        out.PasswordHasher
	slots        chan struct{}
	queueTimeout time.Duration
}

var _ out.PasswordHasher = (*BoundedPasswordHasher)(nil)

// NewBoundedPasswordHasher wraps inner with maxConcurrent slots and the longest wait for one of them.
func NewBoundedPasswordHasher(inner out.PasswordHasher, maxConcurrent int, queueTimeout time.Duration) *BoundedPasswordHasher {
	return &BoundedPasswordHasher{inner: inner, slots: make(chan struct{}, maxConcurrent), queueTimeout: queueTimeout}
}

// Hash hashes password when a slot is free within the queue timeout.
func (b *BoundedPasswordHasher) Hash(password model.Password) (string, error) {
	if !b.acquire() {
		return "", model.ErrPasswordHasherBusy
	}
	defer b.release()
	return b.inner.Hash(password)
}

// Verify compares password with hash when a slot is free within the queue timeout.
func (b *BoundedPasswordHasher) Verify(hash, password string) (bool, error) {
	if !b.acquire() {
		return false, model.ErrPasswordHasherBusy
	}
	defer b.release()
	return b.inner.Verify(hash, password)
}

func (b *BoundedPasswordHasher) acquire() bool {
	select {
	case b.slots <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(b.queueTimeout)
	defer timer.Stop()
	select {
	case b.slots <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

func (b *BoundedPasswordHasher) release() { <-b.slots }
