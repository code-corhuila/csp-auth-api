package model

import (
	"errors"
	"time"
)

// Limits of the number of rows one purge call may delete (auth-service contract, MaintenanceRequest).
const (
	DefaultPurgeBatchSize = 100
	MaxPurgeBatchSize     = 500
)

// ErrInvalidPurgeBatchSize is a batch size outside 1 to MaxPurgeBatchSize.
var ErrInvalidPurgeBatchSize = errors.New("batch size must be between 1 and 500")

// PurgeBatchSize is the most rows one purge call deletes, in total over all the tables.
type PurgeBatchSize int

// NewPurgeBatchSize validates a batch size.
func NewPurgeBatchSize(value int) (PurgeBatchSize, error) {
	if value < 1 || value > MaxPurgeBatchSize {
		return 0, ErrInvalidPurgeBatchSize
	}
	return PurgeBatchSize(value), nil
}

// RetentionPolicy is how long each kind of auth record is kept before the purge may delete it
// (ADR-030): outbox events 30 days, refresh tokens 30 days after they expire or are revoked,
// idempotency keys 7 days and email verification requests 7 days after they expire.
type RetentionPolicy struct {
	OutboxEvents       time.Duration
	RefreshTokens      time.Duration
	IdempotencyKeys    time.Duration
	EmailVerifications time.Duration
}

// DefaultRetentionPolicy returns the retention that ADR-030 fixes.
func DefaultRetentionPolicy() RetentionPolicy {
	const day = 24 * time.Hour
	return RetentionPolicy{OutboxEvents: 30 * day, RefreshTokens: 30 * day, IdempotencyKeys: 7 * day, EmailVerifications: 7 * day}
}
