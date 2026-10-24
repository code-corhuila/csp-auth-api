package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	failedPasswordChangesKeyPrefix = "attempts:pwd:"
	passwordChangeLockKeyPrefix    = "locked:pwd:"
)

// PasswordChangeAttempts implements out.PasswordChangeAttempts with two string keys per user, attempts:pwd:{userId} and
// locked:pwd:{userId} (ADR-051). They count and lock exactly as the keys of the login attempt limit (ADR-040) and stay inside
// the prefixes that the ACL of the auth Redis already grants, so the same commands apply and no grant changes.
type PasswordChangeAttempts struct {
	limit *LoginAttempts
}

var _ out.PasswordChangeAttempts = (*PasswordChangeAttempts)(nil)

// NewPasswordChangeAttempts creates the store over client with the rule of policy.
func NewPasswordChangeAttempts(client *goredis.Client, policy model.LoginAttemptPolicy) *PasswordChangeAttempts {
	return &PasswordChangeAttempts{limit: newAttemptLimit(client, policy, failedPasswordChangesKeyPrefix, passwordChangeLockKeyPrefix)}
}

// Locked is one TTL of the lock key: a missing key is not locked.
func (a *PasswordChangeAttempts) Locked(ctx context.Context, userID string) (time.Duration, error) {
	return a.limit.LockedFor(ctx, userID)
}

// RecordFailure counts one wrong current password and writes the lock when the policy is reached.
func (a *PasswordChangeAttempts) RecordFailure(ctx context.Context, userID string) error {
	return a.limit.RecordFailure(ctx, userID)
}

// Clear is one DEL of the counter.
func (a *PasswordChangeAttempts) Clear(ctx context.Context, userID string) error {
	return a.limit.Clear(ctx, userID)
}
