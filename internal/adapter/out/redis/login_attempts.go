package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	failedLoginsKeyPrefix = "attempts:"
	loginLockKeyPrefix    = "locked:"
)

// keyWithoutExpiration is what TTL answers for a key that exists and never expires.
const keyWithoutExpiration = time.Duration(-1)

// LoginAttempts implements out.LoginAttempts with two string keys per client address, attempts:{ip}
// (the failure counter, which lives for the window) and locked:{ip} (the lock, which lives for the
// lock time), as in data-model.md. Both expire by themselves, so nothing is ever purged. The limit of the wrong
// current passwords counts the same way under other prefixes (PasswordChangeAttempts).
type LoginAttempts struct {
	client        *goredis.Client
	policy        model.LoginAttemptPolicy
	counterPrefix string
	lockPrefix    string
}

var _ out.LoginAttempts = (*LoginAttempts)(nil)

// NewLoginAttempts creates the store over client with the rule of policy.
func NewLoginAttempts(client *goredis.Client, policy model.LoginAttemptPolicy) *LoginAttempts {
	return newAttemptLimit(client, policy, failedLoginsKeyPrefix, loginLockKeyPrefix)
}

// newAttemptLimit counts and locks under the keys counterPrefix+subject and lockPrefix+subject.
func newAttemptLimit(client *goredis.Client, policy model.LoginAttemptPolicy, counterPrefix, lockPrefix string) *LoginAttempts {
	return &LoginAttempts{client: client, policy: policy, counterPrefix: counterPrefix, lockPrefix: lockPrefix}
}

// LockedFor is one TTL of the lock key: a missing key is not locked.
func (a *LoginAttempts) LockedFor(ctx context.Context, clientAddress string) (time.Duration, error) {
	remaining, err := a.client.TTL(ctx, a.lockPrefix+clientAddress).Result()
	if err != nil {
		return 0, fmt.Errorf("look up lock in redis: %w", err)
	}
	switch {
	case remaining == keyWithoutExpiration:
		// This adapter never writes a lock without expiration; if one exists it must not lock for ever.
		return a.policy.Lock, nil
	case remaining < 0:
		return 0, nil
	}
	return remaining, nil
}

// RecordFailure counts one failure. The first one of a window starts the window; the one that reaches
// the policy writes the lock and drops the counter, so the next window starts clean after the lock. The outcome carries
// the count and, for the failure that locked, the length of the lock.
func (a *LoginAttempts) RecordFailure(ctx context.Context, clientAddress string) (model.LoginFailureOutcome, error) {
	counterKey := a.counterPrefix + clientAddress
	failures, err := a.client.Incr(ctx, counterKey).Result()
	if err != nil {
		return model.LoginFailureOutcome{}, fmt.Errorf("count failed attempt in redis: %w", err)
	}
	if failures == 1 {
		if err := a.client.Expire(ctx, counterKey, a.policy.Window).Err(); err != nil {
			return model.LoginFailureOutcome{}, fmt.Errorf("start attempt window in redis: %w", err)
		}
	}
	outcome := model.LoginFailureOutcome{Attempts: int(failures)}
	if !a.policy.Reached(int(failures)) {
		return outcome, nil
	}
	if err := a.client.Set(ctx, a.lockPrefix+clientAddress, "1", a.policy.Lock).Err(); err != nil {
		return model.LoginFailureOutcome{}, fmt.Errorf("lock subject in redis: %w", err)
	}
	if err := a.client.Del(ctx, counterKey).Err(); err != nil {
		return model.LoginFailureOutcome{}, fmt.Errorf("drop attempt counter in redis: %w", err)
	}
	outcome.LockedFor = a.policy.Lock
	return outcome, nil
}

// Clear is one DEL of the counter; a lock is not cleared because a locked client never gets to log in.
func (a *LoginAttempts) Clear(ctx context.Context, clientAddress string) error {
	if err := a.client.Del(ctx, a.counterPrefix+clientAddress).Err(); err != nil {
		return fmt.Errorf("clear failed attempts in redis: %w", err)
	}
	return nil
}
