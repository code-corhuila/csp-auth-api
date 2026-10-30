package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// accountFailuresKeyPrefix stays under attempts:* so that the ACL of auth_app (ADR-028) needs no change.
const accountFailuresKeyPrefix = "attempts:account:"

// AccountLoginFailures implements out.AccountLoginFailures with one string key per account, attempts:account:{subject},
// which lives for the window. Only INCR and EXPIRE are used, both granted to auth_app. The counter never locks.
type AccountLoginFailures struct {
	client *goredis.Client
	window time.Duration
}

var _ out.AccountLoginFailures = (*AccountLoginFailures)(nil)

// NewAccountLoginFailures creates the store over client; a window starts with the first failure and ends window later.
func NewAccountLoginFailures(client *goredis.Client, window time.Duration) *AccountLoginFailures {
	return &AccountLoginFailures{client: client, window: window}
}

// Record is one INCR and, for the first failure of a window, one EXPIRE.
func (a *AccountLoginFailures) Record(ctx context.Context, subject string) (int, error) {
	key := accountFailuresKeyPrefix + subject
	failures, err := a.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("count failed account login in redis: %w", err)
	}
	if failures == 1 {
		if err := a.client.Expire(ctx, key, a.window).Err(); err != nil {
			return 0, fmt.Errorf("start account window in redis: %w", err)
		}
	}
	return int(failures), nil
}
