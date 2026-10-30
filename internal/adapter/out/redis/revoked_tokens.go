package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

const (
	revokedTokenKeyPrefix = "blacklist:"
	// userSessionsKeyPrefix cannot collide with a jti, which is a UUID and has no "user:" prefix.
	userSessionsKeyPrefix = revokedTokenKeyPrefix + "user:"
	// userSessionsTTL is the longest life of an access token (security-rules.md): a token issued at or
	// before the marker expires at the instant of the marker plus this time at the latest.
	userSessionsTTL = time.Hour
)

// RevokedTokens implements out.RevokedTokens with one string key per jti, blacklist:{jti}
// (data-model.md). The key expires with the token, so the list never grows beyond the live tokens. It also
// keeps one marker per user, blacklist:user:{userId}, holding the instant in epoch seconds at which
// the sessions of the user were ended (ADR-031, amendment 2026-10-24).
type RevokedTokens struct {
	client *goredis.Client
}

var _ out.RevokedTokens = (*RevokedTokens)(nil)

// NewRevokedTokens creates the list over client.
func NewRevokedTokens(client *goredis.Client) *RevokedTokens {
	return &RevokedTokens{client: client}
}

// Revoke is one SET with an expiration; repeating it for the same jti only renews the expiration.
func (r *RevokedTokens) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	if err := r.client.Set(ctx, revokedTokenKey(jti), "1", ttl).Err(); err != nil {
		return fmt.Errorf("revoke token in redis: %w", err)
	}
	return nil
}

// IsRevoked is one EXISTS.
func (r *RevokedTokens) IsRevoked(ctx context.Context, jti string) (bool, error) {
	found, err := r.client.Exists(ctx, revokedTokenKey(jti)).Result()
	if err != nil {
		return false, fmt.Errorf("look up token in redis: %w", err)
	}
	return found > 0, nil
}

// RevokeUserSessions is one SET with an expiration; a later revocation overwrites the instant.
func (r *RevokedTokens) RevokeUserSessions(ctx context.Context, userID string, at time.Time) error {
	if err := r.client.Set(ctx, userSessionsKey(userID), at.Unix(), userSessionsTTL).Err(); err != nil {
		return fmt.Errorf("mark the sessions of the user as ended in redis: %w", err)
	}
	return nil
}

// UserSessionsRevokedAt is one GET; a value that is not an instant in epoch seconds is an error, so
// the caller fails closed instead of accepting a token it cannot judge.
func (r *RevokedTokens) UserSessionsRevokedAt(ctx context.Context, userID string) (time.Time, bool, error) {
	value, err := r.client.Get(ctx, userSessionsKey(userID)).Result()
	if errors.Is(err, goredis.Nil) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("look up the sessions of the user in redis: %w", err)
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("the marker of the sessions of the user is not an instant: %w", err)
	}
	return time.Unix(seconds, 0), true, nil
}

func userSessionsKey(userID string) string {
	return userSessionsKeyPrefix + userID
}

func revokedTokenKey(jti string) string {
	return revokedTokenKeyPrefix + jti
}
