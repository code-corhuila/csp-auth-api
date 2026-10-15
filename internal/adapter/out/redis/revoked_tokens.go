package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

const revokedTokenKeyPrefix = "blacklist:"

// RevokedTokens implements out.RevokedTokens with one string key per jti, blacklist:{jti}
// (data-model.md). The key expires with the token, so the list never grows beyond the live tokens.
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

func revokedTokenKey(jti string) string {
	return revokedTokenKeyPrefix + jti
}
