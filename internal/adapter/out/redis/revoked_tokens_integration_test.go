//go:build integration

package redis

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// The tests need the Redis 7 of the platform (csp-infra-redis) and its auth_app user, whose ACL allows
// only the commands and key patterns of the auth state. They read the URL of that user and are
// skipped without it:
//
//	AUTH_TEST_REDIS_URL   redis://auth_app:<password>@localhost:6379/0
const redisURLVariable = "AUTH_TEST_REDIS_URL"

func openClient(t *testing.T) *goredis.Client {
	t.Helper()
	url := os.Getenv(redisURLVariable)
	if url == "" {
		t.Skipf("%s is not set: integration tests need the Redis of csp-infra-redis", redisURLVariable)
	}
	client, err := NewClient(ClientSettings{URL: url, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newJTI(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

func TestRevokeListsTheTokenUntilItsLifeEnds(t *testing.T) {
	client := openClient(t)
	list := NewRevokedTokens(client)
	ctx := context.Background()
	jti := newJTI(t)

	if revoked, err := list.IsRevoked(ctx, jti); err != nil || revoked {
		t.Fatalf("IsRevoked() before = %v, %v; want false, nil", revoked, err)
	}
	if err := list.Revoke(ctx, jti, 30*time.Minute); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if revoked, err := list.IsRevoked(ctx, jti); err != nil || !revoked {
		t.Fatalf("IsRevoked() after = %v, %v; want true, nil", revoked, err)
	}
	ttl, err := client.TTL(ctx, "blacklist:"+jti).Result()
	if err != nil {
		t.Fatalf("TTL() error = %v", err)
	}
	if ttl <= 29*time.Minute || ttl > 30*time.Minute {
		t.Errorf("ttl = %v, want about 30m", ttl)
	}
}

func TestRevokedEntryExpires(t *testing.T) {
	list := NewRevokedTokens(openClient(t))
	ctx := context.Background()
	jti := newJTI(t)

	if err := list.Revoke(ctx, jti, time.Second); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	if revoked, err := list.IsRevoked(ctx, jti); err != nil || revoked {
		t.Errorf("IsRevoked() after the ttl = %v, %v; want false, nil", revoked, err)
	}
}

func TestRevokeWritesNothingForAnExpiredToken(t *testing.T) {
	client := openClient(t)
	jti := newJTI(t)

	if err := NewRevokedTokens(client).Revoke(context.Background(), jti, 0); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if found, _ := client.Exists(context.Background(), "blacklist:"+jti).Result(); found != 0 {
		t.Errorf("key exists = %d, want none: a ttl of zero would never expire", found)
	}
}

func TestRevokeTwiceKeepsTheTokenRevoked(t *testing.T) {
	list := NewRevokedTokens(openClient(t))
	ctx := context.Background()
	jti := newJTI(t)

	for i := 0; i < 2; i++ {
		if err := list.Revoke(ctx, jti, time.Minute); err != nil {
			t.Fatalf("Revoke() #%d error = %v", i+1, err)
		}
	}
	if revoked, err := list.IsRevoked(ctx, jti); err != nil || !revoked {
		t.Errorf("IsRevoked() = %v, %v; want true, nil", revoked, err)
	}
}

// The ACL of auth_app allows get, set, exists, incr, expire, ttl, del and ping on three key
// patterns: the commands the adapter uses must pass and the rest of the instance must stay closed.
func TestTheACLOfAuthAppAllowsTheAdapterAndNothingElse(t *testing.T) {
	client := openClient(t)
	ctx := context.Background()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Errorf("PING denied: %v", err)
	}
	if err := client.Set(ctx, "other:"+newJTI(t), "1", time.Minute).Err(); err == nil {
		t.Error("SET outside the key patterns of auth was allowed")
	}
	if err := client.FlushAll(ctx).Err(); err == nil {
		t.Error("FLUSHALL was allowed")
	}
	if err := client.Keys(ctx, "blacklist:*").Err(); err == nil {
		t.Error("KEYS was allowed")
	}
}

func TestAnUnreachableRedisIsAnError(t *testing.T) {
	client, err := NewClient(ClientSettings{URL: "redis://127.0.0.1:1/0", Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	list := NewRevokedTokens(client)

	if err := list.Revoke(context.Background(), "jti", time.Minute); err == nil {
		t.Error("Revoke() error = nil, want an error")
	}
	if _, err := list.IsRevoked(context.Background(), "jti"); err == nil {
		t.Error("IsRevoked() error = nil, want an error")
	}
	if err := list.RevokeUserSessions(context.Background(), "user", time.Now()); err == nil {
		t.Error("RevokeUserSessions() error = nil, want an error")
	}
	if _, _, err := list.UserSessionsRevokedAt(context.Background(), "user"); err == nil {
		t.Error("UserSessionsRevokedAt() error = nil, want an error")
	}
}

func TestRevokeUserSessionsStoresTheInstantInSecondsWithTheLifeOfAnAccessToken(t *testing.T) {
	client := openClient(t)
	list := NewRevokedTokens(client)
	ctx := context.Background()
	userID := newJTI(t)
	at := time.Unix(1_790_000_000, 900_000_000)

	if _, found, err := list.UserSessionsRevokedAt(ctx, userID); err != nil || found {
		t.Fatalf("UserSessionsRevokedAt() before = %v, %v; want not found, nil", found, err)
	}
	if err := list.RevokeUserSessions(ctx, userID, at); err != nil {
		t.Fatalf("RevokeUserSessions() error = %v", err)
	}

	got, found, err := list.UserSessionsRevokedAt(ctx, userID)
	if err != nil || !found || got.Unix() != at.Unix() || got.Nanosecond() != 0 {
		t.Errorf("UserSessionsRevokedAt() = %v, %v, %v; want %d seconds, found, nil", got, found, err, at.Unix())
	}
	if raw, err := client.Get(ctx, "blacklist:user:"+userID).Result(); err != nil || raw != "1790000000" {
		t.Errorf("stored value = %q, %v; want the epoch seconds 1790000000", raw, err)
	}
	if ttl, err := client.TTL(ctx, "blacklist:user:"+userID).Result(); err != nil || ttl <= 59*time.Minute || ttl > time.Hour {
		t.Errorf("ttl = %v, %v; want up to 3600 s", ttl, err)
	}
}

func TestRevokeUserSessionsOverwritesAnEarlierInstantAndLeavesTheTokensAlone(t *testing.T) {
	list := NewRevokedTokens(openClient(t))
	ctx := context.Background()
	userID := newJTI(t)

	for _, seconds := range []int64{1_790_000_000, 1_790_000_500} {
		if err := list.RevokeUserSessions(ctx, userID, time.Unix(seconds, 0)); err != nil {
			t.Fatalf("RevokeUserSessions(%d) error = %v", seconds, err)
		}
	}

	if got, _, _ := list.UserSessionsRevokedAt(ctx, userID); got.Unix() != 1_790_000_500 {
		t.Errorf("instant = %d, want the later revocation 1790000500", got.Unix())
	}
	if revoked, err := list.IsRevoked(ctx, userID); err != nil || revoked {
		t.Errorf("IsRevoked(%s) = %v, %v; want false: the marker of a user is not the entry of a jti", userID, revoked, err)
	}
}

func TestAMarkerThatIsNotAnInstantIsAnErrorAndNotAnAcceptedToken(t *testing.T) {
	client := openClient(t)
	userID := newJTI(t)
	if err := client.Set(context.Background(), "blacklist:user:"+userID, "tomorrow", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}

	if _, _, err := NewRevokedTokens(client).UserSessionsRevokedAt(context.Background(), userID); err == nil {
		t.Error("UserSessionsRevokedAt() error = nil, want an error for a value that is not an instant")
	}
}
