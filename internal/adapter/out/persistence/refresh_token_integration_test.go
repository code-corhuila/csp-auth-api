//go:build integration

package persistence

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// newStoredToken registers a user (refresh_token.user_id has a foreign key) and returns an unsaved
// token of that user together with its opaque value.
func newStoredToken(t *testing.T, f fixture, ctx context.Context, userAgent string) (*model.RefreshToken, string) {
	t.Helper()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	opaque, err := model.NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	token, err := model.NewRefreshToken(newUUID(t), user.ID(), opaque, userAgent, time.Now().UTC(), 7*24*time.Hour)
	if err != nil {
		t.Fatalf("NewRefreshToken() error = %v", err)
	}
	return token, opaque
}

func TestRefreshTokenIsStoredByDigestAndFoundAgain(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	repository := NewRefreshTokenRepository(f.pool)
	token, opaque := newStoredToken(t, f, ctx, "Mozilla/5.0")

	if err := repository.Save(ctx, token); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	var storedHash string
	if err := f.pool.QueryRow(ctx, `SELECT token_hash FROM auth.refresh_token WHERE id = $1`, token.ID()).Scan(&storedHash); err != nil {
		t.Fatalf("token not stored: %v", err)
	}
	if storedHash != model.HashOpaqueToken(opaque) || storedHash == opaque {
		t.Errorf("stored token_hash = %q, want only the SHA-256 digest", storedHash)
	}
	found, err := repository.FindByHash(ctx, model.HashOpaqueToken(opaque))
	if err != nil {
		t.Fatalf("FindByHash() error = %v", err)
	}
	if found.ID() != token.ID() || found.UserID() != token.UserID() || found.UserAgent() != "Mozilla/5.0" ||
		!found.ExpiresAt().Equal(token.ExpiresAt().Truncate(time.Microsecond)) || found.RevokedAt() != nil || !found.IsValidAt(time.Now()) {
		t.Errorf("found %+v differs from the saved token %+v", found, token)
	}
}

func TestRefreshTokenWithoutUserAgentIsStoredAsNull(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	repository := NewRefreshTokenRepository(f.pool)
	token, _ := newStoredToken(t, f, ctx, "")

	if err := repository.Save(ctx, token); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	var userAgent *string
	if err := f.pool.QueryRow(ctx, `SELECT user_agent FROM auth.refresh_token WHERE id = $1`, token.ID()).Scan(&userAgent); err != nil || userAgent != nil {
		t.Errorf("user_agent = %v, %v, want NULL", userAgent, err)
	}
}

func TestFindByHashReportsAnUnknownToken(t *testing.T) {
	f, ctx := newFixture(t), context.Background()

	_, err := NewRefreshTokenRepository(f.pool).FindByHash(ctx, model.HashOpaqueToken("never-issued"))

	if !errors.Is(err, model.ErrRefreshTokenNotFound) {
		t.Errorf("error = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestSaveRejectsADuplicateDigest(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	repository := NewRefreshTokenRepository(f.pool)
	token, opaque := newStoredToken(t, f, ctx, "")
	if err := repository.Save(ctx, token); err != nil {
		t.Fatalf("first Save() error = %v", err)
	}
	clone, _ := model.NewRefreshToken(newUUID(t), token.UserID(), opaque, "", time.Now().UTC(), time.Hour)

	err := repository.Save(ctx, clone)

	if !errors.Is(err, model.ErrRefreshTokenDuplicated) {
		t.Errorf("error = %v, want ErrRefreshTokenDuplicated", err)
	}
}

func saveToken(t *testing.T, f fixture, ctx context.Context, repository *RefreshTokenRepository) (*model.RefreshToken, string) {
	t.Helper()
	token, opaque := newStoredToken(t, f, ctx, "")
	if err := repository.Save(ctx, token); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	return token, opaque
}

func TestRevokeByHashRevokesOnceAndTheSecondCallFindsNothing(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	repository := NewRefreshTokenRepository(f.pool)
	token, opaque := saveToken(t, f, ctx, repository)
	first := time.Now().UTC().Truncate(time.Microsecond)

	userID, ok, err := repository.RevokeByHash(ctx, model.HashOpaqueToken(opaque), first)
	if err != nil || !ok || userID != token.UserID() {
		t.Fatalf("RevokeByHash() = %q, %v, %v; want the user of the token and ok", userID, ok, err)
	}
	_, again, err := repository.RevokeByHash(ctx, model.HashOpaqueToken(opaque), first.Add(time.Hour))
	if err != nil || again {
		t.Errorf("second RevokeByHash() ok = %v, error = %v, want nothing to revoke", again, err)
	}

	found, err := repository.FindByHash(ctx, model.HashOpaqueToken(opaque))
	if err != nil {
		t.Fatalf("FindByHash() error = %v", err)
	}
	if got := found.RevokedAt(); got == nil || !got.Equal(first) || found.IsValidAt(time.Now()) {
		t.Errorf("RevokedAt() = %v, want the first instant and an invalid token", got)
	}
}

func TestRevokeByHashIgnoresUnknownExpiredAndSoftDeletedTokens(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	repository := NewRefreshTokenRepository(f.pool)
	_, expiredOpaque := saveToken(t, f, ctx, repository)
	_, deletedOpaque := saveToken(t, f, ctx, repository)
	if _, err := f.pool.Exec(ctx, `UPDATE auth.refresh_token SET expires_at = NOW() - INTERVAL '1 second' WHERE token_hash = $1`, model.HashOpaqueToken(expiredOpaque)); err != nil {
		t.Fatalf("expire the token: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.refresh_token SET deleted_at = NOW() WHERE token_hash = $1`, model.HashOpaqueToken(deletedOpaque)); err != nil {
		t.Fatalf("soft-delete the token: %v", err)
	}

	for name, opaque := range map[string]string{"unknown": "never-issued", "expired": expiredOpaque, "soft-deleted": deletedOpaque} {
		if _, ok, err := repository.RevokeByHash(ctx, model.HashOpaqueToken(opaque), time.Now()); err != nil || ok {
			t.Errorf("%s: RevokeByHash() ok = %v, error = %v, want nothing to revoke", name, ok, err)
		}
	}
}

func TestRevokeByHashLetsExactlyOneOfTwoConcurrentCallersWin(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	repository := NewRefreshTokenRepository(f.pool)
	_, opaque := saveToken(t, f, ctx, repository)
	const callers = 8
	var winners atomic.Int32
	var group sync.WaitGroup
	start := make(chan struct{})
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if _, ok, err := repository.RevokeByHash(ctx, model.HashOpaqueToken(opaque), time.Now()); err != nil {
				t.Errorf("RevokeByHash() error = %v", err)
			} else if ok {
				winners.Add(1)
			}
		}()
	}
	close(start)
	group.Wait()

	if got := winners.Load(); got != 1 {
		t.Errorf("%d callers rotated the same token, want exactly 1", got)
	}
}

func TestRevokeAllForUserRevokesOnlyTheActiveTokensOfThatUser(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	repository := NewRefreshTokenRepository(f.pool)
	token, opaque := saveToken(t, f, ctx, repository)
	second, err := model.NewRefreshToken(newUUID(t), token.UserID(), "second-"+opaque, "", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatalf("NewRefreshToken() error = %v", err)
	}
	if err := repository.Save(ctx, second); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	_, otherOpaque := saveToken(t, f, ctx, repository)
	first := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if _, ok, err := repository.RevokeByHash(ctx, model.HashOpaqueToken(opaque), first); err != nil || !ok {
		t.Fatalf("RevokeByHash() ok = %v, error = %v", ok, err)
	}

	if err := repository.RevokeAllForUser(ctx, token.UserID(), time.Now()); err != nil {
		t.Fatalf("RevokeAllForUser() error = %v", err)
	}

	revoked, _ := repository.FindByHash(ctx, model.HashOpaqueToken(opaque))
	if got := revoked.RevokedAt(); got == nil || !got.Equal(first) {
		t.Errorf("already revoked token RevokedAt() = %v, want its first instant %v", got, first)
	}
	sibling, _ := repository.FindByHash(ctx, second.Hash())
	if sibling.RevokedAt() == nil {
		t.Error("the other active token of the user must be revoked")
	}
	other, _ := repository.FindByHash(ctx, model.HashOpaqueToken(otherOpaque))
	if other.RevokedAt() != nil {
		t.Error("the token of another user must stay active")
	}
}

func TestRefreshTokensCannotBeDeletedByTheService(t *testing.T) {
	f, ctx := newFixture(t), context.Background()

	if _, err := f.pool.Exec(ctx, `DELETE FROM auth.refresh_token WHERE id = $1`, newUUID(t)); err == nil {
		t.Error("DELETE succeeded, auth_writer must not have that privilege")
	}
}
