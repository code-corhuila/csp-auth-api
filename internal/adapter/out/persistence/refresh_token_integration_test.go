//go:build integration

package persistence

import (
	"context"
	"errors"
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

func TestRevokeSetsRevokedAtOnceAndInvalidatesTheToken(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	repository := NewRefreshTokenRepository(f.pool)
	token, opaque := newStoredToken(t, f, ctx, "")
	if err := repository.Save(ctx, token); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	first := time.Now().UTC().Truncate(time.Microsecond)

	if err := repository.Revoke(ctx, token.ID(), first); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if err := repository.Revoke(ctx, token.ID(), first.Add(time.Hour)); err != nil {
		t.Fatalf("second Revoke() error = %v", err)
	}

	found, err := repository.FindByHash(ctx, model.HashOpaqueToken(opaque))
	if err != nil {
		t.Fatalf("FindByHash() error = %v", err)
	}
	if got := found.RevokedAt(); got == nil || !got.Equal(first) || found.IsValidAt(time.Now()) {
		t.Errorf("RevokedAt() = %v, valid = %v; want the first instant and an invalid token", got, found.IsValidAt(time.Now()))
	}
}

func TestRevokeReportsAnUnknownToken(t *testing.T) {
	f, ctx := newFixture(t), context.Background()

	err := NewRefreshTokenRepository(f.pool).Revoke(ctx, newUUID(t), time.Now())

	if !errors.Is(err, model.ErrRefreshTokenNotFound) {
		t.Errorf("error = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestRefreshTokensCannotBeDeletedByTheService(t *testing.T) {
	f, ctx := newFixture(t), context.Background()

	if _, err := f.pool.Exec(ctx, `DELETE FROM auth.refresh_token WHERE id = $1`, newUUID(t)); err == nil {
		t.Error("DELETE succeeded, auth_writer must not have that privilege")
	}
}
