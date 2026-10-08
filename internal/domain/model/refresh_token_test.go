package model

import (
	"encoding/base64"
	"errors"
	"regexp"
	"testing"
	"time"
)

var issuedAt = time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)

const week = 7 * 24 * time.Hour

func TestNewOpaqueTokenIsRandomAndAtLeast32Bytes(t *testing.T) {
	first, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken() error = %v", err)
	}
	second, _ := NewOpaqueToken()
	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil || len(decoded) < 32 {
		t.Errorf("token %q is not base64url of at least 32 bytes (decoded %d, %v)", first, len(decoded), err)
	}
	if first == second {
		t.Error("two tokens are equal")
	}
}

func TestHashOpaqueTokenIsTheSHA256Hex(t *testing.T) {
	got := HashOpaqueToken("abc")
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("HashOpaqueToken(abc) = %s, want %s", got, want)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(HashOpaqueToken("another")) {
		t.Error("digest is not 64 lowercase hex characters")
	}
}

func TestNewRefreshTokenStoresOnlyTheDigestAndExpiresAfterTheTTL(t *testing.T) {
	token, err := NewRefreshToken("id-1", "user-1", "opaque-value", "curl/8", issuedAt, week)
	if err != nil {
		t.Fatalf("NewRefreshToken() error = %v", err)
	}
	if token.Hash() != HashOpaqueToken("opaque-value") || token.Hash() == "opaque-value" {
		t.Errorf("Hash() = %q, want the digest of the opaque value", token.Hash())
	}
	if !token.ExpiresAt().Equal(issuedAt.Add(week)) {
		t.Errorf("ExpiresAt() = %v, want %v", token.ExpiresAt(), issuedAt.Add(week))
	}
	if token.ID() != "id-1" || token.UserID() != "user-1" || token.UserAgent() != "curl/8" || token.RevokedAt() != nil {
		t.Errorf("unexpected token %+v", token)
	}
}

func TestNewRefreshTokenRejectsInvalidData(t *testing.T) {
	cases := map[string]struct {
		id, userID, opaque string
		ttl                time.Duration
		want               error
	}{
		"empty id":    {"", "user-1", "opaque", week, ErrInvalidRefreshToken},
		"empty token": {"id-1", "user-1", "", week, ErrInvalidRefreshToken},
		"zero ttl":    {"id-1", "user-1", "opaque", 0, ErrInvalidRefreshToken},
		"negative":    {"id-1", "user-1", "opaque", -time.Hour, ErrInvalidRefreshToken},
		"empty user":  {"id-1", "", "opaque", week, ErrInvalidUserID},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRefreshToken(c.id, c.userID, c.opaque, "", issuedAt, c.ttl); !errors.Is(err, c.want) {
				t.Fatalf("error = %v, want %v", err, c.want)
			}
		})
	}
}

func TestRefreshTokenValidity(t *testing.T) {
	active, _ := NewRefreshToken("id-1", "user-1", "opaque", "", issuedAt, week)
	revoked, _ := NewRefreshToken("id-2", "user-1", "opaque", "", issuedAt, week)
	revoked.Revoke(issuedAt.Add(time.Hour))
	cases := map[string]struct {
		token *RefreshToken
		now   time.Time
		want  bool
	}{
		"just issued":         {active, issuedAt, true},
		"before expiry":       {active, issuedAt.Add(week - time.Second), true},
		"at expiry":           {active, issuedAt.Add(week), false},
		"after expiry":        {active, issuedAt.Add(week + time.Hour), false},
		"revoked":             {revoked, issuedAt.Add(2 * time.Hour), false},
		"revoked and expired": {revoked, issuedAt.Add(2 * week), false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := c.token.IsValidAt(c.now); got != c.want {
				t.Errorf("IsValidAt() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRevokeKeepsTheFirstInstant(t *testing.T) {
	token, _ := NewRefreshToken("id-1", "user-1", "opaque", "", issuedAt, week)
	first, later := issuedAt.Add(time.Hour), issuedAt.Add(2*time.Hour)

	token.Revoke(first)
	token.Revoke(later)

	if got := token.RevokedAt(); got == nil || !got.Equal(first) {
		t.Errorf("RevokedAt() = %v, want %v", got, first)
	}
}

func TestRestoreRefreshTokenKeepsTheStoredState(t *testing.T) {
	revokedAt := issuedAt.Add(time.Hour)
	token := RestoreRefreshToken("id-1", "user-1", "hash", "ua", issuedAt.Add(week), &revokedAt)
	if token.Hash() != "hash" || token.IsValidAt(issuedAt) {
		t.Errorf("restored token %+v should keep its hash and stay revoked", token)
	}
}
