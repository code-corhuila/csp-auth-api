package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// NewOpaqueToken returns a random (version 4) UUID from crypto/rand, the opaque refresh token
// format of the contract. It is what the client holds; only its digest is stored.
func NewOpaqueToken() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]), nil
}

// HashOpaqueToken returns the SHA-256 digest of token in lowercase hexadecimal, the only form
// in which a refresh token is persisted or looked up.
func HashOpaqueToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// RefreshToken is a stateful session credential of a user (HU-AUTH-002). It holds the digest of the
// opaque token, never the token itself, and is valid until it expires or is revoked.
type RefreshToken struct {
	id        string
	userID    string
	hash      string
	userAgent string
	expiresAt time.Time
	revokedAt *time.Time
}

// NewRefreshToken creates a token for userID from the opaque value given to the client. It
// expires ttl after issuedAt.
func NewRefreshToken(id, userID, opaqueToken, userAgent string, issuedAt time.Time, ttl time.Duration) (*RefreshToken, error) {
	if id == "" || opaqueToken == "" || ttl <= 0 {
		return nil, ErrInvalidRefreshToken
	}
	if userID == "" {
		return nil, ErrInvalidUserID
	}
	return &RefreshToken{id: id, userID: userID, hash: HashOpaqueToken(opaqueToken), userAgent: userAgent, expiresAt: issuedAt.Add(ttl)}, nil
}

// RestoreRefreshToken rebuilds a stored token without applying creation rules.
func RestoreRefreshToken(id, userID, hash, userAgent string, expiresAt time.Time, revokedAt *time.Time) *RefreshToken {
	return &RefreshToken{id: id, userID: userID, hash: hash, userAgent: userAgent, expiresAt: expiresAt, revokedAt: revokedAt}
}

// Revoke ends the token at the given instant; revoking twice keeps the first instant.
func (t *RefreshToken) Revoke(at time.Time) {
	if t.revokedAt == nil {
		t.revokedAt = &at
	}
}

// IsValidAt reports whether the token can still be redeemed at now: not revoked and not expired.
func (t *RefreshToken) IsValidAt(now time.Time) bool {
	return t.revokedAt == nil && now.Before(t.expiresAt)
}

func (t *RefreshToken) ID() string           { return t.id }
func (t *RefreshToken) UserID() string       { return t.userID }
func (t *RefreshToken) Hash() string         { return t.hash }
func (t *RefreshToken) UserAgent() string    { return t.userAgent }
func (t *RefreshToken) ExpiresAt() time.Time { return t.expiresAt }

// RevokedAt returns the revocation instant, or nil while the token is active.
func (t *RefreshToken) RevokedAt() *time.Time { return t.revokedAt }
