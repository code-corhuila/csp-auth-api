package out

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// PasswordResetRepository stores the requests to reset a password (pattern Repository).
// Implementations take part in the transaction carried by the context.
type PasswordResetRepository interface {
	// LockRequestsOf serializes the requests of a user until the transaction ends, so two concurrent
	// requests are counted and superseded one after the other. It returns model.ErrUserNotFound when
	// the account does not exist, was deleted or is not active.
	LockRequestsOf(ctx context.Context, userID string) error
	// CountRequestsSince counts the requests of the user made at or after since, superseded ones included.
	CountRequestsSince(ctx context.Context, userID string, since time.Time) (int, error)
	// SupersedePending soft-deletes the pending request of the user, if any, at at.
	SupersedePending(ctx context.Context, userID string, at time.Time) error
	// Add stores a new pending request.
	Add(ctx context.Context, reset *model.PasswordReset) error
	// LockByTokenHash locks, account first and request second, the request with that digest and returns it.
	// An unknown or superseded token, and a token of an account that is not active, is model.ErrPasswordResetRejected.
	LockByTokenHash(ctx context.Context, tokenHash string) (*model.PasswordReset, error)
	// MarkUsed stores the consumption of the request.
	MarkUsed(ctx context.Context, reset *model.PasswordReset) error
}

// ResetTokenGenerator draws reset tokens from a cryptographic source.
type ResetTokenGenerator interface {
	NewToken() (model.ResetToken, error)
}

// PasswordResetDelivery is what a PasswordResetSender needs to get the link to the user.
type PasswordResetDelivery struct {
	UserID    string
	Email     model.Email
	Token     model.ResetToken
	ExpiresAt time.Time
}

// PasswordResetSender hands the token to whatever delivers it (pattern Strategy: the composition root
// picks the adapter, ADR-050). It is called after the commit and must not make the caller wait for the
// delivery. The token is a secret: it never goes to the outbox, an event or a log.
type PasswordResetSender interface {
	Send(ctx context.Context, delivery PasswordResetDelivery) error
}

// PasswordUpdater replaces the password hash of an account, in the transaction carried by the context.
type PasswordUpdater interface {
	// UpdatePasswordHash stores hash for the active account userID, or returns model.ErrUserNotFound.
	UpdatePasswordHash(ctx context.Context, userID, hash string, at time.Time) error
}

// RefreshTokenRevoker ends the sessions of a user.
type RefreshTokenRevoker interface {
	// RevokeAllActiveByUser revokes every active refresh token of that user and returns how many.
	RevokeAllActiveByUser(ctx context.Context, userID string, at time.Time) (int, error)
}
