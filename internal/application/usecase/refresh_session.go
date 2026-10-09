package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RefreshSession implements in.RefreshSession (HU-AUTH-002): refresh token rotation.
type RefreshSession struct {
	tokens       out.RefreshTokenRepository
	users        out.UserRepository
	transactions out.TransactionManager
	session      sessionIssuer
	clock        out.Clock
}

var _ in.RefreshSession = (*RefreshSession)(nil)

// NewRefreshSession wires the use case with the ports it needs.
func NewRefreshSession(tokens out.RefreshTokenRepository, users out.UserRepository, transactions out.TransactionManager, access out.TokenIssuer, sessions in.IssueRefreshToken, clock out.Clock) *RefreshSession {
	return &RefreshSession{
		tokens:       tokens,
		users:        users,
		transactions: transactions,
		session:      sessionIssuer{tokens: access, sessions: sessions, clock: clock},
		clock:        clock,
	}
}

// Refresh spends the presented token and issues a new access token and a new refresh token.
//
// Spending the token, loading the user and issuing the new pair happen in one transaction, so a
// failure while issuing rolls the revocation back and the client keeps a valid token to retry
// with; it is never left with a spent token and no new one. The token is spent by a single
// conditional UPDATE, so of two requests presenting the same token only one rotates it.
//
// An unknown, expired, revoked or soft-deleted token, and one whose user no longer exists, give
// the same model.ErrRefreshTokenRejected. When the token exists and was already revoked it has
// been used before, which a legitimate client does not do, so every active token of its user is
// revoked too (reuse detection); that revocation is committed even though the call fails. A
// locked user gets model.ErrUserLocked and keeps the token unspent.
func (r *RefreshSession) Refresh(ctx context.Context, command in.RefreshSessionCommand) (in.LoginUserResult, error) {
	hash := model.HashOpaqueToken(command.RefreshToken)
	var result in.LoginUserResult
	rejected := false
	err := r.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		now := r.clock.Now()
		userID, spent, err := r.tokens.RevokeByHash(ctx, hash, now)
		if err != nil {
			return err
		}
		if !spent {
			rejected = true
			return r.revokeSessionsOfReusedToken(ctx, hash, now)
		}
		user, err := r.users.FindByID(ctx, userID)
		if errors.Is(err, model.ErrUserNotFound) {
			rejected = true
			return model.ErrRefreshTokenRejected
		}
		if err != nil {
			return err
		}
		if err := user.EnsureCanAuthenticate(); err != nil {
			return err
		}
		result, err = r.session.open(ctx, user, command.UserAgent)
		return err
	})
	switch {
	case err != nil && !errors.Is(err, model.ErrRefreshTokenRejected):
		return in.LoginUserResult{}, err
	case rejected:
		return in.LoginUserResult{}, model.ErrRefreshTokenRejected
	}
	return result, nil
}

// revokeSessionsOfReusedToken revokes the other tokens of the user when hash belongs to a token
// that was already revoked. An unknown or merely expired token revokes nothing.
func (r *RefreshSession) revokeSessionsOfReusedToken(ctx context.Context, hash string, at time.Time) error {
	token, err := r.tokens.FindByHash(ctx, hash)
	if errors.Is(err, model.ErrRefreshTokenNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if token.RevokedAt() == nil {
		return nil
	}
	return r.tokens.RevokeAllForUser(ctx, token.UserID(), at)
}
