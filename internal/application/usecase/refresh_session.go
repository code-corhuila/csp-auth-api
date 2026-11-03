package usecase

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RefreshSession implements in.RefreshSession (HU-AUTH-002): refresh token rotation.
type RefreshSession struct {
	refreshTokens out.RefreshTokenRepository
	users         out.UserRepository
	transactions  out.TransactionManager
	session       sessionIssuer
	clock         out.Clock
	reuseGrace    time.Duration
}

var _ in.RefreshSession = (*RefreshSession)(nil)

// NewRefreshSession wires the use case with the ports it needs. reuseGrace is how long after a
// token was spent its presentation is still taken as a concurrent refresh (ADR-029).
func NewRefreshSession(refreshTokens out.RefreshTokenRepository, users out.UserRepository, transactions out.TransactionManager, accessTokens out.TokenIssuer, sessions in.IssueRefreshToken, clock out.Clock, reuseGrace time.Duration) *RefreshSession {
	return &RefreshSession{
		refreshTokens: refreshTokens,
		users:         users,
		transactions:  transactions,
		session:       sessionIssuer{accessTokens: accessTokens, sessions: sessions, clock: clock},
		clock:         clock,
		reuseGrace:    reuseGrace,
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
// the same model.ErrRefreshTokenRejected. A token that was spent more than the grace window ago
// is a reuse (ADR-029): every active token of its user is revoked, in a transaction of its own
// because the one above rolls back with the failed request, and the answer is the same. A locked
// user gets model.ErrUserLocked and keeps the token unspent.
func (r *RefreshSession) Refresh(ctx context.Context, command in.RefreshSessionCommand) (in.LoginUserResult, error) {
	hash := model.HashOpaqueToken(command.RefreshToken)
	var result in.LoginUserResult
	err := r.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		now := r.clock.Now()
		userID, spent, err := r.refreshTokens.RevokeByHash(ctx, hash, now)
		if err != nil {
			return err
		}
		if !spent {
			return model.ErrRefreshTokenRejected
		}
		user, err := r.users.FindByID(ctx, userID)
		if errors.Is(err, model.ErrUserNotFound) {
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
	if errors.Is(err, model.ErrRefreshTokenRejected) {
		r.revokeSessionsOnReuse(ctx, hash)
	}
	if err != nil {
		return in.LoginUserResult{}, err
	}
	return result, nil
}

// revokeSessionsOnReuse ends the sessions of the user whose spent token was presented again. It
// never changes the answer of the request: a failure is logged and the caller still gets the
// rejection, so the detection is not revealed. Unknown, expired and soft-deleted tokens revoke
// nothing.
func (r *RefreshSession) revokeSessionsOnReuse(ctx context.Context, hash string) {
	token, err := r.refreshTokens.FindByHash(ctx, hash)
	if errors.Is(err, model.ErrRefreshTokenNotFound) {
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "refresh token reuse check failed", "error", err)
		return
	}
	now := r.clock.Now()
	if !token.IsReusedAt(now, r.reuseGrace) {
		return
	}
	revoked, err := r.refreshTokens.RevokeAllActiveByUser(ctx, token.UserID(), now)
	if err != nil {
		slog.ErrorContext(ctx, "refresh token reuse revocation failed", "userId", token.UserID(), "tokenId", token.ID(), "error", err)
		return
	}
	slog.WarnContext(ctx, "refresh token reuse detected, sessions revoked", "userId", token.UserID(), "tokenId", token.ID(), "revokedTokens", revoked)
}
