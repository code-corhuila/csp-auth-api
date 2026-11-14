package usecase

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// minRevocationTTL is the shortest life of an entry of the revoked list (ADR-033): a token about to
// expire is still listed.
const minRevocationTTL = time.Second

// Logout implements in.Logout (HU-AUTH-003, ADR-033).
type Logout struct {
	refreshTokens out.RefreshTokenRepository
	revoked       out.RevokedTokens
	transactions  out.TransactionManager
	clock         out.Clock
}

var _ in.Logout = (*Logout)(nil)

// NewLogout wires the use case with the ports it needs.
func NewLogout(refreshTokens out.RefreshTokenRepository, revoked out.RevokedTokens, transactions out.TransactionManager, clock out.Clock) *Logout {
	return &Logout{refreshTokens: refreshTokens, revoked: revoked, transactions: transactions, clock: clock}
}

// Logout revokes the refresh tokens in one transaction that is committed before the access token is
// listed, with a ttl of its remaining life. If listing fails the refresh tokens stay revoked and
// the error is returned so that the client repeats the call, which is idempotent.
//
// With AllDevices every active refresh token of the user is revoked; otherwise only the presented
// one, and only if it belongs to the user. A token that is not the user's, is unknown or was
// already revoked revokes nothing and is not an error, so the answer reveals nothing about it.
func (l *Logout) Logout(ctx context.Context, command in.LogoutCommand) error {
	err := l.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		now := l.clock.Now()
		switch {
		case command.AllDevices:
			_, err := l.refreshTokens.RevokeAllActiveByUser(ctx, command.UserID, now)
			return err
		case command.RefreshToken != "":
			return l.refreshTokens.RevokeActiveByUserAndHash(ctx, command.UserID, model.HashOpaqueToken(command.RefreshToken), now)
		default:
			return nil
		}
	})
	if err != nil {
		return err
	}
	return l.revoked.Revoke(ctx, command.TokenID, max(command.ExpiresAt.Sub(l.clock.Now()), minRevocationTTL))
}
