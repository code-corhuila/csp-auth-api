package usecase

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// IssueRefreshToken implements in.IssueRefreshToken (HU-AUTH-002).
type IssueRefreshToken struct {
	tokens out.RefreshTokenRepository
	ids    out.IDGenerator
	clock  out.Clock
	ttl    time.Duration
}

var _ in.IssueRefreshToken = (*IssueRefreshToken)(nil)

// NewIssueRefreshToken wires the use case; ttl is the lifetime given to every token.
func NewIssueRefreshToken(tokens out.RefreshTokenRepository, ids out.IDGenerator, clock out.Clock, ttl time.Duration) *IssueRefreshToken {
	return &IssueRefreshToken{tokens: tokens, ids: ids, clock: clock, ttl: ttl}
}

// Issue creates an opaque token for the user, stores only its digest and returns the raw value
// once. The caller must hand it to the client: it cannot be recovered afterwards.
func (i *IssueRefreshToken) Issue(ctx context.Context, command in.IssueRefreshTokenCommand) (in.IssuedRefreshToken, error) {
	opaque, err := model.NewOpaqueToken()
	if err != nil {
		return in.IssuedRefreshToken{}, err
	}
	token, err := model.NewRefreshToken(i.ids.NewID(), command.UserID, opaque, command.UserAgent, i.clock.Now(), i.ttl)
	if err != nil {
		return in.IssuedRefreshToken{}, err
	}
	if err := i.tokens.Save(ctx, token); err != nil {
		return in.IssuedRefreshToken{}, err
	}
	return in.IssuedRefreshToken{Token: opaque, ExpiresAt: token.ExpiresAt()}, nil
}
