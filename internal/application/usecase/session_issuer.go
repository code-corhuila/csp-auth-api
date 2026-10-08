package usecase

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// sessionIssuer opens the session of an authenticated or just registered user: an access token
// and a refresh token. Login and registration share it.
type sessionIssuer struct {
	tokens   out.TokenIssuer
	sessions in.IssueRefreshToken
	clock    out.Clock
}

func (s sessionIssuer) open(ctx context.Context, user *model.User, userAgent string) (in.LoginUserResult, error) {
	claims, err := model.NewAccessClaims(user.ID(), user.Roles())
	if err != nil {
		return in.LoginUserResult{}, err
	}
	access, err := s.tokens.IssueAccessToken(claims)
	if err != nil {
		return in.LoginUserResult{}, err
	}
	refresh, err := s.sessions.Issue(ctx, in.IssueRefreshTokenCommand{UserID: user.ID(), UserAgent: boundUserAgent(userAgent)})
	if err != nil {
		return in.LoginUserResult{}, err
	}
	return in.LoginUserResult{
		AccessToken:  access.Value,
		RefreshToken: refresh.Token,
		ExpiresIn:    int(access.ExpiresAt.Sub(s.clock.Now()) / time.Second),
		User:         summarize(user, claims),
	}, nil
}

func summarizeUser(user *model.User) (in.UserSummary, error) {
	claims, err := model.NewAccessClaims(user.ID(), user.Roles())
	if err != nil {
		return in.UserSummary{}, err
	}
	return summarize(user, claims), nil
}
