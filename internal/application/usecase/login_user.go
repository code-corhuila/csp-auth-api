package usecase

import (
	"context"
	"errors"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// maxUserAgentRunes bounds the user agent kept with a session; a longer one is cut, not rejected,
// because it is informative and must not stop a valid login.
const maxUserAgentRunes = 255

// absentUserHash is a valid bcrypt hash (cost 12, the default work factor) of a random value
// nobody knows. It is checked when the email has no account, so that answering takes about as
// long as for an existing account and the response time does not reveal which emails exist.
const absentUserHash = "$2a$12$kWQob4IFYPEufI1r3647A.zx0gCb1jFQiI8uIA3XFVz5o88kV.JW6"

// LoginUser implements in.LoginUser (HU-AUTH-002).
type LoginUser struct {
	users   out.UserRepository
	hasher  out.PasswordHasher
	session sessionIssuer
}

var _ in.LoginUser = (*LoginUser)(nil)

// NewLoginUser wires the use case with the ports it needs.
func NewLoginUser(users out.UserRepository, hasher out.PasswordHasher, tokens out.TokenIssuer, sessions in.IssueRefreshToken, clock out.Clock) *LoginUser {
	return &LoginUser{users: users, hasher: hasher, session: sessionIssuer{tokens: tokens, sessions: sessions, clock: clock}}
}

// Login checks the credentials and issues an access token and a refresh token.
//
// An unknown or malformed email and a wrong password give the same model.ErrInvalidCredentials.
// A locked account is reported (model.ErrUserLocked) only after the password is verified, so the
// lock state is not revealed to someone who does not hold the right password. The presented
// password is not checked against the password policy: login presents a password, it does not choose one.
func (l *LoginUser) Login(ctx context.Context, command in.LoginUserCommand) (in.LoginUserResult, error) {
	user, err := l.authenticate(ctx, command)
	if err != nil {
		return in.LoginUserResult{}, err
	}
	return l.session.open(ctx, user, command.UserAgent)
}

func (l *LoginUser) authenticate(ctx context.Context, command in.LoginUserCommand) (*model.User, error) {
	email, err := model.NewEmail(command.Email)
	if err != nil {
		l.hasher.Verify(absentUserHash, command.Password)
		return nil, model.ErrInvalidCredentials
	}
	user, err := l.users.FindByEmail(ctx, email)
	if errors.Is(err, model.ErrUserNotFound) {
		l.hasher.Verify(absentUserHash, command.Password)
		return nil, model.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if !l.hasher.Verify(user.PasswordHash(), command.Password) {
		return nil, model.ErrInvalidCredentials
	}
	if err := user.EnsureCanAuthenticate(); err != nil {
		return nil, err
	}
	return user, nil
}

func boundUserAgent(userAgent string) string {
	runes := []rune(userAgent)
	if len(runes) <= maxUserAgentRunes {
		return userAgent
	}
	return string(runes[:maxUserAgentRunes])
}

func summarize(user *model.User, claims model.AccessClaims) in.UserSummary {
	roles := make([]string, 0, len(claims.Roles))
	for _, role := range claims.Roles {
		roles = append(roles, role.String())
	}
	return in.UserSummary{
		ID:          user.ID(),
		Email:       user.Email().String(),
		Name:        user.Name().String(),
		Roles:       roles,
		Permissions: claims.Permissions,
	}
}
