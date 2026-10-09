package usecase

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const presentedToken = "presented-opaque-token"

// storedRefreshTokens is an in-memory refresh token table keyed by digest.
type storedRefreshTokens struct {
	rows map[string]*model.RefreshToken
	err  error
}

func (s *storedRefreshTokens) Save(_ context.Context, token *model.RefreshToken) error {
	s.rows[token.Hash()] = token
	return nil
}

func (s *storedRefreshTokens) FindByHash(_ context.Context, hash string) (*model.RefreshToken, error) {
	if s.err != nil {
		return nil, s.err
	}
	if token, found := s.rows[hash]; found {
		return token, nil
	}
	return nil, model.ErrRefreshTokenNotFound
}

func (s *storedRefreshTokens) RevokeByHash(_ context.Context, hash string, at time.Time) (string, bool, error) {
	if s.err != nil {
		return "", false, s.err
	}
	token, found := s.rows[hash]
	if !found || !token.IsValidAt(at) {
		return "", false, nil
	}
	token.Revoke(at)
	return token.UserID(), true, nil
}

func (s *storedRefreshTokens) snapshot() map[string]*model.RefreshToken {
	copied := make(map[string]*model.RefreshToken, len(s.rows))
	for hash, token := range s.rows {
		copied[hash] = model.RestoreRefreshToken(token.ID(), token.UserID(), hash, token.UserAgent(), token.ExpiresAt(), token.RevokedAt())
	}
	return copied
}

// rollingBack is a transaction manager that restores the table when the work fails.
type rollingBack struct{ tokens *storedRefreshTokens }

func (m rollingBack) WithinTransaction(ctx context.Context, work func(context.Context) error) error {
	before := m.tokens.snapshot()
	if err := work(ctx); err != nil {
		m.tokens.rows = before
		return err
	}
	return nil
}

type refreshUsers struct {
	user *model.User
	err  error
}

func (u refreshUsers) ExistsByEmail(context.Context, model.Email) (bool, error) { return false, nil }
func (u refreshUsers) Save(context.Context, *model.User) error                  { return nil }
func (u refreshUsers) FindByEmail(context.Context, model.Email) (*model.User, error) {
	return nil, model.ErrUserNotFound
}
func (u refreshUsers) FindByID(context.Context, string) (*model.User, error) {
	if u.err != nil {
		return nil, u.err
	}
	if u.user == nil {
		return nil, model.ErrUserNotFound
	}
	return u.user, nil
}

type refreshFixture struct {
	useCase  *RefreshSession
	tokens   *storedRefreshTokens
	users    *refreshUsers
	sessions *loginSessions
}

// newRefreshFixture stores one token of user-1 for presentedToken, valid for a day.
func newRefreshFixture(t *testing.T, user *model.User) *refreshFixture {
	t.Helper()
	tokens := &storedRefreshTokens{rows: map[string]*model.RefreshToken{}}
	stored, err := model.NewRefreshToken("token-1", "user-1", presentedToken, "old-agent", registeredAt, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewRefreshToken() error = %v", err)
	}
	tokens.rows[stored.Hash()] = stored
	f := &refreshFixture{tokens: tokens, users: &refreshUsers{user: user}, sessions: &loginSessions{}}
	f.useCase = NewRefreshSession(tokens, f.users, rollingBack{tokens}, loginTokens{}, f.sessions, fakeClock{})
	return f
}

func (f *refreshFixture) stored() *model.RefreshToken {
	return f.tokens.rows[model.HashOpaqueToken(presentedToken)]
}

func TestRefreshSpendsTheTokenAndIssuesANewPairForTheCurrentRoles(t *testing.T) {
	f := newRefreshFixture(t, storedUser(t, model.UserActive, model.RoleClient, model.RoleAdmin))

	result, err := f.useCase.Refresh(context.Background(), in.RefreshSessionCommand{RefreshToken: presentedToken, UserAgent: "curl/8"})

	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if result.AccessToken != accessSecret || result.RefreshToken != "opaque-refresh" || result.ExpiresIn != 3600 {
		t.Errorf("tokens = %q %q %d, want the issued ones and 3600 seconds", result.AccessToken, result.RefreshToken, result.ExpiresIn)
	}
	if !reflect.DeepEqual(result.User.Roles, []string{"CLIENT", "ADMIN"}) || !contains(result.User.Permissions, "user:role:update") {
		t.Errorf("user = %+v, want the current roles and their permissions", result.User)
	}
	if got := f.stored().RevokedAt(); got == nil || !got.Equal(registeredAt) {
		t.Errorf("revokedAt = %v, want the old token revoked now", got)
	}
	if want := []in.IssueRefreshTokenCommand{{UserID: "user-1", UserAgent: "curl/8"}}; !reflect.DeepEqual(f.sessions.commands, want) {
		t.Errorf("session commands = %+v, want %+v", f.sessions.commands, want)
	}
}

func TestRefreshRejectsUnknownExpiredAndRevokedTokensWithTheSameError(t *testing.T) {
	cases := map[string]func(*refreshFixture) string{
		"unknown": func(*refreshFixture) string { return "never-issued" },
		"expired": func(f *refreshFixture) string {
			expired := model.RestoreRefreshToken("token-2", "user-1", model.HashOpaqueToken("old"), "", registeredAt.Add(-time.Second), nil)
			f.tokens.rows[expired.Hash()] = expired
			return "old"
		},
		"revoked": func(f *refreshFixture) string {
			f.stored().Revoke(registeredAt.Add(-time.Minute))
			return presentedToken
		},
	}
	for name, arrange := range cases {
		f := newRefreshFixture(t, storedUser(t, model.UserActive, model.RoleClient))
		token := arrange(f)

		result, err := f.useCase.Refresh(context.Background(), in.RefreshSessionCommand{RefreshToken: token})

		if err != model.ErrRefreshTokenRejected || !reflect.DeepEqual(result, in.LoginUserResult{}) {
			t.Errorf("%s: result = %+v, error = %v, want an empty result and ErrRefreshTokenRejected", name, result, err)
		}
		if len(f.sessions.commands) != 0 {
			t.Errorf("%s: a rejected token must not open a session", name)
		}
	}
}

func TestRefreshTokenIsSingleUse(t *testing.T) {
	f := newRefreshFixture(t, storedUser(t, model.UserActive, model.RoleClient))
	command := in.RefreshSessionCommand{RefreshToken: presentedToken}

	_, first := f.useCase.Refresh(context.Background(), command)
	_, second := f.useCase.Refresh(context.Background(), command)

	if first != nil || second != model.ErrRefreshTokenRejected {
		t.Errorf("errors = %v, %v, want success and then ErrRefreshTokenRejected", first, second)
	}
}

func TestRefreshOfALockedUserGivesErrUserLockedAndKeepsTheTokenUnspent(t *testing.T) {
	f := newRefreshFixture(t, storedUser(t, model.UserLocked, model.RoleClient))

	_, err := f.useCase.Refresh(context.Background(), in.RefreshSessionCommand{RefreshToken: presentedToken})

	if err != model.ErrUserLocked {
		t.Errorf("error = %v, want ErrUserLocked", err)
	}
	if f.stored().RevokedAt() != nil || len(f.sessions.commands) != 0 {
		t.Error("a locked user must not spend the token nor get a new session")
	}
}

func TestRefreshOfAMissingUserIsRejectedLikeAnyInvalidToken(t *testing.T) {
	f := newRefreshFixture(t, nil)

	_, err := f.useCase.Refresh(context.Background(), in.RefreshSessionCommand{RefreshToken: presentedToken})

	if err != model.ErrRefreshTokenRejected || f.stored().RevokedAt() != nil {
		t.Errorf("error = %v, revoked = %v, want ErrRefreshTokenRejected and the token untouched", err, f.stored().RevokedAt())
	}
}

func TestRefreshFailureWhileIssuingKeepsTheOldTokenValid(t *testing.T) {
	failure := errors.New("boom")
	cases := map[string]func(*refreshFixture){
		"user lookup":   func(f *refreshFixture) { f.users.err = failure },
		"access token":  func(f *refreshFixture) { f.useCase.session.tokens = loginTokens{err: failure} },
		"refresh token": func(f *refreshFixture) { f.sessions.err = failure },
	}
	for name, breakIt := range cases {
		f := newRefreshFixture(t, storedUser(t, model.UserActive, model.RoleClient))
		breakIt(f)

		result, err := f.useCase.Refresh(context.Background(), in.RefreshSessionCommand{RefreshToken: presentedToken})

		if !errors.Is(err, failure) || !reflect.DeepEqual(result, in.LoginUserResult{}) {
			t.Errorf("%s: result = %+v, error = %v, want an empty result and the failure", name, result, err)
		}
		if f.stored().RevokedAt() != nil {
			t.Errorf("%s: the old token was lost: the client could not retry", name)
		}
		if strings.Contains(err.Error(), presentedToken) {
			t.Errorf("%s: error leaks the token: %v", name, err)
		}
	}
}

func TestRefreshSurfacesRepositoryFailures(t *testing.T) {
	failure := errors.New("boom")
	f := newRefreshFixture(t, storedUser(t, model.UserActive, model.RoleClient))
	f.tokens.err = failure

	if _, err := f.useCase.Refresh(context.Background(), in.RefreshSessionCommand{RefreshToken: presentedToken}); !errors.Is(err, failure) {
		t.Errorf("error = %v, want the failure, not a rejection", err)
	}
}

func TestRefreshOfARevokedTokenRevokesNothingElse(t *testing.T) {
	f := newRefreshFixture(t, storedUser(t, model.UserActive, model.RoleClient))
	sibling := model.RestoreRefreshToken("token-2", "user-1", model.HashOpaqueToken("sibling"), "", registeredAt.Add(time.Hour), nil)
	f.tokens.rows[sibling.Hash()] = sibling
	f.stored().Revoke(registeredAt.Add(-time.Minute))

	_, err := f.useCase.Refresh(context.Background(), in.RefreshSessionCommand{RefreshToken: presentedToken})

	if err != model.ErrRefreshTokenRejected || sibling.RevokedAt() != nil {
		t.Errorf("error = %v, sibling revoked = %v, want ErrRefreshTokenRejected and the other token untouched", err, sibling.RevokedAt())
	}
}
