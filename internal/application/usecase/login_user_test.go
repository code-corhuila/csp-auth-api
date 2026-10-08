package usecase

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	storedHash   = "$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
	rightPass    = "Secret123"
	accessLife   = time.Hour
	accessSecret = "signed.access.token"
)

type loginUsers struct {
	user  *model.User
	err   error
	asked []string
}

func (u *loginUsers) ExistsByEmail(context.Context, model.Email) (bool, error) { return false, nil }
func (u *loginUsers) Save(context.Context, *model.User) error                  { return nil }
func (u *loginUsers) FindByEmail(_ context.Context, email model.Email) (*model.User, error) {
	u.asked = append(u.asked, email.String())
	if u.err != nil {
		return nil, u.err
	}
	if u.user == nil {
		return nil, model.ErrUserNotFound
	}
	return u.user, nil
}

// loginHasher accepts rightPass for storedHash and records every comparison.
type loginHasher struct{ checked []string }

func (h *loginHasher) Hash(model.Password) (string, error) { return storedHash, nil }
func (h *loginHasher) Verify(hash, password string) bool {
	h.checked = append(h.checked, hash)
	return hash == storedHash && password == rightPass
}

type loginTokens struct{ err error }

func (t loginTokens) IssueAccessToken(model.AccessClaims) (out.IssuedAccessToken, error) {
	if t.err != nil {
		return out.IssuedAccessToken{}, t.err
	}
	return out.IssuedAccessToken{Value: accessSecret, ExpiresAt: registeredAt.Add(accessLife)}, nil
}

type loginSessions struct {
	commands []in.IssueRefreshTokenCommand
	err      error
}

func (s *loginSessions) Issue(_ context.Context, command in.IssueRefreshTokenCommand) (in.IssuedRefreshToken, error) {
	s.commands = append(s.commands, command)
	if s.err != nil {
		return in.IssuedRefreshToken{}, s.err
	}
	return in.IssuedRefreshToken{Token: "opaque-refresh", ExpiresAt: registeredAt.Add(7 * 24 * time.Hour)}, nil
}

func storedUser(t *testing.T, status model.UserStatus, roles ...model.Role) *model.User {
	t.Helper()
	email, _ := model.NewEmail("ana@example.com")
	name, _ := model.NewName("Ana Pérez")
	phone, _ := model.NewPhone("3001234567")
	address, _ := model.NewAddress("Calle 123 #45-67")
	user, err := model.RestoreUser("user-1", name, email, storedHash, phone, address, roles, status)
	if err != nil {
		t.Fatalf("RestoreUser() error = %v", err)
	}
	return user
}

type loginFixture struct {
	useCase  *LoginUser
	users    *loginUsers
	hasher   *loginHasher
	sessions *loginSessions
}

func newLoginFixture(user *model.User) *loginFixture {
	f := &loginFixture{users: &loginUsers{user: user}, hasher: &loginHasher{}, sessions: &loginSessions{}}
	f.useCase = NewLoginUser(f.users, f.hasher, loginTokens{}, f.sessions, fakeClock{})
	return f
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestLoginReturnsBothTokensAndThePublicUser(t *testing.T) {
	f := newLoginFixture(storedUser(t, model.UserActive, model.RoleClient))

	result, err := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: " Ana@Example.com ", Password: rightPass, UserAgent: "curl/8"})

	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if result.AccessToken != accessSecret || result.RefreshToken != "opaque-refresh" || result.ExpiresIn != 3600 {
		t.Errorf("tokens = %q %q %d, want the issued ones and 3600 seconds", result.AccessToken, result.RefreshToken, result.ExpiresIn)
	}
	want := in.UserSummary{ID: "user-1", Email: "ana@example.com", Name: "Ana Pérez", Roles: []string{"CLIENT"}, Permissions: result.User.Permissions}
	if !reflect.DeepEqual(result.User, want) || !contains(result.User.Permissions, "booking:create") {
		t.Errorf("user = %+v, want %+v with client permissions", result.User, want)
	}
	if !reflect.DeepEqual(f.users.asked, []string{"ana@example.com"}) {
		t.Errorf("lookups = %v, want the normalized email", f.users.asked)
	}
	if want := []in.IssueRefreshTokenCommand{{UserID: "user-1", UserAgent: "curl/8"}}; !reflect.DeepEqual(f.sessions.commands, want) {
		t.Errorf("session commands = %+v, want %+v", f.sessions.commands, want)
	}
}

func TestLoginGivesAnAdminItsExtraPermissions(t *testing.T) {
	f := newLoginFixture(storedUser(t, model.UserActive, model.RoleClient, model.RoleAdmin))

	result, err := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: rightPass})

	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if !reflect.DeepEqual(result.User.Roles, []string{"CLIENT", "ADMIN"}) || !contains(result.User.Permissions, "user:role:update") {
		t.Errorf("user = %+v, want both roles and admin permissions", result.User)
	}
}

func TestLoginRejectsUnknownEmailAndWrongPasswordWithTheSameError(t *testing.T) {
	unknown := newLoginFixture(nil)
	wrong := newLoginFixture(storedUser(t, model.UserActive, model.RoleClient))

	_, unknownErr := unknown.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ghost@example.com", Password: rightPass})
	_, wrongErr := wrong.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: "Wrong1234"})

	if unknownErr != model.ErrInvalidCredentials || wrongErr != model.ErrInvalidCredentials {
		t.Errorf("errors = %v, %v, want model.ErrInvalidCredentials for both", unknownErr, wrongErr)
	}
	if len(unknown.sessions.commands)+len(wrong.sessions.commands) != 0 {
		t.Error("no refresh token may be issued on a failed login")
	}
}

func TestLoginComparesAgainstADummyHashWhenTheEmailHasNoAccount(t *testing.T) {
	for _, email := range []string{"ghost@example.com", "not-an-email"} {
		f := newLoginFixture(nil)

		_, err := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: email, Password: rightPass})

		if err != model.ErrInvalidCredentials {
			t.Errorf("Login(%q) error = %v, want model.ErrInvalidCredentials", email, err)
		}
		if !reflect.DeepEqual(f.hasher.checked, []string{absentUserHash}) {
			t.Errorf("Login(%q) comparisons = %v, want one against the dummy hash", email, f.hasher.checked)
		}
	}
}

func TestLoginReportsALockedUserOnlyWithTheRightPassword(t *testing.T) {
	f := newLoginFixture(storedUser(t, model.UserLocked, model.RoleClient))

	_, right := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: rightPass})
	_, wrong := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: "Wrong1234"})

	if right != model.ErrUserLocked {
		t.Errorf("right password error = %v, want model.ErrUserLocked", right)
	}
	if wrong != model.ErrInvalidCredentials {
		t.Errorf("wrong password error = %v, want model.ErrInvalidCredentials", wrong)
	}
	if len(f.sessions.commands) != 0 {
		t.Error("a locked user must not get a refresh token")
	}
}

func TestLoginBoundsTheUserAgentTo255Characters(t *testing.T) {
	f := newLoginFixture(storedUser(t, model.UserActive, model.RoleClient))

	if _, err := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: rightPass, UserAgent: strings.Repeat("é", 300)}); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if got := f.sessions.commands[0].UserAgent; got != strings.Repeat("é", 255) {
		t.Errorf("user agent has %d characters, want it cut to 255", len([]rune(got)))
	}
}

func TestLoginSurfacesFailuresWithoutSecrets(t *testing.T) {
	failure := errors.New("boom")
	cases := map[string]func(*loginFixture){
		"repository":    func(f *loginFixture) { f.users.err = failure },
		"access token":  func(f *loginFixture) { f.useCase.tokens = loginTokens{err: failure} },
		"refresh token": func(f *loginFixture) { f.sessions.err = failure },
	}
	for name, breakIt := range cases {
		f := newLoginFixture(storedUser(t, model.UserActive, model.RoleClient))
		breakIt(f)

		result, err := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: rightPass})

		if !errors.Is(err, failure) {
			t.Errorf("%s: error = %v, want the failure", name, err)
		}
		if !reflect.DeepEqual(result, in.LoginUserResult{}) {
			t.Errorf("%s: result = %+v, want it empty", name, result)
		}
		if strings.Contains(err.Error(), rightPass) || strings.Contains(err.Error(), storedHash) {
			t.Errorf("%s: error leaks a secret: %v", name, err)
		}
	}
}
