package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type fakeAccessTokens struct {
	claims map[string]model.AccessClaims
	called int
}

func (f *fakeAccessTokens) VerifyAccessToken(token string) (model.AccessClaims, error) {
	f.called++
	if claims, ok := f.claims[token]; ok {
		return claims, nil
	}
	return model.AccessClaims{}, model.ErrAccessTokenInvalid
}

func newUserAuthorizer(t *testing.T) (*AuthorizeUser, *fakeAccessTokens) {
	t.Helper()
	return newUserAuthorizerWith(t, newRevokedList())
}

func newUserAuthorizerWith(t *testing.T, revoked *fakeRevokedTokens) (*AuthorizeUser, *fakeAccessTokens) {
	t.Helper()
	admin, err := model.NewAccessClaims("admin-1", []model.Role{model.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	client, err := model.NewAccessClaims("client-1", []model.Role{model.RoleClient})
	if err != nil {
		t.Fatal(err)
	}
	admin.TokenID, client.TokenID = "jti-admin", "jti-client"
	tokens := &fakeAccessTokens{claims: map[string]model.AccessClaims{"admin-token": admin, "client-token": client}}
	return NewAuthorizeUser(tokens, revoked), tokens
}

func TestAuthorizeUserReturnsTheUserOfATokenWithThePermission(t *testing.T) {
	useCase, _ := newUserAuthorizer(t)

	userID, err := useCase.AuthorizeUser(context.Background(), "admin-token", "user:role:update")

	if err != nil || userID != "admin-1" {
		t.Errorf("userID = %q, error = %v, want admin-1 and no error", userID, err)
	}
}

func TestAuthorizeUserForbidsAValidTokenWithoutThePermission(t *testing.T) {
	useCase, _ := newUserAuthorizer(t)

	userID, err := useCase.AuthorizeUser(context.Background(), "client-token", "user:role:update")

	if !errors.Is(err, model.ErrPermissionDenied) || userID != "" {
		t.Errorf("userID = %q, error = %v, want ErrPermissionDenied", userID, err)
	}
}

func TestAuthorizeUserRejectsAMissingOrInvalidTokenBeforeLookingAtThePermission(t *testing.T) {
	for name, bearer := range map[string]string{"empty": "", "unknown": "forged-token"} {
		useCase, tokens := newUserAuthorizer(t)

		userID, err := useCase.AuthorizeUser(context.Background(), bearer, "user:role:update")

		if !errors.Is(err, model.ErrAccessTokenInvalid) || userID != "" {
			t.Errorf("%s: userID = %q, error = %v, want ErrAccessTokenInvalid", name, userID, err)
		}
		if name == "empty" && tokens.called != 0 {
			t.Errorf("%s: the verifier was called %d times, want 0", name, tokens.called)
		}
	}
}

func TestAuthorizeUserPassesAnUnexpectedVerifierFailureOn(t *testing.T) {
	failure := errors.New("key store down")
	useCase := NewAuthorizeUser(failingAccessTokens{failure}, newRevokedList())

	if _, err := useCase.AuthorizeUser(context.Background(), "any-token", "user:role:update"); !errors.Is(err, failure) {
		t.Errorf("error = %v, want %v", err, failure)
	}
}

type failingAccessTokens struct{ err error }

func (f failingAccessTokens) VerifyAccessToken(string) (model.AccessClaims, error) {
	return model.AccessClaims{}, f.err
}

func TestAuthenticateUserReturnsTheClaimsOfAValidTokenWhateverItsPermissions(t *testing.T) {
	useCase, _ := newUserAuthorizer(t)

	claims, err := useCase.AuthenticateUser(context.Background(), "client-token")

	if err != nil || claims.Subject != "client-1" {
		t.Errorf("claims = %+v, error = %v, want the claims of client-1", claims, err)
	}
}

func TestAuthenticateUserRejectsAMissingOrInvalidToken(t *testing.T) {
	for name, bearer := range map[string]string{"empty": "", "unknown": "forged-token"} {
		useCase, _ := newUserAuthorizer(t)

		_, err := useCase.AuthenticateUser(context.Background(), bearer)

		if !errors.Is(err, model.ErrAccessTokenInvalid) {
			t.Errorf("%s: error = %v, want ErrAccessTokenInvalid", name, err)
		}
	}
}

func TestAuthenticateUserRejectsATokenThatALogoutRevoked(t *testing.T) {
	revoked := newRevokedList()
	revoked.ttls["jti-client"] = time.Hour
	useCase, _ := newUserAuthorizerWith(t, revoked)

	_, err := useCase.AuthenticateUser(context.Background(), "client-token")

	if !errors.Is(err, model.ErrAccessTokenInvalid) {
		t.Errorf("error = %v, want ErrAccessTokenInvalid", err)
	}
	if claims, err := useCase.AuthenticateUser(context.Background(), "admin-token"); err != nil || claims.Subject != "admin-1" {
		t.Errorf("another token: claims = %+v, error = %v, want it accepted", claims, err)
	}
}

func TestAuthorizeUserAnswersARevokedTokenAsInvalidEvenWhenItLacksThePermission(t *testing.T) {
	revoked := newRevokedList()
	revoked.ttls["jti-client"] = time.Hour
	useCase, _ := newUserAuthorizerWith(t, revoked)

	_, err := useCase.AuthorizeUser(context.Background(), "client-token", "user:role:update")

	if !errors.Is(err, model.ErrAccessTokenInvalid) {
		t.Errorf("error = %v, want ErrAccessTokenInvalid and not ErrPermissionDenied", err)
	}
}

func TestAuthenticateUserFailsClosedWhenTheListCannotBeConsulted(t *testing.T) {
	revoked := newRevokedList()
	revoked.err = errors.New("dial tcp: connection refused")
	useCase, _ := newUserAuthorizerWith(t, revoked)

	for name, call := range map[string]func() error{
		"authenticate": func() error { _, err := useCase.AuthenticateUser(context.Background(), "admin-token"); return err },
		"authorize": func() error {
			_, err := useCase.AuthorizeUser(context.Background(), "admin-token", "user:role:update")
			return err
		},
	} {
		if err := call(); !errors.Is(err, model.ErrRevokedTokensUnavailable) || errors.Is(err, model.ErrAccessTokenInvalid) {
			t.Errorf("%s: error = %v, want ErrRevokedTokensUnavailable", name, err)
		}
	}
}

func TestAuthenticateUserOnlyConsultsTheListForAValidToken(t *testing.T) {
	revoked := newRevokedList()
	useCase, _ := newUserAuthorizerWith(t, revoked)

	for _, bearer := range []string{"", "forged-token"} {
		_, _ = useCase.AuthenticateUser(context.Background(), bearer)
	}

	if len(revoked.journal.steps) != 0 {
		t.Errorf("the list was consulted %v for tokens that are not valid, want never", revoked.journal.steps)
	}
}
