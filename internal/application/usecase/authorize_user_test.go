package usecase

import (
	"context"
	"errors"
	"testing"

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
	admin, err := model.NewAccessClaims("admin-1", []model.Role{model.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	client, err := model.NewAccessClaims("client-1", []model.Role{model.RoleClient})
	if err != nil {
		t.Fatal(err)
	}
	tokens := &fakeAccessTokens{claims: map[string]model.AccessClaims{"admin-token": admin, "client-token": client}}
	return NewAuthorizeUser(tokens), tokens
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
	useCase := NewAuthorizeUser(failingAccessTokens{failure})

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
