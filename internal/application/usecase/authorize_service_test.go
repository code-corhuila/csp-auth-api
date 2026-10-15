package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type fakeServiceTokens struct {
	subjects map[string]string
	called   int
}

func (f *fakeServiceTokens) VerifyServiceToken(token string) (string, error) {
	f.called++
	if subject, ok := f.subjects[token]; ok {
		return subject, nil
	}
	return "", model.ErrServiceTokenInvalid
}

func newAuthorizer(allowed ...string) (*AuthorizeService, *fakeServiceTokens) {
	tokens := &fakeServiceTokens{subjects: map[string]string{"worker-token": "csp-worker", "user-token": "7c1e0a7e-user", "other-token": "booking-service"}}
	return NewAuthorizeService(tokens, allowed), tokens
}

func TestAuthorizeServiceAcceptsAValidTokenOfAnAllowedSubject(t *testing.T) {
	for _, allowed := range [][]string{{"csp-worker"}, {"booking-service", "csp-worker"}} {
		useCase, _ := newAuthorizer(allowed...)

		if err := useCase.AuthorizeService(context.Background(), "worker-token"); err != nil {
			t.Errorf("allowed %v: error = %v, want nil", allowed, err)
		}
	}
}

func TestAuthorizeServiceForbidsAValidTokenWhoseSubjectIsNotAllowed(t *testing.T) {
	useCase, _ := newAuthorizer("csp-worker")

	for _, token := range []string{"user-token", "other-token"} {
		if err := useCase.AuthorizeService(context.Background(), token); !errors.Is(err, model.ErrServiceNotAllowed) {
			t.Errorf("%s: error = %v, want ErrServiceNotAllowed", token, err)
		}
	}
}

func TestAuthorizeServiceForbidsEveryValidTokenWhenNoSubjectIsConfigured(t *testing.T) {
	useCase, _ := newAuthorizer()

	if err := useCase.AuthorizeService(context.Background(), "worker-token"); !errors.Is(err, model.ErrServiceNotAllowed) {
		t.Errorf("error = %v, want ErrServiceNotAllowed", err)
	}
}

func TestAuthorizeServiceRejectsAMissingOrInvalidToken(t *testing.T) {
	useCase, tokens := newAuthorizer("csp-worker")

	for _, token := range []string{"", "forged-token"} {
		if err := useCase.AuthorizeService(context.Background(), token); !errors.Is(err, model.ErrServiceTokenInvalid) {
			t.Errorf("%q: error = %v, want ErrServiceTokenInvalid", token, err)
		}
	}
	if tokens.called != 1 {
		t.Errorf("the verifier was called %d times, want 1: an empty token is rejected without asking it", tokens.called)
	}
}

func TestAuthorizeServiceIgnoresBlankSubjectsOfTheConfiguration(t *testing.T) {
	tokens := &fakeServiceTokens{subjects: map[string]string{"blank": ""}}

	err := NewAuthorizeService(tokens, []string{""}).AuthorizeService(context.Background(), "blank")

	if !errors.Is(err, model.ErrServiceNotAllowed) {
		t.Errorf("error = %v, want ErrServiceNotAllowed: an empty subject is never allowed", err)
	}
}
