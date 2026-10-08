package usecase

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const refreshTTL = 7 * 24 * time.Hour

type fakeRefreshTokens struct {
	saved []*model.RefreshToken
	err   error
}

func (r *fakeRefreshTokens) Save(_ context.Context, token *model.RefreshToken) error {
	if r.err != nil {
		return r.err
	}
	r.saved = append(r.saved, token)
	return nil
}

func (*fakeRefreshTokens) FindByHash(context.Context, string) (*model.RefreshToken, error) {
	return nil, model.ErrRefreshTokenNotFound
}

func (*fakeRefreshTokens) Revoke(context.Context, string, time.Time) error { return nil }

func TestIssueStoresTheDigestAndReturnsTheRawTokenOnce(t *testing.T) {
	tokens := &fakeRefreshTokens{}
	useCase := NewIssueRefreshToken(tokens, &fakeIDs{next: []string{"token-1"}}, fakeClock{}, refreshTTL)

	issued, err := useCase.Issue(context.Background(), in.IssueRefreshTokenCommand{UserID: "user-1", UserAgent: "curl/8"})

	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	raw, decodeErr := base64.RawURLEncoding.DecodeString(issued.Token)
	if decodeErr != nil || len(raw) < 32 {
		t.Errorf("Token %q is not base64url of at least 32 bytes", issued.Token)
	}
	if want := registeredAt.Add(refreshTTL); !issued.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", issued.ExpiresAt, want)
	}
	if len(tokens.saved) != 1 {
		t.Fatalf("saved %d tokens, want 1", len(tokens.saved))
	}
	stored := tokens.saved[0]
	if stored.Hash() != model.HashOpaqueToken(issued.Token) || stored.Hash() == issued.Token {
		t.Errorf("stored hash %q is not the digest of the returned token", stored.Hash())
	}
	if stored.ID() != "token-1" || stored.UserID() != "user-1" || stored.UserAgent() != "curl/8" || !stored.ExpiresAt().Equal(issued.ExpiresAt) {
		t.Errorf("unexpected stored token %+v", stored)
	}
}

func TestIssueGivesEachCallADifferentToken(t *testing.T) {
	useCase := NewIssueRefreshToken(&fakeRefreshTokens{}, &fakeIDs{next: []string{"a", "b"}}, fakeClock{}, refreshTTL)
	first, _ := useCase.Issue(context.Background(), in.IssueRefreshTokenCommand{UserID: "user-1"})
	second, _ := useCase.Issue(context.Background(), in.IssueRefreshTokenCommand{UserID: "user-1"})
	if first.Token == second.Token {
		t.Error("two calls returned the same token")
	}
}

func TestIssueRejectsAnEmptyUserWithoutSaving(t *testing.T) {
	tokens := &fakeRefreshTokens{}
	useCase := NewIssueRefreshToken(tokens, &fakeIDs{next: []string{"token-1"}}, fakeClock{}, refreshTTL)

	_, err := useCase.Issue(context.Background(), in.IssueRefreshTokenCommand{})

	if !errors.Is(err, model.ErrInvalidUserID) || len(tokens.saved) != 0 {
		t.Errorf("error = %v, saved = %d; want ErrInvalidUserID and nothing saved", err, len(tokens.saved))
	}
}

func TestIssueReturnsNoTokenWhenTheStoreFails(t *testing.T) {
	failure := errors.New("database down")
	useCase := NewIssueRefreshToken(&fakeRefreshTokens{err: failure}, &fakeIDs{next: []string{"token-1"}}, fakeClock{}, refreshTTL)

	issued, err := useCase.Issue(context.Background(), in.IssueRefreshTokenCommand{UserID: "user-1"})

	if !errors.Is(err, failure) || issued.Token != "" {
		t.Errorf("issued = %+v, error = %v; want the store error and no token", issued, err)
	}
}
