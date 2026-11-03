package usecase

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// AuthorizeService implements in.AuthorizeService: an internal operation accepts a valid service
// token whose subject is in the configured list (SERVICE_SUBJECTS, ADR-020).
type AuthorizeService struct {
	tokens  out.ServiceTokenVerifier
	allowed map[string]struct{}
}

var _ in.AuthorizeService = (*AuthorizeService)(nil)

// NewAuthorizeService wires the use case. With no allowed subject every valid token is forbidden.
func NewAuthorizeService(tokens out.ServiceTokenVerifier, allowedSubjects []string) *AuthorizeService {
	allowed := make(map[string]struct{}, len(allowedSubjects))
	for _, subject := range allowedSubjects {
		allowed[subject] = struct{}{}
	}
	return &AuthorizeService{tokens: tokens, allowed: allowed}
}

// AuthorizeService verifies the token first and only then looks at its subject, so a caller that
// is not authenticated never learns which subjects are allowed.
func (a *AuthorizeService) AuthorizeService(_ context.Context, bearerToken string) error {
	if bearerToken == "" {
		return model.ErrServiceTokenInvalid
	}
	subject, err := a.tokens.VerifyServiceToken(bearerToken)
	if err != nil {
		return err
	}
	if _, ok := a.allowed[subject]; !ok || subject == "" {
		return model.ErrServiceNotAllowed
	}
	return nil
}
