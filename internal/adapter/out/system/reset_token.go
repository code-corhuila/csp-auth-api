package system

import (
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ResetTokenGenerator draws reset tokens from the cryptographic source of model.NewOpaqueToken (ADR-050).
type ResetTokenGenerator struct{}

var _ out.ResetTokenGenerator = ResetTokenGenerator{}

// NewToken returns a random UUID of version 4 as a reset token.
func (ResetTokenGenerator) NewToken() (model.ResetToken, error) {
	raw, err := model.NewOpaqueToken()
	if err != nil {
		return model.ResetToken{}, err
	}
	return model.NewResetToken(raw)
}
