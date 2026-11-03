package system

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// codeSpace is the number of six-digit codes, 000000 to 999999.
var codeSpace = big.NewInt(1_000_000)

// VerificationCodeGenerator draws verification codes uniformly from a cryptographic source
// (ADR-034).
type VerificationCodeGenerator struct {
	source io.Reader
}

var _ out.VerificationCodeGenerator = VerificationCodeGenerator{}

// NewVerificationCodeGenerator creates a generator over crypto/rand.
func NewVerificationCodeGenerator() VerificationCodeGenerator {
	return VerificationCodeGenerator{source: rand.Reader}
}

// NewCode returns a code of six decimal digits, leading zeros kept.
func (g VerificationCodeGenerator) NewCode() (model.VerificationCode, error) {
	n, err := rand.Int(g.source, codeSpace)
	if err != nil {
		return model.VerificationCode{}, fmt.Errorf("draw a verification code: %w", err)
	}
	return model.NewVerificationCode(fmt.Sprintf("%06d", n.Int64()))
}
