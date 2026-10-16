// Package logging is the outbound adapter that writes to the service log.
package logging

import (
	"context"
	"log/slog"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// VerificationCodeSender implements out.VerificationCodeSender by writing the code in the service
// log (pattern Strategy). It is the deliberate, temporary adapter of ADR-034: no service can send
// emails yet, so the team reads the code in the log of development and QA. It must be replaced
// before the email change reaches production. It never logs the address or any token.
type VerificationCodeSender struct {
	logger *slog.Logger
}

var _ out.VerificationCodeSender = VerificationCodeSender{}

// NewVerificationCodeSender creates a sender that writes to logger.
func NewVerificationCodeSender(logger *slog.Logger) VerificationCodeSender {
	return VerificationCodeSender{logger: logger}
}

// Send logs the delivery at INFO.
func (s VerificationCodeSender) Send(ctx context.Context, delivery out.VerificationCodeDelivery) error {
	s.logger.InfoContext(ctx, "email verification code issued",
		"userId", delivery.UserID, "requestId", delivery.RequestID, "code", delivery.Code.String())
	return nil
}
