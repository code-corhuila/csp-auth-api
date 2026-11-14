package mail

import (
	"context"
	"errors"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ErrRegistrationMailNotConfigured is the failure of every delivery of a service that has no SMTP relay or no
// confirmation link: the registration still answers as usual and the use case logs the failure as a WARN.
var ErrRegistrationMailNotConfigured = errors.New("registration messages are not delivered: the SMTP relay or the confirmation link is not configured")

// UnconfiguredRegistrationSender implements out.RegistrationSender for a service without a relay (null object): it
// delivers nothing, so the answer of the registration does not depend on whether the relay exists.
type UnconfiguredRegistrationSender struct{}

var _ out.RegistrationSender = UnconfiguredRegistrationSender{}

// SendConfirmation always fails with ErrRegistrationMailNotConfigured.
func (UnconfiguredRegistrationSender) SendConfirmation(context.Context, out.RegistrationConfirmation) error {
	return ErrRegistrationMailNotConfigured
}

// SendAccountNotice always fails with ErrRegistrationMailNotConfigured.
func (UnconfiguredRegistrationSender) SendAccountNotice(context.Context, model.Email) error {
	return ErrRegistrationMailNotConfigured
}
