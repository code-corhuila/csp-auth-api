package usecase

import (
	"context"
	"errors"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// VerifyEmailChangePorts are the outbound ports VerifyEmailChange needs.
type VerifyEmailChangePorts struct {
	Requests     out.EmailVerificationRepository
	Outbox       out.UserEmailChangedOutbox
	IDs          out.IDGenerator
	Clock        out.Clock
	Transactions out.TransactionManager
}

// VerifyEmailChange implements in.VerifyEmailChange (HU-AUTH-004, ADR-034).
type VerifyEmailChange struct {
	ports VerifyEmailChangePorts
}

var _ in.VerifyEmailChange = (*VerifyEmailChange)(nil)

// NewVerifyEmailChange wires the use case with the ports it needs.
func NewVerifyEmailChange(ports VerifyEmailChangePorts) *VerifyEmailChange {
	return &VerifyEmailChange{ports: ports}
}

// VerifyChange locks the pending request and checks the code. The right code changes the email and
// appends UserEmailChanged in the same transaction. A refusal that must be remembered, a wrong code
// counted or a request invalidated because the address was taken, is returned after the
// transaction commits, so what it wrote is kept.
func (c *VerifyEmailChange) VerifyChange(ctx context.Context, command in.VerifyEmailChangeCommand) error {
	code, err := model.NewVerificationCode(command.VerificationCode)
	if err != nil {
		return err
	}
	var refusal error
	err = c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		var failure error
		refusal, failure = c.verify(ctx, command.UserID, code)
		return failure
	})
	if err != nil {
		return err
	}
	return refusal
}

// verify returns the refusal to answer once the transaction commits and, apart from it, the failure
// that rolls the transaction back.
func (c *VerifyEmailChange) verify(ctx context.Context, userID string, code model.VerificationCode) (refusal, failure error) {
	now := c.ports.Clock.Now()
	request, err := c.ports.Requests.FindPendingForUpdate(ctx, userID)
	if errors.Is(err, model.ErrEmailChangeNotFound) {
		return model.ErrVerificationRejected, nil
	}
	if err != nil {
		return nil, err
	}
	switch err := request.Submit(code, now); {
	case errors.Is(err, model.ErrWrongVerificationCode):
		return model.ErrVerificationRejected, c.ports.Requests.RecordWrongAttempt(ctx, request, now)
	case err != nil:
		return err, nil
	}
	err = c.ports.Requests.ConfirmEmailChange(ctx, request, now)
	if errors.Is(err, model.ErrEmailAlreadyRegistered) {
		return err, c.ports.Requests.Invalidate(ctx, request, now)
	}
	if err != nil {
		return nil, err
	}
	event := model.NewUserEmailChanged(c.ports.IDs.NewID(), now, userID, request.NewEmail())
	return nil, c.ports.Outbox.AppendEmailChanged(ctx, event)
}
