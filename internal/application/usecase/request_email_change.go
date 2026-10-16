package usecase

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RequestEmailChangePorts are the outbound ports RequestEmailChange needs.
type RequestEmailChangePorts struct {
	Users        out.UserRepository
	Requests     out.EmailVerificationRepository
	Codes        out.VerificationCodeGenerator
	Sender       out.VerificationCodeSender
	IDs          out.IDGenerator
	Clock        out.Clock
	Transactions out.TransactionManager
}

// RequestEmailChange implements in.RequestEmailChange (HU-AUTH-004, ADR-034).
type RequestEmailChange struct {
	ports RequestEmailChangePorts
}

var _ in.RequestEmailChange = (*RequestEmailChange)(nil)

// NewRequestEmailChange wires the use case with the ports it needs.
func NewRequestEmailChange(ports RequestEmailChangePorts) *RequestEmailChange {
	return &RequestEmailChange{ports: ports}
}

// RequestChange stores the pending request, supersedes the previous one and hands the code to the
// sender in one transaction: if the sender fails nothing is kept and the user asks again.
func (c *RequestEmailChange) RequestChange(ctx context.Context, command in.RequestEmailChangeCommand) error {
	email, err := model.NewEmail(command.Email)
	if err != nil {
		return err
	}
	return c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		return c.request(ctx, command.UserID, email)
	})
}

func (c *RequestEmailChange) request(ctx context.Context, userID string, email model.Email) error {
	now := c.ports.Clock.Now()
	if err := c.ports.Requests.LockRequestsOf(ctx, userID); err != nil {
		return err
	}
	taken, err := c.ports.Users.ExistsByEmail(ctx, email)
	if err != nil {
		return err
	}
	if taken {
		return model.ErrEmailAlreadyRegistered
	}
	made, err := c.ports.Requests.CountRequestsSince(ctx, userID, now.Add(-model.EmailChangeRequestWindow))
	if err != nil {
		return err
	}
	if made >= model.MaxEmailChangeRequests {
		return model.ErrTooManyEmailChangeRequests
	}
	if err := c.ports.Requests.SupersedePending(ctx, userID, now); err != nil {
		return err
	}
	code, err := c.ports.Codes.NewCode()
	if err != nil {
		return err
	}
	request := model.NewEmailChangeRequest(c.ports.IDs.NewID(), userID, email, code, now)
	if err := c.ports.Requests.Add(ctx, request); err != nil {
		return err
	}
	return c.ports.Sender.Send(ctx, out.VerificationCodeDelivery{
		RequestID: request.ID(), UserID: userID, NewEmail: email, Code: code, ExpiresAt: request.ExpiresAt(),
	})
}
