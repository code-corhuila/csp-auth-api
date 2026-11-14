package usecase

import (
	"context"
	"errors"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RequestEmailChangePorts are the outbound ports RequestEmailChange needs.
type RequestEmailChangePorts struct {
	Users        out.UserRepository
	Requests     out.EmailVerificationRepository
	Keys         out.EmailChangeKeyRepository
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

// emailChangeRequest is a validated request: the key, the hash of the account and address it was made for.
type emailChangeRequest struct {
	key    model.IdempotencyKey
	hash   string
	userID string
	email  model.Email
}

// RequestChange stores the pending request and its idempotency key, supersedes the previous request and
// hands the code to the sender in one transaction: if the sender fails nothing is kept and the user asks
// again. Once the account is locked it looks the key up: a key used by the same account and address is a
// replay that creates and sends nothing and is not counted against the limit, by another one
// model.ErrIdempotencyKeyConflict. The key is stored only when a request is created, so a refused request
// (address taken, limit reached) leaves no key.
//
// The account lock serializes the same key of one account. The same key of another account loses on the
// key: it rolls back before anything is sent and looks the key up once more in a new transaction, which
// now sees the winner. The retry is bounded to one.
func (c *RequestEmailChange) RequestChange(ctx context.Context, command in.RequestEmailChangeCommand) error {
	key, err := model.NewIdempotencyKey(command.IdempotencyKey)
	if err != nil {
		return err
	}
	email, err := model.NewEmail(command.Email)
	if err != nil {
		return err
	}
	request := emailChangeRequest{key: key, hash: model.EmailChangeRequestHash(command.UserID, email), userID: command.UserID, email: email}
	err = c.requestOnce(ctx, request)
	if errors.Is(err, model.ErrIdempotencyKeyTaken) {
		err = c.requestOnce(ctx, request)
	}
	return err
}

func (c *RequestEmailChange) requestOnce(ctx context.Context, request emailChangeRequest) error {
	return c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		return c.request(ctx, request)
	})
}

func (c *RequestEmailChange) request(ctx context.Context, request emailChangeRequest) error {
	userID, email := request.userID, request.email
	now := c.ports.Clock.Now()
	if err := c.ports.Requests.LockRequestsOf(ctx, userID); err != nil {
		return err
	}
	record, found, err := c.ports.Keys.Find(ctx, request.key)
	if err != nil {
		return err
	}
	if found {
		return replayOf(record.RequestHash, request.hash)
	}
	taken, err := c.ports.Users.ExistsByEmail(ctx, email)
	if err != nil {
		return err
	}
	if taken {
		return model.ErrEmailAlreadyRegistered
	}
	requestedAt, err := c.ports.Requests.RequestTimesSince(ctx, userID, now.Add(-model.EmailChangeRequestWindow))
	if err != nil {
		return err
	}
	if err := model.CheckEmailChangeRate(requestedAt, now); err != nil {
		return err
	}
	if err := c.ports.Requests.SupersedePending(ctx, userID, now); err != nil {
		return err
	}
	code, err := c.ports.Codes.NewCode()
	if err != nil {
		return err
	}
	pending := model.NewEmailChangeRequest(c.ports.IDs.NewID(), userID, email, code, now)
	if err := c.ports.Requests.Add(ctx, pending); err != nil {
		return err
	}
	if err := c.ports.Keys.Save(ctx, request.key, out.EmailChangeKeyRecord{RequestHash: request.hash, EmailVerificationID: pending.ID()}); err != nil {
		return err
	}
	return c.ports.Sender.Send(ctx, out.VerificationCodeDelivery{
		RequestID: pending.ID(), UserID: userID, NewEmail: email, Code: code, ExpiresAt: pending.ExpiresAt(),
	})
}
