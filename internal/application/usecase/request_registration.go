package usecase

import (
	"context"
	"errors"
	"log/slog"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RequestRegistrationPorts are the outbound ports RequestRegistration needs.
type RequestRegistrationPorts struct {
	Users         out.UserRepository
	Registrations out.RegistrationRequestRepository
	Hasher        out.PasswordHasher
	Tokens        out.ResetTokenGenerator
	Sender        out.RegistrationSender
	IDs           out.IDGenerator
	Clock         out.Clock
	Transactions  out.TransactionManager
}

// RequestRegistration implements in.RequestRegistration (issue csp-docs#282, Norma 5.3.8).
type RequestRegistration struct {
	ports RequestRegistrationPorts
}

var _ in.RequestRegistration = (*RequestRegistration)(nil)

// NewRequestRegistration wires the use case with the ports it needs.
func NewRequestRegistration(ports RequestRegistrationPorts) *RequestRegistration {
	return &RequestRegistration{ports: ports}
}

// registrationMessage is the one message a request sends after the commit.
type registrationMessage int

const (
	nothingToSend registrationMessage = iota
	sendConfirmation
	sendAccountNotice
)

type registrationAttempt struct {
	key         model.IdempotencyKey
	requestHash string
	email       model.Email
	name        model.Name
	phone       model.Phone
	address     model.Address
	hash        string
	token       model.ResetToken
}

type registrationOutcome struct {
	record   out.RegistrationRecord
	replayed bool
	message  registrationMessage
}

// Request validates the command and always does the same work whatever the address is: it hashes the password and draws
// a token. Then, in one transaction, it looks the idempotency key up first: a key used by the same request is a replay
// that creates and sends nothing, by another request model.ErrIdempotencyKeyConflict, which depends only on the key and
// the request and never on the account. A new key is saved whatever the address is, with the pending registration of a
// free address within its limit (it supersedes the previous one), so every outcome leaves the same trace. The message
// (the link for a free address, the notice for an address with an account, none over the limit) is handed to the sender
// after the commit, so neither its latency nor its failure changes the answer.
//
// A concurrent request with the same key loses on the key: it rolls back and looks the key up once more in a new
// transaction, which now sees the winner. The retry is bounded to one.
func (c *RequestRegistration) Request(ctx context.Context, command in.RequestRegistrationCommand) (in.RequestRegistrationResult, error) {
	attempt, err := c.newAttempt(command)
	if err != nil {
		return in.RequestRegistrationResult{}, err
	}
	outcome, err := c.recordOnce(ctx, attempt)
	if errors.Is(err, model.ErrIdempotencyKeyTaken) {
		outcome, err = c.recordOnce(ctx, attempt)
	}
	if err != nil {
		return in.RequestRegistrationResult{}, err
	}
	c.send(ctx, attempt, outcome)
	return in.RequestRegistrationResult{RequestID: outcome.record.ID, Replayed: outcome.replayed}, nil
}

func (c *RequestRegistration) newAttempt(command in.RequestRegistrationCommand) (registrationAttempt, error) {
	key, err := model.NewIdempotencyKey(command.IdempotencyKey)
	if err != nil {
		return registrationAttempt{}, err
	}
	email, err := model.NewEmail(command.Email)
	if err != nil {
		return registrationAttempt{}, err
	}
	password, err := model.NewPassword(command.Password)
	if err != nil {
		return registrationAttempt{}, err
	}
	name, err := model.NewName(command.Name)
	if err != nil {
		return registrationAttempt{}, err
	}
	phone, err := model.NewPhone(command.Phone)
	if err != nil {
		return registrationAttempt{}, err
	}
	address, err := model.NewAddress(command.Address)
	if err != nil {
		return registrationAttempt{}, err
	}
	hash, err := c.ports.Hasher.Hash(password)
	if err != nil {
		return registrationAttempt{}, err
	}
	token, err := c.ports.Tokens.NewToken()
	if err != nil {
		return registrationAttempt{}, err
	}
	return registrationAttempt{
		key: key, requestHash: model.RegistrationRequestHash(email, name, phone, address),
		email: email, name: name, phone: phone, address: address, hash: hash, token: token,
	}, nil
}

// recordOnce runs one transaction and returns what to answer and what to send.
func (c *RequestRegistration) recordOnce(ctx context.Context, attempt registrationAttempt) (registrationOutcome, error) {
	var outcome registrationOutcome
	err := c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		outcome = registrationOutcome{}
		record, found, err := c.ports.Registrations.FindByKey(ctx, attempt.key)
		if err != nil {
			return err
		}
		if found {
			outcome.record, outcome.replayed = record, true
			return replayOf(record.RequestHash, attempt.requestHash)
		}
		outcome, err = c.store(ctx, attempt)
		return err
	})
	return outcome, err
}

// store records the request: the pending registration of a free address, or only the trace of a request that creates
// nothing, which is what an address with an account and an address over its limit get.
func (c *RequestRegistration) store(ctx context.Context, attempt registrationAttempt) (registrationOutcome, error) {
	now := c.ports.Clock.Now()
	if err := c.ports.Registrations.LockEmail(ctx, attempt.email); err != nil {
		return registrationOutcome{}, err
	}
	taken, err := c.ports.Users.ExistsByEmail(ctx, attempt.email)
	if err != nil {
		return registrationOutcome{}, err
	}
	requested, err := c.ports.Registrations.CountRequestsSince(ctx, attempt.email, now.Add(-model.RegistrationRequestWindow))
	if err != nil {
		return registrationOutcome{}, err
	}
	outcome := registrationOutcome{record: out.RegistrationRecord{ID: c.ports.IDs.NewID(), RequestHash: attempt.requestHash}}
	switch within := model.RegistrationRequestAllowed(requested); {
	case within && taken:
		outcome.message = sendAccountNotice
	case within:
		outcome.message = sendConfirmation
		if err := c.ports.Registrations.SupersedePending(ctx, attempt.email, now); err != nil {
			return registrationOutcome{}, err
		}
		outcome.record.Request = model.NewRegistrationRequest(outcome.record.ID, attempt.email, attempt.hash, attempt.name, attempt.phone, attempt.address, attempt.token, now)
	}
	return outcome, c.ports.Registrations.Add(ctx, attempt.key, outcome.record, attempt.email, now)
}

func (c *RequestRegistration) send(ctx context.Context, attempt registrationAttempt, outcome registrationOutcome) {
	var err error
	switch outcome.message {
	case sendConfirmation:
		err = c.ports.Sender.SendConfirmation(ctx, out.RegistrationConfirmation{Email: attempt.email, Token: attempt.token, ExpiresAt: outcome.record.Request.ExpiresAt()})
	case sendAccountNotice:
		err = c.ports.Sender.SendAccountNotice(ctx, attempt.email)
	default:
		return
	}
	if err != nil {
		slog.WarnContext(ctx, "registration message not sent", "requestId", outcome.record.ID, "error", err)
	}
}
