package usecase

import (
	"context"
	"errors"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ConfirmRegistrationPorts are the outbound ports ConfirmRegistration needs.
type ConfirmRegistrationPorts struct {
	Users         out.UserRepository
	Registrations out.RegistrationRequestRepository
	Keys          out.IdempotencyKeyRepository
	Outbox        out.OutboxWriter
	IDs           out.IDGenerator
	Clock         out.Clock
	Transactions  out.TransactionManager
	Tokens        out.TokenIssuer
	Sessions      in.IssueRefreshToken
}

// ConfirmRegistration implements in.ConfirmRegistration (HU-AUTH-001, issue csp-docs#282, Norma 5.3.8).
type ConfirmRegistration struct {
	ports   ConfirmRegistrationPorts
	session sessionIssuer
}

var _ in.ConfirmRegistration = (*ConfirmRegistration)(nil)

// NewConfirmRegistration wires the use case with the ports it needs.
func NewConfirmRegistration(ports ConfirmRegistrationPorts) *ConfirmRegistration {
	return &ConfirmRegistration{ports: ports, session: sessionIssuer{accessTokens: ports.Tokens, sessions: ports.Sessions, clock: ports.Clock}}
}

// Confirm validates the command and, in one transaction, looks the idempotency key up first. A key already used by the
// same token is a replay (the account, no tokens, nothing created); by another token, model.ErrIdempotencyKeyConflict; a
// new key redeems the token and saves the CLIENT user, the key and the UserRegistered event together, and the tokens are
// issued after the commit. The hash of the token is what the key stands for.
//
// A concurrent request with the same key loses on the key or on the unique email index: it rolls back and looks the key
// up once more in a new transaction, which now sees the winner. The retry is bounded to one.
func (c *ConfirmRegistration) Confirm(ctx context.Context, command in.ConfirmRegistrationCommand) (in.ConfirmRegistrationResult, error) {
	key, err := model.NewIdempotencyKey(command.IdempotencyKey)
	if err != nil {
		return in.ConfirmRegistrationResult{}, err
	}
	token, err := model.NewResetToken(command.Token)
	if err != nil {
		return in.ConfirmRegistrationResult{}, err
	}
	user, replayed, err := c.confirmOnce(ctx, key, token.Hash())
	if lostRace(err) {
		user, replayed, err = c.confirmOnce(ctx, key, token.Hash())
	}
	if err != nil {
		return in.ConfirmRegistrationResult{}, err
	}
	if replayed {
		summary, err := summarizeUser(user)
		if err != nil {
			return in.ConfirmRegistrationResult{}, err
		}
		return in.ConfirmRegistrationResult{Replayed: true, Session: in.LoginUserResult{User: summary}}, nil
	}
	session, err := c.session.open(ctx, user, command.UserAgent)
	if err != nil {
		return in.ConfirmRegistrationResult{}, err
	}
	return in.ConfirmRegistrationResult{Session: session}, nil
}

func lostRace(err error) bool {
	return errors.Is(err, model.ErrIdempotencyKeyTaken) || errors.Is(err, model.ErrEmailAlreadyRegistered)
}

// confirmOnce runs one transaction: it returns the account of a replay or the one it just created.
func (c *ConfirmRegistration) confirmOnce(ctx context.Context, key model.IdempotencyKey, tokenHash string) (*model.User, bool, error) {
	var user *model.User
	var replayed bool
	err := c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		user, replayed = nil, false
		record, found, err := c.ports.Keys.Find(ctx, key)
		if err != nil {
			return err
		}
		if found {
			replayed = true
			if err := replayOf(record.RequestHash, tokenHash); err != nil {
				return err
			}
			user, err = c.ports.Users.FindByID(ctx, record.UserID)
			return err
		}
		user, err = c.create(ctx, key, tokenHash)
		return err
	})
	return user, replayed, err
}

func (c *ConfirmRegistration) create(ctx context.Context, key model.IdempotencyKey, tokenHash string) (*model.User, error) {
	request, err := c.ports.Registrations.LockByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	now := c.ports.Clock.Now()
	if err := request.Redeem(now); err != nil {
		return nil, err
	}
	taken, err := c.ports.Users.ExistsByEmail(ctx, request.Email())
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, model.ErrEmailAlreadyRegistered
	}
	user, err := request.Account(c.ports.IDs.NewID())
	if err != nil {
		return nil, err
	}
	if err := c.ports.Users.Save(ctx, user); err != nil {
		return nil, err
	}
	if err := c.ports.Keys.Save(ctx, key, out.IdempotencyRecord{UserID: user.ID(), RequestHash: tokenHash}); err != nil {
		return nil, err
	}
	if err := c.ports.Registrations.MarkUsed(ctx, request); err != nil {
		return nil, err
	}
	return user, c.ports.Outbox.Append(ctx, model.NewUserRegistered(c.ports.IDs.NewID(), now, user))
}
