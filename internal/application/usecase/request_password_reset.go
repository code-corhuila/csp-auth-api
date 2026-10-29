package usecase

import (
	"context"
	"errors"
	"log/slog"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RequestPasswordResetPorts are the outbound ports RequestPasswordReset needs.
type RequestPasswordResetPorts struct {
	Users        out.UserRepository
	Resets       out.PasswordResetRepository
	Keys         out.PasswordResetKeyRepository
	Tokens       out.ResetTokenGenerator
	Sender       out.PasswordResetSender
	IDs          out.IDGenerator
	Clock        out.Clock
	Transactions out.TransactionManager
}

// RequestPasswordReset implements in.RequestPasswordReset (HU-AUTH-006, ADR-050, Norma 5.3.8).
type RequestPasswordReset struct {
	ports RequestPasswordResetPorts
}

var _ in.RequestPasswordReset = (*RequestPasswordReset)(nil)

// NewRequestPasswordReset wires the use case with the ports it needs.
func NewRequestPasswordReset(ports RequestPasswordResetPorts) *RequestPasswordReset {
	return &RequestPasswordReset{ports: ports}
}

// passwordResetRequest is a validated request: the key, the hash of the address it was made for and the account
// found for that address, nil when there is none or it is not active.
type passwordResetRequest struct {
	key   model.IdempotencyKey
	hash  string
	email model.Email
	user  *model.User
	token model.ResetToken
}

// RequestReset looks the account up and draws a token whatever the email is, so an unknown address, an
// inactive account and a real one do the same work up to there. Then, in one transaction, it looks the
// idempotency key up: a key used by the same address is a replay that creates and sends nothing, by
// another address model.ErrIdempotencyKeyConflict, which depends only on the key and the address and
// never on the account. A new key is saved whatever the account is, linked to the stored token of an
// active account within its limit that supersedes the previous one, so every outcome leaves the same
// trace. The message is handed to the sender after the commit, so neither its latency nor its failure
// changes the answer (ADR-050).
//
// A concurrent request with the same key loses on the key: it rolls back and looks the key up once more
// in a new transaction, which now sees the winner. The retry is bounded to one.
func (c *RequestPasswordReset) RequestReset(ctx context.Context, command in.RequestPasswordResetCommand) error {
	request, err := c.newRequest(ctx, command)
	if err != nil {
		return err
	}
	reset, err := c.recordOnce(ctx, request)
	if errors.Is(err, model.ErrIdempotencyKeyTaken) {
		reset, err = c.recordOnce(ctx, request)
	}
	if err != nil || reset == nil {
		return err
	}
	delivery := out.PasswordResetDelivery{UserID: request.user.ID(), Email: request.email, Token: request.token, ExpiresAt: reset.ExpiresAt()}
	if err := c.ports.Sender.Send(ctx, delivery); err != nil {
		slog.Warn("password reset link not sent", "userId", request.user.ID(), "error", err)
	}
	return nil
}

func (c *RequestPasswordReset) newRequest(ctx context.Context, command in.RequestPasswordResetCommand) (passwordResetRequest, error) {
	key, err := model.NewIdempotencyKey(command.IdempotencyKey)
	if err != nil {
		return passwordResetRequest{}, err
	}
	email, err := model.NewEmail(command.Email)
	if err != nil {
		return passwordResetRequest{}, err
	}
	user, err := c.ports.Users.FindByEmail(ctx, email)
	if errors.Is(err, model.ErrUserNotFound) {
		user = nil
	} else if err != nil {
		return passwordResetRequest{}, err
	}
	token, err := c.ports.Tokens.NewToken()
	if err != nil {
		return passwordResetRequest{}, err
	}
	if user != nil && user.Status() != model.UserActive {
		user = nil
	}
	return passwordResetRequest{key: key, hash: model.PasswordResetRequestHash(email), email: email, user: user, token: token}, nil
}

// recordOnce runs one transaction. It returns the stored request to deliver, or nil when the key is a
// replay or the request created nothing.
func (c *RequestPasswordReset) recordOnce(ctx context.Context, request passwordResetRequest) (*model.PasswordReset, error) {
	var reset *model.PasswordReset
	err := c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		reset = nil
		record, found, err := c.ports.Keys.Find(ctx, request.key)
		if err != nil {
			return err
		}
		if found {
			return replayOf(record.RequestHash, request.hash)
		}
		if request.user != nil {
			if reset, err = c.store(ctx, request.user.ID(), request.token); err != nil {
				return err
			}
		}
		record = out.PasswordResetKeyRecord{RequestHash: request.hash}
		if reset != nil {
			record.PasswordResetID = reset.ID()
		}
		return c.ports.Keys.Save(ctx, request.key, record)
	})
	return reset, err
}

// replayOf is nil for a key already used by the same request and model.ErrIdempotencyKeyConflict for another.
func replayOf(recordedHash, requestHash string) error {
	if recordedHash != requestHash {
		return model.ErrIdempotencyKeyConflict
	}
	return nil
}

// store supersedes the pending request and adds the new one. It returns nil when the account is gone
// or has used its requests of the rolling hour: nothing is created and the caller answers the same.
func (c *RequestPasswordReset) store(ctx context.Context, userID string, token model.ResetToken) (*model.PasswordReset, error) {
	now := c.ports.Clock.Now()
	if err := c.ports.Resets.LockRequestsOf(ctx, userID); errors.Is(err, model.ErrUserNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	requested, err := c.ports.Resets.CountRequestsSince(ctx, userID, now.Add(-model.PasswordResetRequestWindow))
	if err != nil {
		return nil, err
	}
	if !model.PasswordResetRequestAllowed(requested) {
		return nil, nil
	}
	if err := c.ports.Resets.SupersedePending(ctx, userID, now); err != nil {
		return nil, err
	}
	reset := model.NewPasswordReset(c.ports.IDs.NewID(), userID, token, now)
	return reset, c.ports.Resets.Add(ctx, reset)
}
