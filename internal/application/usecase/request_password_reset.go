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
	Tokens       out.ResetTokenGenerator
	Sender       out.PasswordResetSender
	IDs          out.IDGenerator
	Clock        out.Clock
	Transactions out.TransactionManager
}

// RequestPasswordReset implements in.RequestPasswordReset (HU-AUTH-006, ADR-050).
type RequestPasswordReset struct {
	ports RequestPasswordResetPorts
}

var _ in.RequestPasswordReset = (*RequestPasswordReset)(nil)

// NewRequestPasswordReset wires the use case with the ports it needs.
func NewRequestPasswordReset(ports RequestPasswordResetPorts) *RequestPasswordReset {
	return &RequestPasswordReset{ports: ports}
}

// RequestReset looks the account up and draws a token whatever the email is, so an unknown address, an
// inactive account and a real one do the same work up to there. Only an active account within its
// limit of requests gets a stored token, in one transaction that supersedes the previous one; the
// message is handed to the sender after the commit, so neither its latency nor its failure changes the
// answer (ADR-050).
func (c *RequestPasswordReset) RequestReset(ctx context.Context, command in.RequestPasswordResetCommand) error {
	email, err := model.NewEmail(command.Email)
	if err != nil {
		return err
	}
	user, err := c.ports.Users.FindByEmail(ctx, email)
	if errors.Is(err, model.ErrUserNotFound) {
		user = nil
	} else if err != nil {
		return err
	}
	token, err := c.ports.Tokens.NewToken()
	if err != nil {
		return err
	}
	if user == nil || user.Status() != model.UserActive {
		return nil
	}
	var reset *model.PasswordReset
	err = c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		var storeErr error
		reset, storeErr = c.store(ctx, user.ID(), token)
		return storeErr
	})
	if err != nil || reset == nil {
		return err
	}
	delivery := out.PasswordResetDelivery{UserID: user.ID(), Email: email, Token: token, ExpiresAt: reset.ExpiresAt()}
	if err := c.ports.Sender.Send(ctx, delivery); err != nil {
		slog.Warn("password reset link not sent", "userId", user.ID(), "error", err)
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
