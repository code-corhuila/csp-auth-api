package usecase

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ResetPasswordPorts are the outbound ports ResetPassword needs.
type ResetPasswordPorts struct {
	Resets       out.PasswordResetRepository
	Hasher       out.PasswordHasher
	Current      out.CurrentPasswordReader
	Passwords    out.PasswordUpdater
	Sessions     out.RefreshTokenRevoker
	Clock        out.Clock
	Transactions out.TransactionManager
}

// ResetPassword implements in.ResetPassword (HU-AUTH-006, ADR-050).
type ResetPassword struct {
	ports ResetPasswordPorts
}

var _ in.ResetPassword = (*ResetPassword)(nil)

// NewResetPassword wires the use case with the ports it needs.
func NewResetPassword(ports ResetPasswordPorts) *ResetPassword {
	return &ResetPassword{ports: ports}
}

// Reset validates the token and the password before touching anything, so a weak password does not
// consume the token, and hashes the password before the transaction, so no lock is held while bcrypt
// runs and a bad token costs the same as a good one. Then, in one transaction, it consumes the token,
// replaces the hash and revokes every refresh token of the user: all or nothing. A password equal to the
// current one is refused with model.ErrPasswordUnchanged, only once the token proved valid, and the
// transaction changes nothing.
func (c *ResetPassword) Reset(ctx context.Context, command in.ResetPasswordCommand) error {
	token, err := model.NewResetToken(command.Token)
	if err != nil {
		return err
	}
	password, err := model.NewPassword(command.Password)
	if err != nil {
		return err
	}
	hash, err := c.ports.Hasher.Hash(password)
	if err != nil {
		return err
	}
	return c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		return c.redeem(ctx, token, password, hash)
	})
}

func (c *ResetPassword) redeem(ctx context.Context, token model.ResetToken, password model.Password, hash string) error {
	now := c.ports.Clock.Now()
	reset, err := c.ports.Resets.LockByTokenHash(ctx, token.Hash())
	if err != nil {
		return err
	}
	if err := reset.EnsureRedeemable(now); err != nil {
		return err
	}
	if err := c.refuseCurrentPassword(ctx, reset.UserID(), password); err != nil {
		return err
	}
	if err := reset.Redeem(now); err != nil {
		return err
	}
	if err := c.ports.Resets.MarkUsed(ctx, reset); err != nil {
		return err
	}
	if err := c.ports.Passwords.UpdatePasswordHash(ctx, reset.UserID(), hash, now); err != nil {
		return err
	}
	_, err = c.ports.Sessions.RevokeAllActiveByUser(ctx, reset.UserID(), now)
	return err
}

func (c *ResetPassword) refuseCurrentPassword(ctx context.Context, userID string, password model.Password) error {
	current, err := c.ports.Current.PasswordHashOf(ctx, userID)
	if err != nil {
		return err
	}
	if c.ports.Hasher.Verify(current, password.Reveal()) {
		return model.ErrPasswordUnchanged
	}
	return nil
}
