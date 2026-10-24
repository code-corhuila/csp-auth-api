package usecase

import (
	"context"
	"errors"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ChangePasswordPorts are the outbound ports ChangePassword needs.
type ChangePasswordPorts struct {
	Users        out.UserRepository
	Hashes       out.PasswordHashLocker
	Passwords    out.PasswordUpdater
	Sessions     out.RefreshTokenRevoker
	Hasher       out.PasswordHasher
	Attempts     out.PasswordChangeAttempts
	Tokens       out.TokenIssuer
	Refresh      in.IssueRefreshToken
	Clock        out.Clock
	Transactions out.TransactionManager
}

// ChangePassword implements in.ChangePassword (HU-AUTH-007, ADR-051).
type ChangePassword struct {
	ports   ChangePasswordPorts
	session sessionIssuer
}

var _ in.ChangePassword = (*ChangePassword)(nil)

// NewChangePassword wires the use case with the ports it needs.
func NewChangePassword(ports ChangePasswordPorts) *ChangePassword {
	return &ChangePassword{ports: ports, session: sessionIssuer{accessTokens: ports.Tokens, sessions: ports.Refresh, clock: ports.Clock}}
}

// Change validates both passwords first: a text that cannot be a password never reaches the comparison and is not a
// failure. A user whose change is locked is refused with *model.PasswordChangeRateLimitedError before anything else, so
// a right password does not help and no bcrypt work is done. Then, in one transaction, it locks the account, verifies the
// current password, refuses a new password equal to it, replaces the hash, revokes every refresh token of the user and opens
// the session of the device that asked: all or nothing. Only a wrong current password is counted against the limit; a
// success forgets the count. The new password is hashed only once the current one is proved, so a wrong guess costs one
// comparison.
func (c *ChangePassword) Change(ctx context.Context, command in.ChangePasswordCommand) (in.LoginUserResult, error) {
	if err := model.CheckPresentedPassword(command.CurrentPassword); err != nil {
		return in.LoginUserResult{}, err
	}
	replacement, err := model.NewPassword(command.NewPassword)
	if err != nil {
		return in.LoginUserResult{}, err
	}
	if err := c.ensureNotLocked(ctx, command.UserID); err != nil {
		return in.LoginUserResult{}, err
	}
	var session in.LoginUserResult
	err = c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		var changeErr error
		session, changeErr = c.replace(ctx, command, replacement)
		return changeErr
	})
	switch {
	case errors.Is(err, model.ErrWrongCurrentPassword):
		c.recordFailure(ctx, command.UserID)
	case err == nil:
		c.forgetFailures(ctx, command.UserID)
	}
	return session, err
}

func (c *ChangePassword) replace(ctx context.Context, command in.ChangePasswordCommand, replacement model.Password) (in.LoginUserResult, error) {
	hash, err := c.ports.Hashes.LockPasswordHashOf(ctx, command.UserID)
	if err != nil {
		return in.LoginUserResult{}, err
	}
	user, err := c.ports.Users.FindByID(ctx, command.UserID)
	if err != nil {
		return in.LoginUserResult{}, err
	}
	if err := user.EnsureCanAuthenticate(); err != nil {
		return in.LoginUserResult{}, err
	}
	if !c.ports.Hasher.Verify(hash, command.CurrentPassword) {
		return in.LoginUserResult{}, model.ErrWrongCurrentPassword
	}
	if c.ports.Hasher.Verify(hash, replacement.Reveal()) {
		return in.LoginUserResult{}, model.ErrPasswordUnchanged
	}
	newHash, err := c.ports.Hasher.Hash(replacement)
	if err != nil {
		return in.LoginUserResult{}, err
	}
	now := c.ports.Clock.Now()
	if err := c.ports.Passwords.UpdatePasswordHash(ctx, user.ID(), newHash, now); err != nil {
		return in.LoginUserResult{}, err
	}
	if _, err := c.ports.Sessions.RevokeAllActiveByUser(ctx, user.ID(), now); err != nil {
		return in.LoginUserResult{}, err
	}
	return c.session.open(ctx, user, command.UserAgent)
}

// ensureNotLocked rejects a user whose change is locked. When the store cannot be reached the change goes on: the limit is
// a protection, not a condition of changing the password, and the bulkhead and the gateway still bound the rate.
func (c *ChangePassword) ensureNotLocked(ctx context.Context, userID string) error {
	remaining, err := c.ports.Attempts.Locked(ctx, userID)
	if err != nil {
		warnUnlessPaused("password change limit unavailable, the change goes on", err)
		return nil
	}
	if remaining > 0 {
		return &model.PasswordChangeRateLimitedError{RetryAfter: remaining}
	}
	return nil
}

func (c *ChangePassword) recordFailure(ctx context.Context, userID string) {
	if err := c.ports.Attempts.RecordFailure(ctx, userID); err != nil {
		warnUnlessPaused("wrong current password could not be counted", err)
	}
}

func (c *ChangePassword) forgetFailures(ctx context.Context, userID string) {
	if err := c.ports.Attempts.Clear(ctx, userID); err != nil {
		warnUnlessPaused("wrong current passwords could not be cleared", err)
	}
}
