package usecase

import (
	"context"
	"fmt"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ChangeUserRolePorts are the outbound ports ChangeUserRole needs.
type ChangeUserRolePorts struct {
	Users        out.UserRepository
	Roles        out.UserRoleRepository
	Outbox       out.UserRoleOutbox
	IDs          out.IDGenerator
	Clock        out.Clock
	Transactions out.TransactionManager
	// RefreshTokens and Sessions end the sessions of a user who loses ADMIN (ADR-031, amendment 2026-10-24).
	RefreshTokens out.RefreshTokenRepository
	Sessions      out.UserSessionRevocations
}

// ChangeUserRole implements in.ChangeUserRole (HU-AUTH-003, ADR-031).
type ChangeUserRole struct {
	ports ChangeUserRolePorts
}

var _ in.ChangeUserRole = (*ChangeUserRole)(nil)

// NewChangeUserRole wires the use case with the ports it needs.
func NewChangeUserRole(ports ChangeUserRolePorts) *ChangeUserRole {
	return &ChangeUserRole{ports: ports}
}

// ChangeRole applies the change in one transaction: the role and its UserRoleChanged event commit
// together. A revoke first locks the active administrators and only then reads the user, so two
// concurrent revokes are serialized and the second one counts what the first one left. A request
// that changes nothing writes nothing and publishes no event, which makes it idempotent by itself.
//
// Removing ADMIN also ends the sessions of the user: their active refresh tokens are revoked in the
// same transaction, so the role cannot be lost while the sessions survive, and once it has committed
// the access tokens issued up to that instant are marked as ended. If the mark cannot be written the
// error is returned, with the role and the refresh tokens already changed.
func (c *ChangeUserRole) ChangeRole(ctx context.Context, command in.ChangeUserRoleCommand) (in.UserSummary, error) {
	role, err := model.ParseRole(command.Role)
	if err != nil {
		return in.UserSummary{}, err
	}
	var user *model.User
	var sessionsEnded bool
	err = c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		var changeErr error
		user, sessionsEnded, changeErr = c.change(ctx, command, role)
		return changeErr
	})
	if err != nil {
		return in.UserSummary{}, err
	}
	if sessionsEnded {
		if err := c.ports.Sessions.RevokeUserSessions(ctx, user.ID(), c.ports.Clock.Now()); err != nil {
			return in.UserSummary{}, fmt.Errorf("the role was changed but the sessions of the user could not be marked as ended: %w", err)
		}
	}
	return summarizeUser(user)
}

// change applies the change and reports whether the sessions of the user were ended by it.
func (c *ChangeUserRole) change(ctx context.Context, command in.ChangeUserRoleCommand, role model.Role) (*model.User, bool, error) {
	activeAdmins := 0
	if !command.Enabled {
		var err error
		if activeAdmins, err = c.ports.Roles.LockActiveAdmins(ctx); err != nil {
			return nil, false, err
		}
	}
	user, err := c.ports.Users.FindByID(ctx, command.UserID)
	if err != nil {
		return nil, false, err
	}
	changed, err := user.SetRole(role, command.Enabled, activeAdmins)
	if err != nil || !changed {
		return user, false, err
	}
	if err := c.ports.Roles.SaveRole(ctx, user, role, command.ActingAdminID); err != nil {
		return nil, false, err
	}
	now := c.ports.Clock.Now()
	event := model.NewUserRoleChanged(c.ports.IDs.NewID(), now, user.ID(), role, command.Enabled, command.ActingAdminID)
	if err := c.ports.Outbox.AppendRoleChanged(ctx, event); err != nil {
		return nil, false, err
	}
	if command.Enabled || !role.EndsSessionsWhenRemoved() {
		return user, false, nil
	}
	_, err = c.ports.RefreshTokens.RevokeAllActiveByUser(ctx, user.ID(), now)
	return user, err == nil, err
}
