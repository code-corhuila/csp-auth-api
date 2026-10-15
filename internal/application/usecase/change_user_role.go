package usecase

import (
	"context"

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
func (c *ChangeUserRole) ChangeRole(ctx context.Context, command in.ChangeUserRoleCommand) (in.UserSummary, error) {
	role, err := model.ParseRole(command.Role)
	if err != nil {
		return in.UserSummary{}, err
	}
	var user *model.User
	err = c.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		var changeErr error
		user, changeErr = c.change(ctx, command, role)
		return changeErr
	})
	if err != nil {
		return in.UserSummary{}, err
	}
	return summarizeUser(user)
}

func (c *ChangeUserRole) change(ctx context.Context, command in.ChangeUserRoleCommand, role model.Role) (*model.User, error) {
	activeAdmins := 0
	if !command.Enabled {
		var err error
		if activeAdmins, err = c.ports.Roles.LockActiveAdmins(ctx); err != nil {
			return nil, err
		}
	}
	user, err := c.ports.Users.FindByID(ctx, command.UserID)
	if err != nil {
		return nil, err
	}
	changed, err := user.SetRole(role, command.Enabled, activeAdmins)
	if err != nil || !changed {
		return user, err
	}
	if err := c.ports.Roles.SaveRole(ctx, user, role, command.ActingAdminID); err != nil {
		return nil, err
	}
	event := model.NewUserRoleChanged(c.ports.IDs.NewID(), c.ports.Clock.Now(), user.ID(), role, command.Enabled, command.ActingAdminID)
	return user, c.ports.Outbox.AppendRoleChanged(ctx, event)
}
