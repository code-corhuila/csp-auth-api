package usecase

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// UpdateProfile implements in.UpdateProfile (HU-AUTH-007, ADR-051).
type UpdateProfile struct {
	users        out.UserRepository
	profiles     out.ProfileUpdater
	clock        out.Clock
	transactions out.TransactionManager
}

var _ in.UpdateProfile = (*UpdateProfile)(nil)

// NewUpdateProfile wires the use case with the ports it needs.
func NewUpdateProfile(users out.UserRepository, profiles out.ProfileUpdater, clock out.Clock, transactions out.TransactionManager) *UpdateProfile {
	return &UpdateProfile{users: users, profiles: profiles, clock: clock, transactions: transactions}
}

// Update validates the edit before touching anything. Then, in one transaction, it writes the fields sent and reads the
// account again: a locked account is refused after the write and the transaction rolls it back.
func (u *UpdateProfile) Update(ctx context.Context, command in.UpdateProfileCommand) (in.Profile, error) {
	change, err := model.NewProfileChange(command.Name, command.Phone, command.Address)
	if err != nil {
		return in.Profile{}, err
	}
	var profile in.Profile
	err = u.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		if err := u.profiles.UpdateProfile(ctx, command.UserID, change, u.clock.Now()); err != nil {
			return err
		}
		profile, err = activeProfile(ctx, u.users, command.UserID)
		return err
	})
	return profile, err
}
