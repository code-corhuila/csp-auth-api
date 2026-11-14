package usecase

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// GetProfile implements in.GetProfile (HU-AUTH-007, ADR-051).
type GetProfile struct {
	users out.UserRepository
}

var _ in.GetProfile = (*GetProfile)(nil)

// NewGetProfile wires the use case with the repository of users.
func NewGetProfile(users out.UserRepository) *GetProfile {
	return &GetProfile{users: users}
}

// Get reads the account from the store, not from the token, so the data is current.
func (g *GetProfile) Get(ctx context.Context, userID string) (in.Profile, error) {
	return activeProfile(ctx, g.users, userID)
}

// activeProfile reads the profile of an account that can still authenticate: a locked account is refused with
// model.ErrUserLocked, because a token it holds no longer identifies an active account.
func activeProfile(ctx context.Context, users out.UserRepository, userID string) (in.Profile, error) {
	user, err := users.FindByID(ctx, userID)
	if err != nil {
		return in.Profile{}, err
	}
	if err := user.EnsureCanAuthenticate(); err != nil {
		return in.Profile{}, err
	}
	return profileOf(user), nil
}

// profileOf projects the account to the profile its owner sees. A phone or an address that was never given is nil:
// a stored value is never empty, because the registration requires it.
func profileOf(user *model.User) in.Profile {
	roles := make([]string, 0, len(user.Roles()))
	for _, role := range user.Roles() {
		roles = append(roles, role.String())
	}
	return in.Profile{
		ID:      user.ID(),
		Email:   user.Email().String(),
		Name:    user.Name().String(),
		Phone:   textOrNil(user.Phone().String()),
		Address: textOrNil(user.Address().String()),
		Roles:   roles,
	}
}

func textOrNil(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
