package model

import (
	"slices"
	"strings"
)

// UserStatus tells whether a user may authenticate.
type UserStatus string

const (
	UserActive UserStatus = "ACTIVE"
	UserLocked UserStatus = "LOCKED"
)

// User is the identity aggregate. Its invariants are enforced here, not in controllers or SQL.
type User struct {
	id           string
	name         Name
	email        Email
	passwordHash string
	phone        Phone
	address      Address
	roles        []Role
	status       UserStatus
}

// NewUser creates an ACTIVE user. The password must already be a bcrypt hash and the user
// needs at least one valid role; repeated roles are kept once. Phone and address are
// contact data: stored with the user, never part of its public projections (ADR-024).
func NewUser(id string, name Name, email Email, passwordHash string, phone Phone, address Address, roles []Role) (*User, error) {
	if strings.TrimSpace(id) == "" {
		return nil, ErrInvalidUserID
	}
	if !isBcryptHash(passwordHash) {
		return nil, ErrInvalidPasswordHash
	}
	unique, err := uniqueRoles(roles)
	if err != nil {
		return nil, err
	}
	return &User{id: id, name: name, email: email, passwordHash: passwordHash, phone: phone, address: address, roles: unique, status: UserActive}, nil
}

// RestoreUser rebuilds a stored user with the status it had. It keeps the invariants of NewUser
// (id, bcrypt hash, valid roles) and also requires a known status. Phone and address may be empty:
// accounts that predate ADR-024 do not have them.
func RestoreUser(id string, name Name, email Email, passwordHash string, phone Phone, address Address, roles []Role, status UserStatus) (*User, error) {
	if status != UserActive && status != UserLocked {
		return nil, ErrInvalidUserStatus
	}
	user, err := NewUser(id, name, email, passwordHash, phone, address, roles)
	if err != nil {
		return nil, err
	}
	user.status = status
	return user, nil
}

func (u *User) ID() string           { return u.id }
func (u *User) Name() Name           { return u.name }
func (u *User) Email() Email         { return u.email }
func (u *User) PasswordHash() string { return u.passwordHash }
func (u *User) Phone() Phone         { return u.phone }
func (u *User) Address() Address     { return u.address }
func (u *User) Status() UserStatus   { return u.status }

// Roles returns a copy, so callers cannot change the aggregate.
func (u *User) Roles() []Role {
	return append([]Role(nil), u.roles...)
}

// HasRole reports whether the user holds role.
func (u *User) HasRole(role Role) bool {
	for _, held := range u.roles {
		if held == role {
			return true
		}
	}
	return false
}

// SetRole makes the user hold role when enabled is true and not hold it otherwise, and reports
// whether anything changed: asking for the state the user already has is not an error and changes
// nothing. Only ADMIN can be granted or revoked; CLIENT is the base role of every account.
//
// activeAdmins is how many active administrators exist now, this user included. A user who counts
// among them cannot lose ADMIN when they are the last one (ErrLastAdmin); a locked administrator
// does not count, so revoking theirs never leaves the platform without an active one.
func (u *User) SetRole(role Role, enabled bool, activeAdmins int) (bool, error) {
	if role != RoleAdmin {
		return false, ErrRoleNotChangeable
	}
	if u.HasRole(role) == enabled {
		return false, nil
	}
	if enabled {
		u.roles = append(u.roles, role)
		slices.Sort(u.roles)
		return true, nil
	}
	if u.status == UserActive && activeAdmins <= 1 {
		return false, ErrLastAdmin
	}
	remaining := slices.DeleteFunc(u.Roles(), func(held Role) bool { return held == role })
	if len(remaining) == 0 {
		return false, ErrNoRoles
	}
	u.roles = remaining
	return true, nil
}

// Lock prevents the user from authenticating.
func (u *User) Lock() { u.status = UserLocked }

// Unlock lets the user authenticate again.
func (u *User) Unlock() { u.status = UserActive }

// EnsureCanAuthenticate returns ErrUserLocked when the user is locked.
func (u *User) EnsureCanAuthenticate() error {
	if u.status == UserLocked {
		return ErrUserLocked
	}
	return nil
}

func uniqueRoles(roles []Role) ([]Role, error) {
	if len(roles) == 0 {
		return nil, ErrNoRoles
	}
	unique := make([]Role, 0, len(roles))
	seen := make(map[Role]bool, len(roles))
	for _, role := range roles {
		if !role.valid() {
			return nil, ErrUnknownRole
		}
		if !seen[role] {
			seen[role] = true
			unique = append(unique, role)
		}
	}
	return unique, nil
}

func isBcryptHash(value string) bool {
	return strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$")
}
