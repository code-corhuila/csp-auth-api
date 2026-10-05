package model

import "strings"

// UserStatus tells whether a user may authenticate.
type UserStatus string

const (
	UserActive UserStatus = "ACTIVE"
	UserLocked UserStatus = "LOCKED"
)

// User is the identity aggregate. Its invariants are enforced here, not in controllers or SQL.
type User struct {
	id           string
	email        Email
	passwordHash string
	roles        []Role
	status       UserStatus
}

// NewUser creates an ACTIVE user. The password must already be a bcrypt hash and the user
// needs at least one valid role; repeated roles are kept once.
func NewUser(id string, email Email, passwordHash string, roles []Role) (*User, error) {
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
	return &User{id: id, email: email, passwordHash: passwordHash, roles: unique, status: UserActive}, nil
}

func (u *User) ID() string           { return u.id }
func (u *User) Email() Email         { return u.email }
func (u *User) PasswordHash() string { return u.passwordHash }
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
