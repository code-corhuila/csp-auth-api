package model

// Role is a permission set granted to a user.
type Role string

const (
	RoleClient Role = "CLIENT"
	RoleAdmin  Role = "ADMIN"
)

// ParseRole converts a stored or received name into a Role.
func ParseRole(name string) (Role, error) {
	role := Role(name)
	if !role.valid() {
		return "", ErrUnknownRole
	}
	return role, nil
}

func (r Role) valid() bool {
	return r == RoleClient || r == RoleAdmin
}

// EndsSessionsWhenRemoved reports whether taking the role away from a user ends their sessions
// (ADR-031, amendment 2026-10-24): ADMIN does, because the permissions travel in the access token
// and a demoted administrator must not keep them.
func (r Role) EndsSessionsWhenRemoved() bool {
	return r == RoleAdmin
}

func (r Role) String() string {
	return string(r)
}
