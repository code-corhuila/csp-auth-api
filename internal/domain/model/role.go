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

func (r Role) String() string {
	return string(r)
}
