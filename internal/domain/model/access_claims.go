package model

import "crypto/rsa"

var clientPermissions = []string{
	"catalog:read",
	"booking:create",
	"booking:read:self",
	"concessions:order:create",
	"concessions:order:read:self",
	"concessions:order:cancel:self",
	"ticket:read:self",
	"profile:read:self",
	"profile:update:self",
}

var adminOnlyPermissions = []string{
	"booking:read:all",
	"catalog:write",
	"room:write",
	"showtime:write",
	"concessions:product:write",
	"concessions:combo:write",
	"concessions:inventory:write",
	"user:role:update",
}

// permissions returns the permissions of a role (authentication.md, "Roles and permissions"):
// ADMIN holds every CLIENT permission plus its own.
func (r Role) permissions() []string {
	switch r {
	case RoleClient:
		return clientPermissions
	case RoleAdmin:
		return append(append([]string{}, clientPermissions...), adminOnlyPermissions...)
	default:
		return nil
	}
}

// AccessClaims is the identity part of an access token: who the user is and what the roles allow.
// The issuer adds the registered claims (iss, aud, iat, exp, jti).
type AccessClaims struct {
	Subject     string
	Roles       []Role
	Permissions []string
}

// NewAccessClaims resolves the permissions of roles, without duplicates, in a stable order.
func NewAccessClaims(userID string, roles []Role) (AccessClaims, error) {
	if userID == "" {
		return AccessClaims{}, ErrInvalidUserID
	}
	if len(roles) == 0 {
		return AccessClaims{}, ErrNoRoles
	}
	seen := make(map[string]bool)
	permissions := []string{}
	for _, role := range roles {
		if !role.valid() {
			return AccessClaims{}, ErrUnknownRole
		}
		for _, permission := range role.permissions() {
			if !seen[permission] {
				seen[permission] = true
				permissions = append(permissions, permission)
			}
		}
	}
	return AccessClaims{Subject: userID, Roles: roles, Permissions: permissions}, nil
}

// PublicKey is a signature verification key identified by KeyID, as published to the other services.
type PublicKey struct {
	KeyID string
	Key   *rsa.PublicKey
}
