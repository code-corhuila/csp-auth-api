package model

import (
	"errors"
	"reflect"
	"testing"
)

func TestNewAccessClaimsResolvesPermissionsFromRoles(t *testing.T) {
	client := []string{
		"catalog:read", "booking:create", "booking:read:self", "concessions:order:create",
		"concessions:order:read:self", "concessions:order:cancel:self", "ticket:read:self",
		"profile:read:self", "profile:update:self",
	}
	admin := append(append([]string{}, client...),
		"booking:read:all", "catalog:write", "room:write", "showtime:write",
		"concessions:product:write", "concessions:combo:write", "concessions:inventory:write", "user:role:update")

	tests := []struct {
		name  string
		roles []Role
		want  []string
	}{
		{"client", []Role{RoleClient}, client},
		{"admin includes client permissions", []Role{RoleAdmin}, admin},
		{"both roles do not repeat permissions", []Role{RoleClient, RoleAdmin}, admin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := NewAccessClaims("user-1", tt.roles)
			if err != nil {
				t.Fatalf("NewAccessClaims() error = %v", err)
			}
			if !reflect.DeepEqual(claims.Permissions, tt.want) {
				t.Errorf("Permissions = %v, want %v", claims.Permissions, tt.want)
			}
			if claims.Subject != "user-1" || !reflect.DeepEqual(claims.Roles, tt.roles) {
				t.Errorf("claims = %+v", claims)
			}
		})
	}
}

func TestNewAccessClaimsRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		userID string
		roles  []Role
		want   error
	}{
		{"empty user id", "", []Role{RoleClient}, ErrInvalidUserID},
		{"no roles", "user-1", nil, ErrNoRoles},
		{"unknown role", "user-1", []Role{"ROOT"}, ErrUnknownRole},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewAccessClaims(tt.userID, tt.roles); !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}
