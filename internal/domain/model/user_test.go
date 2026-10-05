package model

import (
	"errors"
	"testing"
)

const validHash = "$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

func newTestUser(t *testing.T, roles ...Role) *User {
	t.Helper()
	email, err := NewEmail("dev@example.com")
	if err != nil {
		t.Fatalf("NewEmail() error = %v", err)
	}
	user, err := NewUser("550e8400-e29b-41d4-a716-446655440000", email, validHash, roles)
	if err != nil {
		t.Fatalf("NewUser() error = %v", err)
	}
	return user
}

func TestNewUserStartsActiveAndCanAuthenticate(t *testing.T) {
	user := newTestUser(t, RoleClient)
	if user.Status() != UserActive {
		t.Errorf("Status() = %v, want ACTIVE", user.Status())
	}
	if err := user.EnsureCanAuthenticate(); err != nil {
		t.Errorf("EnsureCanAuthenticate() error = %v", err)
	}
	if !user.HasRole(RoleClient) || user.HasRole(RoleAdmin) {
		t.Errorf("roles = %v, want only CLIENT", user.Roles())
	}
}

func TestNewUserKeepsEachRoleOnce(t *testing.T) {
	user := newTestUser(t, RoleClient, RoleClient, RoleAdmin)
	if got := len(user.Roles()); got != 2 {
		t.Errorf("len(Roles()) = %d, want 2", got)
	}
}

func TestNewUserRejectsInvalidInput(t *testing.T) {
	email, _ := NewEmail("dev@example.com")
	cases := map[string]struct {
		id    string
		hash  string
		roles []Role
		want  error
	}{
		"empty id":        {"", validHash, []Role{RoleClient}, ErrInvalidUserID},
		"plain password":  {"u1", "Secret123!", []Role{RoleClient}, ErrInvalidPasswordHash},
		"empty hash":      {"u1", "", []Role{RoleClient}, ErrInvalidPasswordHash},
		"no roles":        {"u1", validHash, nil, ErrNoRoles},
		"role zero value": {"u1", validHash, []Role{""}, ErrUnknownRole},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewUser(c.id, email, c.hash, c.roles); !errors.Is(err, c.want) {
				t.Fatalf("NewUser() error = %v, want %v", err, c.want)
			}
		})
	}
}

func TestLockedUserCannotAuthenticate(t *testing.T) {
	user := newTestUser(t, RoleClient)
	user.Lock()
	if user.Status() != UserLocked {
		t.Errorf("Status() = %v, want LOCKED", user.Status())
	}
	if err := user.EnsureCanAuthenticate(); !errors.Is(err, ErrUserLocked) {
		t.Errorf("EnsureCanAuthenticate() error = %v, want ErrUserLocked", err)
	}
}

func TestUnlockRestoresAuthentication(t *testing.T) {
	user := newTestUser(t, RoleClient)
	user.Lock()
	user.Unlock()
	if err := user.EnsureCanAuthenticate(); err != nil {
		t.Errorf("EnsureCanAuthenticate() error = %v", err)
	}
}

func TestRolesReturnsACopy(t *testing.T) {
	user := newTestUser(t, RoleClient)
	user.Roles()[0] = RoleAdmin
	if user.HasRole(RoleAdmin) {
		t.Error("changing the returned slice must not change the user")
	}
}
