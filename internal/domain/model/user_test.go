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
	phone, _ := NewPhone("3001234567")
	address, _ := NewAddress("Calle 123 #45-67")
	name, _ := NewName("Ana Pérez")
	user, err := NewUser("550e8400-e29b-41d4-a716-446655440000", name, email, validHash, phone, address, roles)
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

func TestNewUserKeepsContactData(t *testing.T) {
	user := newTestUser(t, RoleClient)
	if got := user.Phone().String(); got != "3001234567" {
		t.Errorf("Phone() = %q, want 3001234567", got)
	}
	if got := user.Address().String(); got != "Calle 123 #45-67" {
		t.Errorf("Address() = %q, want Calle 123 #45-67", got)
	}
}

func TestNewUserKeepsItsName(t *testing.T) {
	user := newTestUser(t, RoleClient)
	if got := user.Name().String(); got != "Ana Pérez" {
		t.Errorf("Name() = %q, want Ana Pérez", got)
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
	phone, _ := NewPhone("3001234567")
	address, _ := NewAddress("Calle 123 #45-67")
	userName, _ := NewName("Ana Pérez")
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
			if _, err := NewUser(c.id, userName, email, c.hash, phone, address, c.roles); !errors.Is(err, c.want) {
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

func TestUserExposesItsIdentity(t *testing.T) {
	user := newTestUser(t, RoleClient)
	if got := user.ID(); got != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("ID() = %q, want the id given to NewUser", got)
	}
	if got := user.Email().String(); got != "dev@example.com" {
		t.Errorf("Email() = %q, want dev@example.com", got)
	}
	if got := user.PasswordHash(); got != validHash {
		t.Errorf("PasswordHash() = %q, want the hash given to NewUser", got)
	}
}

func TestRestoreUserKeepsTheStoredStatusAndContactData(t *testing.T) {
	email, _ := NewEmail("dev@example.com")
	name, _ := NewName("Ana Pérez")

	user, err := RestoreUser("user-1", name, email, validHash, Phone{}, Address{}, []Role{RoleClient, RoleClient}, UserLocked)

	if err != nil {
		t.Fatalf("RestoreUser() error = %v", err)
	}
	if user.Status() != UserLocked || user.EnsureCanAuthenticate() != ErrUserLocked {
		t.Errorf("status = %v, want LOCKED", user.Status())
	}
	if user.Phone().String() != "" || len(user.Roles()) != 1 {
		t.Errorf("phone = %q roles = %v, want empty phone and one role", user.Phone(), user.Roles())
	}
}

func TestRestoreUserKeepsTheInvariants(t *testing.T) {
	email, _ := NewEmail("dev@example.com")
	name, _ := NewName("Ana Pérez")
	cases := map[string]struct {
		id, hash string
		roles    []Role
		status   UserStatus
		want     error
	}{
		"empty id":       {"", validHash, []Role{RoleClient}, UserActive, ErrInvalidUserID},
		"plain password": {"u", "Secret123", []Role{RoleClient}, UserActive, ErrInvalidPasswordHash},
		"no roles":       {"u", validHash, nil, UserActive, ErrNoRoles},
		"unknown role":   {"u", validHash, []Role{"ROOT"}, UserActive, ErrUnknownRole},
		"unknown status": {"u", validHash, []Role{RoleClient}, "DELETED", ErrInvalidUserStatus},
	}
	for name_, c := range cases {
		if _, err := RestoreUser(c.id, name, email, c.hash, Phone{}, Address{}, c.roles, c.status); !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", name_, err, c.want)
		}
	}
}
