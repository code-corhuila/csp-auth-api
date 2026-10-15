package model

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestSetRoleGrantsAdminKeepingTheOtherRoles(t *testing.T) {
	user := newTestUser(t, RoleClient)

	changed, err := user.SetRole(RoleAdmin, true, 0)

	if err != nil || !changed {
		t.Fatalf("SetRole() = %v, %v, want a change", changed, err)
	}
	if want := []Role{RoleAdmin, RoleClient}; !reflect.DeepEqual(user.Roles(), want) {
		t.Errorf("Roles() = %v, want %v", user.Roles(), want)
	}
}

func TestSetRoleDoesNothingWhenTheUserAlreadyIsInTheWantedState(t *testing.T) {
	cases := map[string]struct {
		user    *User
		enabled bool
	}{
		"grant a role already held": {newTestUser(t, RoleClient, RoleAdmin), true},
		"revoke a role not held":    {newTestUser(t, RoleClient), false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			before := c.user.Roles()

			changed, err := c.user.SetRole(RoleAdmin, c.enabled, 1)

			if err != nil || changed {
				t.Errorf("SetRole() = %v, %v, want no change and no error", changed, err)
			}
			if !reflect.DeepEqual(c.user.Roles(), before) {
				t.Errorf("Roles() = %v, want %v", c.user.Roles(), before)
			}
		})
	}
}

func TestSetRoleRevokesAdminWhenAnotherActiveAdministratorRemains(t *testing.T) {
	user := newTestUser(t, RoleClient, RoleAdmin)

	changed, err := user.SetRole(RoleAdmin, false, 2)

	if err != nil || !changed {
		t.Fatalf("SetRole() = %v, %v, want a change", changed, err)
	}
	if want := []Role{RoleClient}; !reflect.DeepEqual(user.Roles(), want) {
		t.Errorf("Roles() = %v, want %v", user.Roles(), want)
	}
}

func TestSetRoleNeverRemovesTheLastActiveAdministrator(t *testing.T) {
	user := newTestUser(t, RoleClient, RoleAdmin)

	changed, err := user.SetRole(RoleAdmin, false, 1)

	if !errors.Is(err, ErrLastAdmin) || changed {
		t.Errorf("SetRole() = %v, %v, want ErrLastAdmin", changed, err)
	}
	if !user.HasRole(RoleAdmin) {
		t.Error("the user lost ADMIN although the change was rejected")
	}
}

func TestSetRoleDoesNotCountALockedAdministratorAsAnActiveOne(t *testing.T) {
	user := newTestUser(t, RoleClient, RoleAdmin)
	user.Lock()

	changed, err := user.SetRole(RoleAdmin, false, 1)

	if err != nil || !changed {
		t.Errorf("SetRole() = %v, %v, want the locked administrator to lose ADMIN", changed, err)
	}
}

func TestSetRoleRejectsARevokeThatLeavesTheUserWithoutRoles(t *testing.T) {
	user := newTestUser(t, RoleAdmin)

	changed, err := user.SetRole(RoleAdmin, false, 2)

	if !errors.Is(err, ErrNoRoles) || changed {
		t.Errorf("SetRole() = %v, %v, want ErrNoRoles", changed, err)
	}
}

func TestSetRoleOnlyChangesAdmin(t *testing.T) {
	user := newTestUser(t, RoleClient)

	changed, err := user.SetRole(RoleClient, false, 2)

	if !errors.Is(err, ErrRoleNotChangeable) || changed {
		t.Errorf("SetRole() = %v, %v, want ErrRoleNotChangeable", changed, err)
	}
}

func TestNewUserRoleChangedCarriesTheActorAndTheDecision(t *testing.T) {
	at := time.Date(2026, 10, 15, 14, 30, 0, 0, time.UTC)

	event := NewUserRoleChanged("evt-1", at, "user-1", RoleAdmin, true, "admin-1")

	want := UserRoleChanged{EventID: "evt-1", OccurredAt: at, UserID: "user-1", Role: "ADMIN", Enabled: true, ChangedBy: "admin-1"}
	if event != want {
		t.Errorf("event = %+v, want %+v", event, want)
	}
	if event.EventType() != "UserRoleChanged" || event.AggregateID() != "user-1" {
		t.Errorf("type and aggregate = %q/%q, want UserRoleChanged/user-1", event.EventType(), event.AggregateID())
	}
}
