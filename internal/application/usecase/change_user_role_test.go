package usecase

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type fakeRoles struct {
	journal      *journal
	activeAdmins int
	lockErr      error
	saveErr      error
	saved        []savedRole
}

type savedRole struct {
	userID    string
	role      model.Role
	held      bool
	changedBy string
}

func (r *fakeRoles) LockActiveAdmins(context.Context) (int, error) {
	r.journal.record("lock-admins")
	return r.activeAdmins, r.lockErr
}

func (r *fakeRoles) SaveRole(_ context.Context, user *model.User, role model.Role, changedBy string) error {
	r.journal.record("save-role")
	if r.saveErr != nil {
		return r.saveErr
	}
	r.saved = append(r.saved, savedRole{user.ID(), role, user.HasRole(role), changedBy})
	return nil
}

type fakeRoleOutbox struct {
	journal *journal
	events  []model.UserRoleChanged
	err     error
}

func (o *fakeRoleOutbox) AppendRoleChanged(_ context.Context, event model.UserRoleChanged) error {
	o.journal.record("outbox")
	if o.err != nil {
		return o.err
	}
	o.events = append(o.events, event)
	return nil
}

type roleFixture struct {
	useCase      *ChangeUserRole
	roles        *fakeRoles
	outbox       *fakeRoleOutbox
	transactions *fakeTransactions
	journal      *journal
}

func newRoleFixture(target *model.User, activeAdmins int) *roleFixture {
	j := &journal{}
	users := &fakeRepository{journal: j, byID: map[string]*model.User{}}
	f := &roleFixture{
		roles:        &fakeRoles{journal: j, activeAdmins: activeAdmins},
		outbox:       &fakeRoleOutbox{journal: j},
		transactions: &fakeTransactions{journal: j},
		journal:      j,
	}
	if target != nil {
		users.byID[target.ID()] = target
	}
	f.useCase = NewChangeUserRole(ChangeUserRolePorts{
		Users: users, Roles: f.roles, Outbox: f.outbox, IDs: &fakeIDs{next: []string{"event-1"}},
		Clock: fakeClock{}, Transactions: f.transactions,
	})
	return f
}

func roleCommand(enabled bool) in.ChangeUserRoleCommand {
	return in.ChangeUserRoleCommand{ActingAdminID: "admin-1", UserID: "user-1", Role: "ADMIN", Enabled: enabled}
}

func TestChangeRoleGrantsAdminAndPublishesTheEventInOneTransaction(t *testing.T) {
	f := newRoleFixture(storedUser(t, model.UserActive, model.RoleClient), 1)

	summary, err := f.useCase.ChangeRole(context.Background(), roleCommand(true))

	if err != nil {
		t.Fatalf("ChangeRole() error = %v", err)
	}
	if !reflect.DeepEqual(summary.Roles, []string{"ADMIN", "CLIENT"}) || !contains(summary.Permissions, "user:role:update") {
		t.Errorf("summary = %+v, want ADMIN and CLIENT with the admin permissions", summary)
	}
	wantSteps := []string{"begin", "find-user", "save-role", "outbox", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	if want := []savedRole{{"user-1", model.RoleAdmin, true, "admin-1"}}; !reflect.DeepEqual(f.roles.saved, want) {
		t.Errorf("saved roles = %+v, want %+v", f.roles.saved, want)
	}
	wantEvent := model.UserRoleChanged{EventID: "event-1", OccurredAt: registeredAt, UserID: "user-1", Role: "ADMIN", Enabled: true, ChangedBy: "admin-1"}
	if !reflect.DeepEqual(f.outbox.events, []model.UserRoleChanged{wantEvent}) {
		t.Errorf("events = %+v, want [%+v]", f.outbox.events, wantEvent)
	}
}

func TestChangeRoleLocksTheAdministratorsBeforeReadingTheUserToRevoke(t *testing.T) {
	f := newRoleFixture(storedUser(t, model.UserActive, model.RoleClient, model.RoleAdmin), 2)

	summary, err := f.useCase.ChangeRole(context.Background(), roleCommand(false))

	if err != nil {
		t.Fatalf("ChangeRole() error = %v", err)
	}
	if !reflect.DeepEqual(summary.Roles, []string{"CLIENT"}) {
		t.Errorf("Roles = %v, want [CLIENT]", summary.Roles)
	}
	wantSteps := []string{"begin", "lock-admins", "find-user", "save-role", "outbox", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	if len(f.outbox.events) != 1 || f.outbox.events[0].Enabled {
		t.Errorf("events = %+v, want one revoke", f.outbox.events)
	}
}

func TestChangeRoleRejectsRevokingTheLastActiveAdministratorAndWritesNothing(t *testing.T) {
	f := newRoleFixture(storedUser(t, model.UserActive, model.RoleClient, model.RoleAdmin), 1)

	_, err := f.useCase.ChangeRole(context.Background(), roleCommand(false))

	if !errors.Is(err, model.ErrLastAdmin) {
		t.Fatalf("error = %v, want ErrLastAdmin", err)
	}
	if len(f.roles.saved) != 0 || len(f.outbox.events) != 0 || f.transactions.committed {
		t.Errorf("saved = %v, events = %v, committed = %v, want nothing written", f.roles.saved, f.outbox.events, f.transactions.committed)
	}
}

func TestChangeRoleIsANoOpWhenTheUserAlreadyHasTheWantedState(t *testing.T) {
	cases := map[string]struct {
		user    *model.User
		enabled bool
		roles   []string
	}{
		"grant a role already held": {storedUser(t, model.UserActive, model.RoleClient, model.RoleAdmin), true, []string{"CLIENT", "ADMIN"}},
		"revoke a role not held":    {storedUser(t, model.UserActive, model.RoleClient), false, []string{"CLIENT"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture(c.user, 1)

			summary, err := f.useCase.ChangeRole(context.Background(), roleCommand(c.enabled))

			if err != nil {
				t.Fatalf("ChangeRole() error = %v", err)
			}
			if !reflect.DeepEqual(summary.Roles, c.roles) {
				t.Errorf("Roles = %v, want %v", summary.Roles, c.roles)
			}
			if len(f.roles.saved) != 0 || len(f.outbox.events) != 0 {
				t.Errorf("saved = %v, events = %v, want nothing written", f.roles.saved, f.outbox.events)
			}
		})
	}
}

func TestChangeRoleReportsAnUnknownUserAndAnUnchangeableRole(t *testing.T) {
	f := newRoleFixture(nil, 2)
	if _, err := f.useCase.ChangeRole(context.Background(), roleCommand(true)); !errors.Is(err, model.ErrUserNotFound) {
		t.Errorf("unknown user: error = %v, want ErrUserNotFound", err)
	}

	f = newRoleFixture(storedUser(t, model.UserActive, model.RoleClient), 2)
	command := roleCommand(true)
	command.Role = "CLIENT"
	if _, err := f.useCase.ChangeRole(context.Background(), command); !errors.Is(err, model.ErrRoleNotChangeable) {
		t.Errorf("CLIENT: error = %v, want ErrRoleNotChangeable", err)
	}
	command.Role = "SUPERUSER"
	if _, err := f.useCase.ChangeRole(context.Background(), command); !errors.Is(err, model.ErrUnknownRole) {
		t.Errorf("unknown role: error = %v, want ErrUnknownRole", err)
	}
}

func TestChangeRoleRollsBackWhenTheEventOrTheRoleCannotBeStored(t *testing.T) {
	failure := errors.New("database down")
	cases := map[string]func(*roleFixture){
		"outbox fails": func(f *roleFixture) { f.outbox.err = failure },
		"save fails":   func(f *roleFixture) { f.roles.saveErr = failure },
		"lock fails":   func(f *roleFixture) { f.roles.lockErr = failure },
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture(storedUser(t, model.UserActive, model.RoleClient, model.RoleAdmin), 2)
			fail(f)

			_, err := f.useCase.ChangeRole(context.Background(), roleCommand(false))

			if !errors.Is(err, failure) || f.transactions.committed {
				t.Errorf("error = %v, committed = %v, want the failure and a rollback", err, f.transactions.committed)
			}
		})
	}
}
