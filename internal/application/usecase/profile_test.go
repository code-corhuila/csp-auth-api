package usecase

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// profileUsers serves one account by id and records the reads.
type profileUsers struct {
	journal *journal
	user    *model.User
}

func (u *profileUsers) ExistsByEmail(context.Context, model.Email) (bool, error) { return false, nil }
func (u *profileUsers) Save(context.Context, *model.User) error                  { return nil }
func (u *profileUsers) FindByEmail(context.Context, model.Email) (*model.User, error) {
	return nil, model.ErrUserNotFound
}
func (u *profileUsers) FindByID(_ context.Context, id string) (*model.User, error) {
	u.journal.record("find-user")
	if u.user == nil || u.user.ID() != id {
		return nil, model.ErrUserNotFound
	}
	return u.user, nil
}

type fakeProfileUpdater struct {
	journal *journal
	userID  string
	change  model.ProfileChange
	at      time.Time
	err     error
}

func (p *fakeProfileUpdater) UpdateProfile(_ context.Context, userID string, change model.ProfileChange, at time.Time) error {
	p.journal.record("update-profile")
	p.userID, p.change, p.at = userID, change, at
	return p.err
}

type profileFixture struct {
	get          *GetProfile
	update       *UpdateProfile
	updater      *fakeProfileUpdater
	transactions *fakeTransactions
	journal      *journal
}

func newProfileFixture(user *model.User) *profileFixture {
	j := &journal{}
	users := &profileUsers{journal: j, user: user}
	f := &profileFixture{updater: &fakeProfileUpdater{journal: j}, transactions: &fakeTransactions{journal: j}, journal: j}
	f.get = NewGetProfile(users)
	f.update = NewUpdateProfile(users, f.updater, fakeClock{}, f.transactions)
	return f
}

func text(value string) *string { return &value }

func TestGetProfileReturnsThePersonalDataOfTheAccountWithItsRoles(t *testing.T) {
	f := newProfileFixture(storedUser(t, model.UserActive, model.RoleClient, model.RoleAdmin))

	profile, err := f.get.Get(context.Background(), "user-1")

	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	want := in.Profile{
		ID: "user-1", Email: "ana@example.com", Name: "Ana Pérez",
		Phone: text("3001234567"), Address: text("Calle 123 #45-67"), Roles: []string{"CLIENT", "ADMIN"},
	}
	if !reflect.DeepEqual(profile, want) {
		t.Errorf("profile = %+v, want %+v", profile, want)
	}
}

func TestGetProfileReturnsNoPhoneAndNoAddressForAnAccountThatPredatesThem(t *testing.T) {
	email, _ := model.NewEmail("old@example.com")
	name, _ := model.NewName("Old Account")
	user, _ := model.RestoreUser("user-1", name, email, storedHash, model.Phone{}, model.Address{}, []model.Role{model.RoleClient}, model.UserActive)
	f := newProfileFixture(user)

	profile, err := f.get.Get(context.Background(), "user-1")

	if err != nil || profile.Phone != nil || profile.Address != nil {
		t.Errorf("profile = %+v, error = %v, want a nil phone and a nil address", profile, err)
	}
}

func TestGetProfileRefusesAnAccountThatIsGoneOrLocked(t *testing.T) {
	cases := map[string]struct {
		user *model.User
		want error
	}{
		"gone":   {nil, model.ErrUserNotFound},
		"locked": {storedUser(t, model.UserLocked, model.RoleClient), model.ErrUserLocked},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newProfileFixture(c.user)

			if _, err := f.get.Get(context.Background(), "user-1"); !errors.Is(err, c.want) {
				t.Errorf("Get() error = %v, want %v", err, c.want)
			}
		})
	}
}

func TestUpdateProfileWritesTheFieldsSentInOneTransactionAndReturnsTheProfile(t *testing.T) {
	f := newProfileFixture(storedUser(t, model.UserActive, model.RoleClient))

	profile, err := f.update.Update(context.Background(), in.UpdateProfileCommand{UserID: "user-1", Name: text(" Ana María "), Phone: text("+573001234567")})

	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if want := []string{"begin", "update-profile", "find-user", "commit"}; !reflect.DeepEqual(f.journal.steps, want) {
		t.Errorf("steps = %v, want %v", f.journal.steps, want)
	}
	name, hasName := f.updater.change.Name()
	phone, hasPhone := f.updater.change.Phone()
	_, hasAddress := f.updater.change.Address()
	if f.updater.userID != "user-1" || !f.updater.at.Equal(registeredAt) || !hasName || name.String() != "Ana María" || !hasPhone || phone.String() != "+573001234567" || hasAddress {
		t.Errorf("updated %q at %v with name %q, phone %q, address sent %v, want only the name and the phone of user-1", f.updater.userID, f.updater.at, name, phone, hasAddress)
	}
	if profile.ID != "user-1" || profile.Email != "ana@example.com" {
		t.Errorf("profile = %+v, want the profile read after the write", profile)
	}
}

func TestUpdateProfileRejectsAnInvalidOrEmptyEditBeforeAnyWork(t *testing.T) {
	cases := map[string]struct {
		command in.UpdateProfileCommand
		want    []error
	}{
		"empty":         {in.UpdateProfileCommand{UserID: "user-1"}, []error{model.ErrEmptyProfileChange}},
		"invalid phone": {in.UpdateProfileCommand{UserID: "user-1", Phone: text("12-34")}, []error{model.ErrInvalidPhone}},
		"two invalid":   {in.UpdateProfileCommand{UserID: "user-1", Name: text(""), Address: text("")}, []error{model.ErrInvalidName, model.ErrInvalidAddress}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newProfileFixture(storedUser(t, model.UserActive, model.RoleClient))

			_, err := f.update.Update(context.Background(), c.command)

			for _, want := range c.want {
				if !errors.Is(err, want) {
					t.Errorf("Update() error = %v, want %v", err, want)
				}
			}
			if len(f.journal.steps) != 0 {
				t.Errorf("steps = %v, want none: nothing is touched", f.journal.steps)
			}
		})
	}
}

func TestUpdateProfileRollsBackWhenTheAccountIsGoneLockedOrTheWriteFails(t *testing.T) {
	boom := errors.New("driver failure")
	cases := map[string]struct {
		user      *model.User
		updateErr error
		want      error
	}{
		"gone":         {nil, model.ErrUserNotFound, model.ErrUserNotFound},
		"locked":       {storedUser(t, model.UserLocked, model.RoleClient), nil, model.ErrUserLocked},
		"write failed": {storedUser(t, model.UserActive, model.RoleClient), boom, boom},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newProfileFixture(c.user)
			f.updater.err = c.updateErr

			_, err := f.update.Update(context.Background(), in.UpdateProfileCommand{UserID: "user-1", Name: text("Ana")})

			if !errors.Is(err, c.want) || f.transactions.committed {
				t.Errorf("Update() error = %v, committed = %v, want %v and a rollback", err, f.transactions.committed, c.want)
			}
		})
	}
}
