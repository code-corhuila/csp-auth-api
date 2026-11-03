//go:build integration

package persistence

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

func text(value string) *string { return &value }

func (f fixture) updateProfile() *usecase.UpdateProfile {
	return usecase.NewUpdateProfile(f.users, f.users, fixedClock{at: time.Now()}, f.transactions)
}

func (f fixture) storedContact(t *testing.T, ctx context.Context, userID string) (name string, phone, address *string) {
	t.Helper()
	err := f.pool.QueryRow(ctx, `SELECT name, phone, address FROM auth.app_user WHERE id = $1`, userID).Scan(&name, &phone, &address)
	if err != nil {
		t.Fatalf("read the contact data: %v", err)
	}
	return name, phone, address
}

func TestUpdateProfileWritesOnlyTheFieldsSentAndAnswersTheProfileAfterTheChange(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}

	profile, err := f.updateProfile().Update(ctx, in.UpdateProfileCommand{UserID: user.ID(), Name: text("  Ana María  "), Address: text("Carrera 7 # 8-9")})

	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	name, phone, address := f.storedContact(t, ctx, user.ID())
	if name != "Ana María" || phone == nil || *phone != "+573001234567" || address == nil || *address != "Carrera 7 # 8-9" {
		t.Errorf("stored name = %q, phone = %v, address = %v, want the new name and address and the phone untouched", name, phone, address)
	}
	if profile.Name != "Ana María" || profile.Phone == nil || *profile.Phone != "+573001234567" || profile.Address == nil || *profile.Address != "Carrera 7 # 8-9" || len(profile.Roles) != 1 || profile.Roles[0] != "CLIENT" {
		t.Errorf("profile = %+v, want the data after the change", profile)
	}
	var updatedBy *string
	if err := f.pool.QueryRow(ctx, `SELECT updated_by::text FROM auth.app_user WHERE id = $1`, user.ID()).Scan(&updatedBy); err != nil || updatedBy == nil || *updatedBy != user.ID() {
		t.Errorf("updated_by = %v (%v), want the user who edited", updatedBy, err)
	}
}

func TestUpdateProfileOfAnAccountThatDoesNotExistIsNotFound(t *testing.T) {
	f, ctx := newFixture(t), context.Background()

	_, err := f.updateProfile().Update(ctx, in.UpdateProfileCommand{UserID: newUUID(t), Name: text("Ana")})

	if !errors.Is(err, model.ErrUserNotFound) {
		t.Errorf("Update() error = %v, want ErrUserNotFound", err)
	}
}

func TestUpdateProfileOfALockedAccountChangesNothing(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.app_user SET status = 'LOCKED' WHERE id = $1`, user.ID()); err != nil {
		t.Fatalf("lock the account: %v", err)
	}

	_, err := f.updateProfile().Update(ctx, in.UpdateProfileCommand{UserID: user.ID(), Name: text("Otro Nombre")})

	name, _, _ := f.storedContact(t, ctx, user.ID())
	if !errors.Is(err, model.ErrUserLocked) || name != "Ana Perez" {
		t.Errorf("error = %v, stored name = %q, want ErrUserLocked and the name untouched", err, name)
	}
}

func TestGetProfileOfAnAccountCreatedBeforeThePhoneAndTheAddressHasNeither(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.app_user SET phone = NULL, address = NULL WHERE id = $1`, user.ID()); err != nil {
		t.Fatalf("clear the contact data: %v", err)
	}

	profile, err := usecase.NewGetProfile(f.users).Get(ctx, user.ID())

	if err != nil || profile.Phone != nil || profile.Address != nil || profile.Email != user.Email().String() {
		t.Errorf("profile = %+v, error = %v, want the email and no phone and no address", profile, err)
	}
}
