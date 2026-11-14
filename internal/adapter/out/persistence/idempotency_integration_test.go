//go:build integration

package persistence

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// fixedHasher gives every password the same bcrypt-shaped hash: these tests are about the race,
// not about bcrypt, whose cost would only slow them down.
type fixedHasher struct{}

func (fixedHasher) Hash(model.Password) (string, error) { return bcryptHash, nil }
func (fixedHasher) Verify(string, string) (bool, error) { return false, nil }

type fixedTokens struct{}

func (fixedTokens) IssueAccessToken(model.AccessClaims) (out.IssuedAccessToken, error) {
	return out.IssuedAccessToken{Value: "access", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func countRows(t *testing.T, f fixture, query string, args ...any) int {
	t.Helper()
	var rows int
	if err := f.pool.QueryRow(context.Background(), query, args...).Scan(&rows); err != nil {
		t.Fatalf("%s error = %v", query, err)
	}
	return rows
}

func TestIdempotencyKeyIsStoredFoundAndNeverOverwritten(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	keys := NewIdempotencyKeyRepository(f.pool)
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	key, _ := model.NewIdempotencyKey("it-key-" + newUUID(t))

	if _, found, err := keys.Find(ctx, key); err != nil || found {
		t.Fatalf("Find() before Save = %v, %v, want not found", found, err)
	}
	record := out.IdempotencyRecord{UserID: user.ID(), RequestHash: "abc123"}
	if err := keys.Save(ctx, key, record); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, found, err := keys.Find(ctx, key)
	if err != nil || !found || got != record {
		t.Errorf("Find() = %+v, %v, %v, want %+v", got, found, err, record)
	}
	other := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, other); err != nil {
		t.Fatalf("register error = %v", err)
	}
	err = keys.Save(ctx, key, out.IdempotencyRecord{UserID: other.ID(), RequestHash: "other"})
	if !errors.Is(err, model.ErrIdempotencyKeyTaken) {
		t.Errorf("second Save() error = %v, want ErrIdempotencyKeyTaken", err)
	}
}

func TestFindByIDLoadsTheUserWithItsRoles(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}

	found, err := f.users.FindByID(ctx, user.ID())

	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != user.ID() || found.Email() != user.Email() || found.Name().String() != "Ana Perez" || !found.HasRole(model.RoleClient) || found.Status() != model.UserActive {
		t.Errorf("found = %q %q %q %v, want the stored user", found.ID(), found.Email(), found.Name(), found.Roles())
	}
	if _, err := f.users.FindByID(ctx, newUUID(t)); !errors.Is(err, model.ErrUserNotFound) {
		t.Errorf("FindByID(unknown) error = %v, want ErrUserNotFound", err)
	}
}
