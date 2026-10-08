//go:build integration

package persistence

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// The tests need a PostgreSQL with the csp-auth-db migrations applied. They read two DSNs:
//
//	AUTH_TEST_DATABASE_URL        login user of the service (auth_app, inherits auth_writer); required
//	AUTH_TEST_OUTBOX_READER_URL   login user that can read outbox payloads (worker_app); optional
//
// Without the first one every test is skipped. auth_writer cannot delete users, so each test
// registers fresh random ids and emails and leaves its rows in the throwaway database.
const (
	serviceURLVariable = "AUTH_TEST_DATABASE_URL"
	readerURLVariable  = "AUTH_TEST_OUTBOX_READER_URL"
	bcryptHash         = "$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
)

func openPool(t *testing.T, variable string) *pgxpool.Pool {
	t.Helper()
	url, ok := os.LookupEnv(variable)
	if !ok || url == "" {
		t.Skipf("%s is not set: integration tests need a PostgreSQL with the csp-auth-db migrations", variable)
	}
	pool, err := NewPool(context.Background(), PoolSettings{URL: url, MaxConnections: 5, ConnectTimeout: 5 * time.Second, QueryTimeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("NewPool(%s) error = %v", variable, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func newUUID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func newUser(t *testing.T, email string) *model.User {
	t.Helper()
	name, _ := model.NewName("Ana Perez")
	parsed, err := model.NewEmail(email)
	if err != nil {
		t.Fatalf("NewEmail() error = %v", err)
	}
	phone, _ := model.NewPhone("+573001234567")
	address, _ := model.NewAddress("Calle 1 # 2-3")
	user, err := model.NewUser(newUUID(t), name, parsed, bcryptHash, phone, address, []model.Role{model.RoleClient})
	if err != nil {
		t.Fatalf("NewUser() error = %v", err)
	}
	return user
}

func uniqueEmail(t *testing.T) string {
	return fmt.Sprintf("it-%s@Example.com", newUUID(t))
}

type fixture struct {
	pool         *pgxpool.Pool
	users        *UserRepository
	outbox       *OutboxWriter
	transactions *TransactionManager
}

func newFixture(t *testing.T) fixture {
	pool := openPool(t, serviceURLVariable)
	return fixture{pool: pool, users: NewUserRepository(pool), outbox: NewOutboxWriter(pool), transactions: NewTransactionManager(pool)}
}

func (f fixture) register(t *testing.T, ctx context.Context, user *model.User) error {
	event := model.NewUserRegistered(newUUID(t), time.Now(), user)
	return f.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		if err := f.users.Save(ctx, user); err != nil {
			return err
		}
		return f.outbox.Append(ctx, event)
	})
}

func TestSaveStoresUserRoleAndOutboxEventAtomically(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))

	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}

	var email, name, hash, status, phone, address string
	err := f.pool.QueryRow(ctx, `SELECT email, name, password_hash, status, phone, address FROM auth.app_user WHERE id = $1`, user.ID()).
		Scan(&email, &name, &hash, &status, &phone, &address)
	if err != nil {
		t.Fatalf("user not stored: %v", err)
	}
	if email != user.Email().String() || email != strings.ToLower(email) || name != "Ana Perez" || hash != bcryptHash || status != "ACTIVE" {
		t.Errorf("unexpected user row: %q %q %q %q", email, name, hash, status)
	}
	if phone != "+573001234567" || address != "Calle 1 # 2-3" {
		t.Errorf("contact data not stored: phone=%q address=%q", phone, address)
	}
	var roles []string
	rows, err := f.pool.Query(ctx, `SELECT r.name FROM auth.user_role ur JOIN auth.role r ON r.id = ur.role_id WHERE ur.user_id = $1`, user.ID())
	if err != nil {
		t.Fatalf("roles query error = %v", err)
	}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			t.Fatal(err)
		}
		roles = append(roles, role)
	}
	rows.Close()
	if len(roles) != 1 || roles[0] != "CLIENT" {
		t.Errorf("roles = %v, want [CLIENT]", roles)
	}
	exists, err := f.users.ExistsByEmail(ctx, user.Email())
	if err != nil || !exists {
		t.Errorf("ExistsByEmail() = %v, %v, want true", exists, err)
	}
}

func TestRollbackLeavesNothingBehind(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))
	failure := errors.New("outbox failed")

	err := f.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		if err := f.users.Save(ctx, user); err != nil {
			return err
		}
		return failure
	})

	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want %v", err, failure)
	}
	exists, err := f.users.ExistsByEmail(ctx, user.Email())
	if err != nil || exists {
		t.Errorf("ExistsByEmail() = %v, %v, want false after rollback", exists, err)
	}
	var roleRows int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.user_role WHERE user_id = $1`, user.ID()).Scan(&roleRows); err != nil || roleRows != 0 {
		t.Errorf("user_role rows = %d, %v, want 0", roleRows, err)
	}
}

func TestSaveRejectsADuplicateEmailIgnoringCase(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	email := uniqueEmail(t)
	if err := f.register(t, ctx, newUser(t, email)); err != nil {
		t.Fatalf("first register error = %v", err)
	}

	err := f.register(t, ctx, newUser(t, strings.ToLower(email)))

	if !errors.Is(err, model.ErrEmailAlreadyRegistered) {
		t.Errorf("error = %v, want ErrEmailAlreadyRegistered", err)
	}
}

func TestConcurrentSavesOfTheSameEmailLeaveOneWinner(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	email := uniqueEmail(t)
	results := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(1)
	for range 2 {
		user := newUser(t, email)
		go func() {
			start.Wait()
			results <- f.register(t, ctx, user)
		}()
	}
	start.Done()

	first, second := <-results, <-results

	succeeded, duplicated := 0, 0
	for _, err := range []error{first, second} {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, model.ErrEmailAlreadyRegistered):
			duplicated++
		default:
			t.Errorf("unexpected error %v", err)
		}
	}
	if succeeded != 1 || duplicated != 1 {
		t.Errorf("succeeded=%d duplicated=%d, want 1 and 1", succeeded, duplicated)
	}
}

func TestOutboxPayloadHasTheEnvelopeAndNoContactData(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	reader := openPool(t, readerURLVariable)
	user := newUser(t, uniqueEmail(t))
	event := model.NewUserRegistered(newUUID(t), time.Date(2026, 9, 6, 19, 0, 0, 0, time.UTC), user)
	err := f.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		if err := f.users.Save(ctx, user); err != nil {
			return err
		}
		return f.outbox.Append(ctx, event)
	})
	if err != nil {
		t.Fatalf("register error = %v", err)
	}

	var aggregateType, aggregateID, eventType string
	var payload []byte
	err = reader.QueryRow(ctx, `SELECT aggregate_type, aggregate_id::text, event_type, payload FROM auth.outbox_event WHERE id = $1`, event.EventID).
		Scan(&aggregateType, &aggregateID, &eventType, &payload)
	if err != nil {
		t.Fatalf("outbox row not stored: %v", err)
	}
	if aggregateType != "User" || aggregateID != user.ID() || eventType != "UserRegistered" {
		t.Errorf("unexpected outbox row: %s %s %s", aggregateType, aggregateID, eventType)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if decoded["eventId"] != event.EventID || decoded["version"] != float64(1) || decoded["source"] != "auth-service" {
		t.Errorf("unexpected envelope: %s", payload)
	}
	for _, forbidden := range []string{"phone", "address", "password", "3001234567", "Calle 1"} {
		if strings.Contains(string(payload), forbidden) {
			t.Errorf("payload contains %q: %s", forbidden, payload)
		}
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM auth.outbox_event WHERE id = $1`, event.EventID); err != nil {
		t.Errorf("cleanup of the outbox row failed: %v", err)
	}
}

func TestFindByEmailLoadsTheUserWithItsRolesAndContactData(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'ADMIN'`, user.ID()); err != nil {
		t.Fatalf("grant ADMIN error = %v", err)
	}

	found, err := f.users.FindByEmail(ctx, user.Email())

	if err != nil {
		t.Fatalf("FindByEmail() error = %v", err)
	}
	if found.ID() != user.ID() || found.Email() != user.Email() || found.Name().String() != "Ana Perez" || found.PasswordHash() != bcryptHash {
		t.Errorf("found = %q %q %q, want the stored user", found.ID(), found.Email(), found.Name())
	}
	if found.Phone().String() != "+573001234567" || found.Address().String() != "Calle 1 # 2-3" || found.Status() != model.UserActive {
		t.Errorf("contact data or status not loaded: %q %q %v", found.Phone(), found.Address(), found.Status())
	}
	if !found.HasRole(model.RoleClient) || !found.HasRole(model.RoleAdmin) || len(found.Roles()) != 2 {
		t.Errorf("roles = %v, want CLIENT and ADMIN", found.Roles())
	}
}

func TestFindByEmailIsCaseInsensitiveThroughTheEmailValueObject(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	upper, err := model.NewEmail(strings.ToUpper(user.Email().String()))
	if err != nil {
		t.Fatalf("NewEmail() error = %v", err)
	}

	found, err := f.users.FindByEmail(ctx, upper)

	if err != nil || found.ID() != user.ID() {
		t.Errorf("FindByEmail(upper) = %v, %v, want the registered user", found, err)
	}
}

func TestFindByEmailReportsAnUnknownEmailAsNotFound(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	email, _ := model.NewEmail(uniqueEmail(t))

	found, err := f.users.FindByEmail(ctx, email)

	if !errors.Is(err, model.ErrUserNotFound) || found != nil {
		t.Errorf("FindByEmail() = %v, %v, want nil and model.ErrUserNotFound", found, err)
	}
}

func TestFindByEmailLoadsALockedUserWithoutContactData(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.app_user SET status = 'LOCKED', phone = NULL, address = NULL WHERE id = $1`, user.ID()); err != nil {
		t.Fatalf("update error = %v", err)
	}

	found, err := f.users.FindByEmail(ctx, user.Email())

	if err != nil {
		t.Fatalf("FindByEmail() error = %v", err)
	}
	if found.Status() != model.UserLocked || found.Phone().String() != "" || found.Address().String() != "" {
		t.Errorf("status = %v phone = %q address = %q, want LOCKED without contact data", found.Status(), found.Phone(), found.Address())
	}
}
