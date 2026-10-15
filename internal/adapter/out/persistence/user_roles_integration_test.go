//go:build integration

package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func (f fixture) changeRole(outbox out.UserRoleOutbox) *usecase.ChangeUserRole {
	return usecase.NewChangeUserRole(usecase.ChangeUserRolePorts{
		Users: f.users, Roles: f.users, Outbox: outbox, IDs: system.UUIDGenerator{}, Clock: system.Clock{}, Transactions: f.transactions,
	})
}

// registerAdmin registers a user and gives it the ADMIN role the way the seed does.
func (f fixture) registerAdmin(t *testing.T, ctx context.Context) *model.User {
	t.Helper()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'ADMIN'`, user.ID()); err != nil {
		t.Fatalf("grant ADMIN error = %v", err)
	}
	return user
}

func (f fixture) adminAssignments(t *testing.T, ctx context.Context, userID string) (live, total int, createdBy string) {
	t.Helper()
	err := f.pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE ur.deleted_at IS NULL), count(*), coalesce(max(ur.created_by::text), '')
		 FROM auth.user_role ur JOIN auth.role r ON r.id = ur.role_id AND r.name = 'ADMIN' WHERE ur.user_id = $1`, userID).Scan(&live, &total, &createdBy)
	if err != nil {
		t.Fatalf("admin assignments query error = %v", err)
	}
	return live, total, createdBy
}

// adminLockKey serializes the tests that count or retire the administrators of the shared test
// database; cmd/auth-api takes the same advisory lock.
const adminLockKey = 3013

func (f fixture) lockAdministrators(t *testing.T, ctx context.Context) {
	t.Helper()
	conn, err := f.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire a connection for the administrators lock: %v", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, adminLockKey); err != nil {
		t.Fatalf("take the administrators lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, adminLockKey)
		conn.Release()
	})
}

type failingRoleOutbox struct{ err error }

func (o failingRoleOutbox) AppendRoleChanged(context.Context, model.UserRoleChanged) error {
	return o.err
}

func TestChangeRoleGrantsRevokesAndRevivesTheAssignmentWithItsEvents(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	f.lockAdministrators(t, ctx)
	reader := openPool(t, readerURLVariable)
	admin, target := f.registerAdmin(t, ctx), newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, target); err != nil {
		t.Fatalf("register error = %v", err)
	}
	useCase := f.changeRole(f.outbox)
	command := in.ChangeUserRoleCommand{ActingAdminID: admin.ID(), UserID: target.ID(), Role: "ADMIN", Enabled: true}

	granted, err := useCase.ChangeRole(ctx, command)
	if err != nil || len(granted.Roles) != 2 {
		t.Fatalf("grant = %+v, %v, want CLIENT and ADMIN", granted, err)
	}
	if live, total, createdBy := f.adminAssignments(t, ctx, target.ID()); live != 1 || total != 1 || createdBy != admin.ID() {
		t.Errorf("after grant: live = %d, total = %d, created_by = %q, want 1, 1, %q", live, total, createdBy, admin.ID())
	}
	found, err := f.users.FindByEmail(ctx, target.Email())
	if err != nil || !found.HasRole(model.RoleAdmin) {
		t.Errorf("FindByEmail() = %v, %v, want the user with ADMIN (what login and refresh read)", found, err)
	}

	command.Enabled = false
	if revoked, err := useCase.ChangeRole(ctx, command); err != nil || len(revoked.Roles) != 1 {
		t.Fatalf("revoke = %+v, %v, want only CLIENT", revoked, err)
	}
	if live, total, _ := f.adminAssignments(t, ctx, target.ID()); live != 0 || total != 1 {
		t.Errorf("after revoke: live = %d, total = %d, want 0 and 1 (soft delete)", live, total)
	}

	command.Enabled = true
	command.ActingAdminID = target.ID()
	if _, err := useCase.ChangeRole(ctx, command); err != nil {
		t.Fatalf("second grant error = %v", err)
	}
	if live, total, createdBy := f.adminAssignments(t, ctx, target.ID()); live != 1 || total != 1 || createdBy != target.ID() {
		t.Errorf("after second grant: live = %d, total = %d, created_by = %q, want the revived row assigned by %q", live, total, createdBy, target.ID())
	}

	rows, err := reader.Query(ctx, `SELECT payload FROM auth.outbox_event WHERE aggregate_id = $1 AND event_type = 'UserRoleChanged' ORDER BY created_at, id`, target.ID())
	if err != nil {
		t.Fatalf("outbox query error = %v", err)
	}
	defer rows.Close()
	var enabled []bool
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var event struct {
			Payload struct {
				UserID, Role string
				Enabled      bool
			}
		}
		if err := json.Unmarshal(payload, &event); err != nil || event.Payload.UserID != target.ID() || event.Payload.Role != "ADMIN" {
			t.Fatalf("payload = %s, %v, want the ADMIN change of %s", payload, err, target.ID())
		}
		enabled = append(enabled, event.Payload.Enabled)
	}
	if len(enabled) != 3 || !enabled[0] || enabled[1] || !enabled[2] {
		t.Errorf("events enabled = %v, want grant, revoke, grant", enabled)
	}
}

func TestChangeRoleThatChangesNothingWritesNoEvent(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	f.lockAdministrators(t, ctx)
	reader := openPool(t, readerURLVariable)
	admin, target := f.registerAdmin(t, ctx), newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, target); err != nil {
		t.Fatalf("register error = %v", err)
	}
	useCase := f.changeRole(f.outbox)

	for _, enabled := range []bool{false, true, true} {
		command := in.ChangeUserRoleCommand{ActingAdminID: admin.ID(), UserID: target.ID(), Role: "ADMIN", Enabled: enabled}
		if _, err := useCase.ChangeRole(ctx, command); err != nil {
			t.Fatalf("ChangeRole(enabled=%v) error = %v", enabled, err)
		}
	}

	var events int
	if err := reader.QueryRow(ctx, `SELECT count(*) FROM auth.outbox_event WHERE aggregate_id = $1 AND event_type = 'UserRoleChanged'`, target.ID()).Scan(&events); err != nil || events != 1 {
		t.Errorf("events = %d, %v, want 1: the revoke of a role not held and the repeated grant publish nothing", events, err)
	}
}

func TestChangeRoleRollsBackTheAssignmentWhenTheEventCannotBeWritten(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	f.lockAdministrators(t, ctx)
	admin, target := f.registerAdmin(t, ctx), newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, target); err != nil {
		t.Fatalf("register error = %v", err)
	}
	failure := errors.New("outbox down")
	command := in.ChangeUserRoleCommand{ActingAdminID: admin.ID(), UserID: target.ID(), Role: "ADMIN", Enabled: true}

	_, err := f.changeRole(failingRoleOutbox{failure}).ChangeRole(ctx, command)

	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want %v", err, failure)
	}
	if live, total, _ := f.adminAssignments(t, ctx, target.ID()); live != 0 || total != 0 {
		t.Errorf("live = %d, total = %d, want the grant rolled back", live, total)
	}
}

func TestChangeRoleReportsAnUnknownUser(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	command := in.ChangeUserRoleCommand{ActingAdminID: newUUID(t), UserID: newUUID(t), Role: "ADMIN", Enabled: true}

	_, err := f.changeRole(f.outbox).ChangeRole(ctx, command)

	if !errors.Is(err, model.ErrUserNotFound) {
		t.Errorf("error = %v, want ErrUserNotFound", err)
	}
}

// A revoke that arrives while another transaction holds the lock on the administrators must wait for
// it and then count what that transaction left. The test plays the first transaction by hand, so the
// interleaving is certain: it locks and counts two administrators, a second revoke starts and must
// block, the first transaction revokes its own target and commits, and only then does the second one
// answer, with ErrLastAdmin. The other administrators of the throwaway database are retired first,
// so exactly two are active.
func TestARevokeWaitsForTheLockAndCountsWhatTheFirstOneLeft(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	f.lockAdministrators(t, ctx)
	first, second := f.registerAdmin(t, ctx), f.registerAdmin(t, ctx)
	_, err := f.pool.Exec(ctx,
		`UPDATE auth.user_role SET deleted_at = NOW() WHERE deleted_at IS NULL AND user_id NOT IN ($1, $2)
		   AND role_id = (SELECT id FROM auth.role WHERE name = 'ADMIN')`, first.ID(), second.ID())
	if err != nil {
		t.Fatalf("retire the other administrators error = %v", err)
	}
	waiting := make(chan error, 1)

	err = f.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		active, err := f.users.LockActiveAdmins(ctx)
		if err != nil || active != 2 {
			return fmt.Errorf("LockActiveAdmins() = %d, %v, want 2", active, err)
		}
		go func() {
			command := in.ChangeUserRoleCommand{ActingAdminID: first.ID(), UserID: second.ID(), Role: "ADMIN"}
			_, err := f.changeRole(f.outbox).ChangeRole(context.Background(), command)
			waiting <- err
		}()
		select {
		case err := <-waiting:
			return fmt.Errorf("the second revoke finished while the first transaction held the lock: %v", err)
		case <-time.After(500 * time.Millisecond):
		}
		revoked, err := f.users.FindByID(ctx, first.ID())
		if err != nil {
			return err
		}
		if _, err := revoked.SetRole(model.RoleAdmin, false, active); err != nil {
			return err
		}
		return f.users.SaveRole(ctx, revoked, model.RoleAdmin, second.ID())
	})
	if err != nil {
		t.Fatalf("first revoke error = %v", err)
	}

	if err := <-waiting; !errors.Is(err, model.ErrLastAdmin) {
		t.Errorf("second revoke error = %v, want ErrLastAdmin", err)
	}
	if live, _, _ := f.adminAssignments(t, ctx, second.ID()); live != 1 {
		t.Errorf("live administrator assignments of the survivor = %d, want 1", live)
	}
}
