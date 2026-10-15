//go:build integration

package persistence

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// registerWithPrefix registers one user per suffix, with the email prefix+suffix@example.com, and
// returns them in the order of the suffixes. The prefix is unique to the test, so the rows of
// other tests never match it.
func (f fixture) registerWithPrefix(t *testing.T, ctx context.Context, prefix string, suffixes ...string) []*model.User {
	t.Helper()
	users := make([]*model.User, 0, len(suffixes))
	for _, suffix := range suffixes {
		user := newUser(t, prefix+suffix+"@Example.com")
		if err := f.register(t, ctx, user); err != nil {
			t.Fatalf("register %s error = %v", suffix, err)
		}
		users = append(users, user)
	}
	return users
}

func searchPrefix(t *testing.T, raw string) model.EmailPrefix {
	t.Helper()
	prefix, err := model.NewEmailPrefix(raw)
	if err != nil {
		t.Fatalf("NewEmailPrefix(%q) error = %v", raw, err)
	}
	return prefix
}

func pageOf(t *testing.T, number, limit int) model.Page {
	t.Helper()
	page, err := model.NewPage(number, limit)
	if err != nil {
		t.Fatalf("NewPage(%d, %d) error = %v", number, limit, err)
	}
	return page
}

func TestSearchUsersPagesByEmailThenIdWithItsActiveRoles(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	reader := NewUserReader(f.pool)
	prefix := "pg" + strings.ReplaceAll(newUUID(t)[:8], "-", "")
	users := f.registerWithPrefix(t, ctx, prefix, "1", "2", "3")
	if _, err := f.pool.Exec(ctx, `INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'ADMIN'`, users[1].ID()); err != nil {
		t.Fatalf("grant ADMIN error = %v", err)
	}

	first, err := reader.SearchUsers(ctx, searchPrefix(t, strings.ToUpper(prefix)), pageOf(t, 1, 2))
	if err != nil {
		t.Fatalf("SearchUsers() error = %v", err)
	}
	second, err := reader.SearchUsers(ctx, searchPrefix(t, prefix), pageOf(t, 2, 2))
	if err != nil {
		t.Fatalf("SearchUsers() page 2 error = %v", err)
	}
	beyond, err := reader.SearchUsers(ctx, searchPrefix(t, prefix), pageOf(t, 3, 2))
	if err != nil {
		t.Fatalf("SearchUsers() page 3 error = %v", err)
	}

	if first.Total != 3 || second.Total != 3 || beyond.Total != 3 || len(beyond.Items) != 0 {
		t.Errorf("totals = %d/%d/%d and %d items beyond the end, want 3/3/3 and none", first.Total, second.Total, beyond.Total, len(beyond.Items))
	}
	if len(first.Items) != 2 || len(second.Items) != 1 {
		t.Fatalf("page sizes = %d and %d, want 2 and 1", len(first.Items), len(second.Items))
	}
	for position, item := range append(first.Items, second.Items...) {
		if item.ID != users[position].ID() || item.Email != users[position].Email().String() || item.Name != "Ana Perez" {
			t.Errorf("item %d = %+v, want %s ordered by email", position, item, users[position].Email())
		}
	}
	if want := []model.Role{model.RoleAdmin, model.RoleClient}; !reflect.DeepEqual(first.Items[1].Roles, want) {
		t.Errorf("roles of the administrator = %v, want %v", first.Items[1].Roles, want)
	}
	if want := []model.Role{model.RoleClient}; !reflect.DeepEqual(first.Items[0].Roles, want) {
		t.Errorf("roles of the client = %v, want %v", first.Items[0].Roles, want)
	}
}

func TestSearchUsersHidesSoftDeletedUsersAndRevokedRoles(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	reader := NewUserReader(f.pool)
	prefix := "sd" + strings.ReplaceAll(newUUID(t)[:8], "-", "")
	users := f.registerWithPrefix(t, ctx, prefix, "1", "2")
	if _, err := f.pool.Exec(ctx, `UPDATE auth.app_user SET deleted_at = NOW() WHERE id = $1`, users[0].ID()); err != nil {
		t.Fatalf("soft delete error = %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.user_role SET deleted_at = NOW() WHERE user_id = $1`, users[1].ID()); err != nil {
		t.Fatalf("revoke error = %v", err)
	}

	found, err := reader.SearchUsers(ctx, searchPrefix(t, prefix), pageOf(t, 1, 20))

	if err != nil || found.Total != 1 || len(found.Items) != 1 || found.Items[0].ID != users[1].ID() {
		t.Fatalf("found = %+v, %v, want only the user that is not deleted", found, err)
	}
	if len(found.Items[0].Roles) != 0 {
		t.Errorf("roles = %v, want none: the assignment was revoked", found.Items[0].Roles)
	}
}

func TestSearchUsersTakesLikeWildcardsAsOrdinaryCharacters(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	reader := NewUserReader(f.pool)
	prefix := "wc" + strings.ReplaceAll(newUUID(t)[:8], "-", "")
	f.registerWithPrefix(t, ctx, prefix, "_x", "ax", "%y", "by")

	for pattern, want := range map[string]string{prefix + "_": prefix + "_x@example.com", prefix + "%": prefix + "%y@example.com"} {
		found, err := reader.SearchUsers(ctx, searchPrefix(t, pattern), pageOf(t, 1, 20))

		if err != nil || found.Total != 1 || len(found.Items) != 1 || found.Items[0].Email != want {
			t.Errorf("prefix %q: found = %+v, %v, want only %s", pattern, found, err, want)
		}
	}
}

func TestSearchUsersWithoutPrefixListsEveryone(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	f.registerWithPrefix(t, ctx, "all"+strings.ReplaceAll(newUUID(t)[:8], "-", ""), "1")

	found, err := NewUserReader(f.pool).SearchUsers(ctx, model.EmailPrefix{}, pageOf(t, 1, 1))

	if err != nil || found.Total < 1 || len(found.Items) != 1 {
		t.Errorf("found = %+v, %v, want one item of at least one user", found, err)
	}
}

// The prefix search is only fast with idx_app_user_email_pattern (csp-auth-db V023). Sequential
// scans are switched off for the connection, so the plan shows whether the index can serve the
// statement the reader sends, planned the way the reader sends it.
func TestSearchUsersStatementsCanUseTheEmailPatternIndex(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	conn, err := f.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire a connection: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET enable_seqscan = off`); err != nil {
		t.Fatalf("disable sequential scans: %v", err)
	}
	statements := map[string][]any{countUsersSQL: {"maria%"}, pageUsersSQL: {"maria%", 20, 0}}

	for statement, arguments := range statements {
		rows, err := conn.Query(ctx, "EXPLAIN "+statement, append([]any{pgx.QueryExecModeExec}, arguments...)...)
		if err != nil {
			t.Fatalf("EXPLAIN error = %v", err)
		}
		var plan strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(line + "\n")
		}
		rows.Close()
		if rows.Err() != nil || !strings.Contains(plan.String(), "idx_app_user_email_pattern") {
			t.Errorf("plan of %q = %s (error %v), want it to use idx_app_user_email_pattern", statement, plan.String(), rows.Err())
		}
	}
}
