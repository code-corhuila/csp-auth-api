package persistence

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// likeEscaper makes the wildcards of LIKE ordinary characters, so a prefix such as "a_b" matches
// only itself.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

const (
	countUsersSQL = `SELECT count(*) FROM auth.app_user WHERE deleted_at IS NULL AND email LIKE $1`
	pageUsersSQL  = `SELECT id::text, email, name FROM auth.app_user WHERE deleted_at IS NULL AND email LIKE $1
		 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`
)

// UserReader implements out.UserReader over auth.app_user and auth.user_role.
type UserReader struct {
	pool *pgxpool.Pool
}

var _ out.UserReader = (*UserReader)(nil)

// NewUserReader creates a reader over pool.
func NewUserReader(pool *pgxpool.Pool) *UserReader {
	return &UserReader{pool: pool}
}

// SearchUsers counts the active accounts whose email starts with prefix and reads one page of them
// with their active roles. The prefix is compared as stored (lower case) with LIKE 'prefix%', the
// form the text_pattern_ops index idx_app_user_email_pattern serves (csp-auth-db V023). Both queries
// run in pgx.QueryExecModeExec: the statement is not prepared, so every execution is planned with the
// prefix in hand. A prepared statement switches to a generic plan after five executions, and a generic
// plan cannot use the index because it does not know where the pattern's wildcard is.
func (r *UserReader) SearchUsers(ctx context.Context, prefix model.EmailPrefix, page model.Page) (out.UserListPage, error) {
	pattern := likeEscaper.Replace(prefix.String()) + "%"
	var result out.UserListPage
	if err := r.pool.QueryRow(ctx, countUsersSQL, pgx.QueryExecModeExec, pattern).Scan(&result.Total); err != nil {
		return out.UserListPage{}, err
	}
	rows, err := r.pool.Query(ctx, pageUsersSQL, pgx.QueryExecModeExec, pattern, page.Limit(), page.Offset())
	if err != nil {
		return out.UserListPage{}, err
	}
	defer rows.Close()
	positions := make(map[string]int)
	ids := []string{}
	for rows.Next() {
		var item out.UserListItem
		if err := rows.Scan(&item.ID, &item.Email, &item.Name); err != nil {
			return out.UserListPage{}, err
		}
		positions[item.ID] = len(result.Items)
		ids = append(ids, item.ID)
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return out.UserListPage{}, err
	}
	rows.Close()
	return result, r.loadRoles(ctx, result.Items, positions, ids)
}

// loadRoles adds the active roles of the users on the page, in one query.
func (r *UserReader) loadRoles(ctx context.Context, items []out.UserListItem, positions map[string]int, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT ur.user_id::text, r.name FROM auth.user_role ur
		 JOIN auth.role r ON r.id = ur.role_id AND r.deleted_at IS NULL
		 WHERE ur.user_id = ANY($1::uuid[]) AND ur.deleted_at IS NULL
		 ORDER BY r.name`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var userID, stored string
		if err := rows.Scan(&userID, &stored); err != nil {
			return err
		}
		role, err := model.ParseRole(stored)
		if err != nil {
			return err
		}
		items[positions[userID]].Roles = append(items[positions[userID]].Roles, role)
	}
	return rows.Err()
}
