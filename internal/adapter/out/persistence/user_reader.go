package persistence

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// likeEscaper makes the wildcards of LIKE ordinary characters, so a prefix such as "a_b" matches
// only itself.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

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
// form a text_pattern_ops index on the email can serve.
func (r *UserReader) SearchUsers(ctx context.Context, prefix model.EmailPrefix, page model.Page) (out.UserListPage, error) {
	pattern := likeEscaper.Replace(prefix.String()) + "%"
	var result out.UserListPage
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM auth.app_user WHERE deleted_at IS NULL AND email LIKE $1`, pattern).Scan(&result.Total); err != nil {
		return out.UserListPage{}, err
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id::text, email, name FROM auth.app_user WHERE deleted_at IS NULL AND email LIKE $1
		 ORDER BY email, id LIMIT $2 OFFSET $3`, pattern, page.Limit(), page.Offset())
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
