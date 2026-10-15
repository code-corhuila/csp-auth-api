package persistence

import (
	"context"
	"fmt"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

var _ out.UserRoleRepository = (*UserRepository)(nil)

// LockActiveAdmins locks the live ADMIN assignments of the ACTIVE accounts until the transaction
// ends and counts them. A concurrent revoke waits on the lock and, once this transaction commits,
// no longer sees the assignment that was revoked, so it counts what is really left.
func (r *UserRepository) LockActiveAdmins(ctx context.Context) (int, error) {
	var count int
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT count(*) FROM (
		   SELECT ur.id FROM auth.user_role ur
		   JOIN auth.role r ON r.id = ur.role_id AND r.name = $1 AND r.deleted_at IS NULL
		   JOIN auth.app_user u ON u.id = ur.user_id AND u.status = 'ACTIVE' AND u.deleted_at IS NULL
		   WHERE ur.deleted_at IS NULL
		   FOR UPDATE OF ur) locked`,
		model.RoleAdmin.String()).Scan(&count)
	return count, err
}

// SaveRole stores whether user holds role. A grant inserts the assignment or revives the one that was
// revoked; a revoke soft-deletes it, so the history of who assigned what stays in the row.
func (r *UserRepository) SaveRole(ctx context.Context, user *model.User, role model.Role, changedBy string) error {
	db := executorFor(ctx, r.pool)
	if !user.HasRole(role) {
		tag, err := db.Exec(ctx,
			`UPDATE auth.user_role SET deleted_at = NOW(), updated_at = NOW(), updated_by = $3
			 WHERE user_id = $1 AND deleted_at IS NULL AND role_id = (SELECT id FROM auth.role WHERE name = $2)`,
			user.ID(), role.String(), changedBy)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("revoke %s from %s: %d assignments found, want 1", role, user.ID(), tag.RowsAffected())
		}
		return nil
	}
	tag, err := db.Exec(ctx,
		`INSERT INTO auth.user_role (user_id, role_id, created_by, updated_by)
		 SELECT $1, id, $3, $3 FROM auth.role WHERE name = $2 AND deleted_at IS NULL
		 ON CONFLICT ON CONSTRAINT uk_user_role_user_id_role_id
		 DO UPDATE SET deleted_at = NULL, updated_at = NOW(), created_by = EXCLUDED.created_by, updated_by = EXCLUDED.updated_by`,
		user.ID(), role.String(), changedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("grant %s to %s: %d assignments written, want 1", role, user.ID(), tag.RowsAffected())
	}
	return nil
}
