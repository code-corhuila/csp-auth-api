package persistence

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

var _ out.PasswordUpdater = (*UserRepository)(nil)

// UpdatePasswordHash replaces the bcrypt hash of the active account userID. An account that does not exist or
// was deleted is model.ErrUserNotFound.
func (r *UserRepository) UpdatePasswordHash(ctx context.Context, userID, hash string, at time.Time) error {
	tag, err := executorFor(ctx, r.pool).Exec(ctx,
		`UPDATE auth.app_user SET password_hash = $2, updated_at = $3, updated_by = $1 WHERE id = $1 AND deleted_at IS NULL`,
		userID, hash, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return model.ErrUserNotFound
	}
	return nil
}
