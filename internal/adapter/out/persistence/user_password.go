package persistence

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

var (
	_ out.PasswordUpdater       = (*UserRepository)(nil)
	_ out.CurrentPasswordReader = (*UserRepository)(nil)
	_ out.PasswordHashLocker    = (*UserRepository)(nil)
)

// LockPasswordHashOf returns the bcrypt hash of the active account userID and keeps its row locked (FOR NO KEY UPDATE) until
// the transaction ends, so two changes of the same password run one after the other. An account that does not exist or was
// deleted is model.ErrUserNotFound.
func (r *UserRepository) LockPasswordHashOf(ctx context.Context, userID string) (string, error) {
	var hash string
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT password_hash FROM auth.app_user WHERE id = $1 AND deleted_at IS NULL FOR NO KEY UPDATE`, userID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", model.ErrUserNotFound
	}
	return hash, err
}

// PasswordHashOf returns the bcrypt hash of the active account userID. An account that does not exist or was
// deleted is model.ErrUserNotFound.
func (r *UserRepository) PasswordHashOf(ctx context.Context, userID string) (string, error) {
	var hash string
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT password_hash FROM auth.app_user WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", model.ErrUserNotFound
	}
	return hash, err
}

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
