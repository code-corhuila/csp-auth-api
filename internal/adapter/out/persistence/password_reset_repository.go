package persistence

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// PasswordResetRepository implements out.PasswordResetRepository over auth.password_reset and
// auth.app_user (pattern Repository, ADR-050). A pending request has neither used_at nor deleted_at;
// a superseded request is soft-deleted, and the unique index of csp-auth-db keeps one pending per user.
type PasswordResetRepository struct {
	pool *pgxpool.Pool
}

var _ out.PasswordResetRepository = (*PasswordResetRepository)(nil)

// NewPasswordResetRepository creates a repository over pool.
func NewPasswordResetRepository(pool *pgxpool.Pool) *PasswordResetRepository {
	return &PasswordResetRepository{pool: pool}
}

// LockRequestsOf locks the row of an active account until the transaction ends, so the requests of one user
// are counted, superseded and stored one after the other. NO KEY UPDATE does not block the foreign key
// check of the insert of the request. An account that is locked or deleted is model.ErrUserNotFound.
func (r *PasswordResetRepository) LockRequestsOf(ctx context.Context, userID string) error {
	var locked string
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT id::text FROM auth.app_user WHERE id = $1 AND status = 'ACTIVE' AND deleted_at IS NULL FOR NO KEY UPDATE`,
		userID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ErrUserNotFound
	}
	return err
}

// CountRequestsSince counts the requests of the user created at or after since: pending, superseded and used ones.
func (r *PasswordResetRepository) CountRequestsSince(ctx context.Context, userID string, since time.Time) (int, error) {
	var requested int
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT count(*) FROM auth.password_reset WHERE user_id = $1 AND created_at >= $2`, userID, since).Scan(&requested)
	return requested, err
}

// SupersedePending soft-deletes the pending request of the user, so only the last token is valid.
func (r *PasswordResetRepository) SupersedePending(ctx context.Context, userID string, at time.Time) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`UPDATE auth.password_reset SET deleted_at = $2, updated_at = $2, updated_by = $1
		 WHERE user_id = $1 AND used_at IS NULL AND deleted_at IS NULL`, userID, at)
	return err
}

// Add stores a pending request. created_at is the instant of the request, derived from its expiry, so the
// rolling count uses the clock of the use case and not the one of the database.
func (r *PasswordResetRepository) Add(ctx context.Context, reset *model.PasswordReset) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`INSERT INTO auth.password_reset (id, user_id, token_hash, expires_at, created_at, updated_at, created_by, updated_by)
		 VALUES ($1, $2, $3, $4, $5, $5, $2, $2)`,
		reset.ID(), reset.UserID(), reset.TokenHash(), reset.ExpiresAt(), reset.RequestedAt())
	return err
}

// LockByTokenHash finds the request, locks the account of its user and then the request, the order of
// the email change, so a request and a reset of one user never wait for each other in a cycle. The
// request is read again under its lock because a new request may have superseded it meanwhile.
func (r *PasswordResetRepository) LockByTokenHash(ctx context.Context, tokenHash string) (*model.PasswordReset, error) {
	db := executorFor(ctx, r.pool)
	var userID string
	err := db.QueryRow(ctx,
		`SELECT user_id::text FROM auth.password_reset WHERE token_hash = $1 AND deleted_at IS NULL`, tokenHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrPasswordResetRejected
	}
	if err != nil {
		return nil, err
	}
	if err := r.LockRequestsOf(ctx, userID); errors.Is(err, model.ErrUserNotFound) {
		return nil, model.ErrPasswordResetRejected
	} else if err != nil {
		return nil, err
	}
	var id string
	var expiresAt time.Time
	var usedAt *time.Time
	err = db.QueryRow(ctx,
		`SELECT id::text, expires_at, used_at FROM auth.password_reset WHERE token_hash = $1 AND deleted_at IS NULL FOR UPDATE`,
		tokenHash).Scan(&id, &expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrPasswordResetRejected
	}
	if err != nil {
		return nil, err
	}
	return model.RestorePasswordReset(id, userID, tokenHash, expiresAt, usedAt), nil
}

// MarkUsed stores the consumption of the request.
func (r *PasswordResetRepository) MarkUsed(ctx context.Context, reset *model.PasswordReset) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`UPDATE auth.password_reset SET used_at = $2, updated_at = $2, updated_by = $3 WHERE id = $1`,
		reset.ID(), reset.UsedAt(), reset.UserID())
	return err
}
