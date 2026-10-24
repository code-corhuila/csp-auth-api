package persistence

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// EmailVerificationRepository implements out.EmailVerificationRepository over
// auth.email_verification and auth.app_user (pattern Repository, ADR-034). A pending request has
// neither verified_at nor deleted_at; superseded, exhausted and invalidated requests are soft-deleted.
type EmailVerificationRepository struct {
	pool *pgxpool.Pool
}

var _ out.EmailVerificationRepository = (*EmailVerificationRepository)(nil)

// NewEmailVerificationRepository creates a repository over pool.
func NewEmailVerificationRepository(pool *pgxpool.Pool) *EmailVerificationRepository {
	return &EmailVerificationRepository{pool: pool}
}

// LockRequestsOf locks the account row until the transaction ends, so the requests of one user are
// counted, superseded and stored one after the other. NO KEY UPDATE does not block the foreign key
// check of the insert of the request.
func (r *EmailVerificationRepository) LockRequestsOf(ctx context.Context, userID string) error {
	var locked string
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT id::text FROM auth.app_user WHERE id = $1 AND deleted_at IS NULL FOR NO KEY UPDATE`, userID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ErrUserNotFound
	}
	return err
}

// RequestTimesSince lists the creation instants of the requests of the user at or after since,
// oldest first: pending, superseded, exhausted and verified ones.
func (r *EmailVerificationRepository) RequestTimesSince(ctx context.Context, userID string, since time.Time) ([]time.Time, error) {
	rows, err := executorFor(ctx, r.pool).Query(ctx,
		`SELECT created_at FROM auth.email_verification WHERE user_id = $1 AND created_at >= $2 ORDER BY created_at`, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var times []time.Time
	for rows.Next() {
		var requestedAt time.Time
		if err := rows.Scan(&requestedAt); err != nil {
			return nil, err
		}
		times = append(times, requestedAt)
	}
	return times, rows.Err()
}

// SupersedePending soft-deletes the pending request of the user, so only the last code is valid.
func (r *EmailVerificationRepository) SupersedePending(ctx context.Context, userID string, at time.Time) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`UPDATE auth.email_verification SET deleted_at = $2, updated_at = $2, updated_by = $1
		 WHERE user_id = $1 AND verified_at IS NULL AND deleted_at IS NULL`, userID, at)
	return err
}

// Add stores a pending request. created_at is the instant of the request, derived from its expiry, so
// the rolling count uses the clock of the use case and not the one of the database.
func (r *EmailVerificationRepository) Add(ctx context.Context, request *model.EmailChangeRequest) error {
	requestedAt := request.ExpiresAt().Add(-model.EmailChangeCodeLifetime)
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`INSERT INTO auth.email_verification
		   (id, user_id, verification_code, expires_at, new_email, attempt_count, created_at, updated_at, created_by, updated_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $2, $2)`,
		request.ID(), request.UserID(), request.Code().String(), request.ExpiresAt(), request.NewEmail().String(), request.Attempts(), requestedAt)
	return err
}

// FindPendingForUpdate locks the pending request of the user until the transaction ends, so two
// verifications of the same request are serialized.
func (r *EmailVerificationRepository) FindPendingForUpdate(ctx context.Context, userID string) (*model.EmailChangeRequest, error) {
	var id, code, newEmail string
	var expiresAt time.Time
	var attempts int
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT id::text, verification_code, new_email, expires_at, attempt_count FROM auth.email_verification
		 WHERE user_id = $1 AND verified_at IS NULL AND deleted_at IS NULL FOR UPDATE`, userID).
		Scan(&id, &code, &newEmail, &expiresAt, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrEmailChangeNotFound
	}
	if err != nil {
		return nil, err
	}
	email, err := model.NewEmail(newEmail)
	if err != nil {
		return nil, fmt.Errorf("email verification %s: stored email: %w", id, err)
	}
	stored, err := model.NewVerificationCode(code)
	if err != nil {
		return nil, fmt.Errorf("email verification %s: stored code: %w", id, err)
	}
	return model.RestoreEmailChangeRequest(id, userID, email, stored, expiresAt, attempts), nil
}

// RecordWrongAttempt stores the attempts of the request and retires it, with deleted_at, when they
// are exhausted.
func (r *EmailVerificationRepository) RecordWrongAttempt(ctx context.Context, request *model.EmailChangeRequest, at time.Time) error {
	var deletedAt *time.Time
	if request.Exhausted() {
		deletedAt = &at
	}
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`UPDATE auth.email_verification SET attempt_count = $2, deleted_at = $3, updated_at = $4 WHERE id = $1`,
		request.ID(), request.Attempts(), deletedAt, at)
	return err
}

// Invalidate soft-deletes the request.
func (r *EmailVerificationRepository) Invalidate(ctx context.Context, request *model.EmailChangeRequest, at time.Time) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`UPDATE auth.email_verification SET deleted_at = $2, updated_at = $2 WHERE id = $1`, request.ID(), at)
	return err
}

// ConfirmEmailChange sets the new email of the account, marks it verified and consumes the request.
// The update of the account runs in a savepoint: when the unique index of the email fires, because
// another account took the address, only the savepoint is undone and the transaction stays usable
// for the caller to invalidate the request.
func (r *EmailVerificationRepository) ConfirmEmailChange(ctx context.Context, request *model.EmailChangeRequest, at time.Time) error {
	db := executorFor(ctx, r.pool)
	savepoint, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := savepoint.Exec(ctx,
		`UPDATE auth.app_user SET email = $2, email_verified = TRUE, updated_at = $3, updated_by = $1
		 WHERE id = $1 AND deleted_at IS NULL`, request.UserID(), request.NewEmail().String(), at)
	if err != nil || tag.RowsAffected() != 1 {
		_ = savepoint.Rollback(context.WithoutCancel(ctx))
		switch {
		case isDuplicateEmail(err):
			return model.ErrEmailAlreadyRegistered
		case err != nil:
			return err
		default:
			return fmt.Errorf("confirm email change %s: %d accounts updated, want 1", request.ID(), tag.RowsAffected())
		}
	}
	if err := savepoint.Commit(ctx); err != nil {
		return err
	}
	_, err = db.Exec(ctx,
		`UPDATE auth.email_verification SET verified_at = $2, updated_at = $2 WHERE id = $1`, request.ID(), at)
	return err
}
