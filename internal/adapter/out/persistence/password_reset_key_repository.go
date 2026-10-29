package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const passwordResetKeyPrimaryKey = "pk_password_reset_idempotency_key"

// PasswordResetKeyRepository implements out.PasswordResetKeyRepository over
// auth.password_reset_idempotency_key. Rows are only inserted and read here; only the purge deletes
// them (NewPasswordResetKeyPurger).
type PasswordResetKeyRepository struct {
	pool *pgxpool.Pool
}

var _ out.PasswordResetKeyRepository = (*PasswordResetKeyRepository)(nil)

// NewPasswordResetKeyRepository creates a repository over pool.
func NewPasswordResetKeyRepository(pool *pgxpool.Pool) *PasswordResetKeyRepository {
	return &PasswordResetKeyRepository{pool: pool}
}

// Find returns the request hash and the linked request stored with key; the link is empty when the
// request created none.
func (r *PasswordResetKeyRepository) Find(ctx context.Context, key model.IdempotencyKey) (out.PasswordResetKeyRecord, bool, error) {
	var record out.PasswordResetKeyRecord
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT request_hash, COALESCE(password_reset_id::text, '') FROM auth.password_reset_idempotency_key WHERE key = $1`,
		key.String()).Scan(&record.RequestHash, &record.PasswordResetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return out.PasswordResetKeyRecord{}, false, nil
	}
	if err != nil {
		return out.PasswordResetKeyRecord{}, false, err
	}
	return record, true, nil
}

// Save inserts the key, linked to the request when there is one. A key that is already stored is
// model.ErrIdempotencyKeyTaken, also when the other request is not committed yet: the insert waits
// for it and then fails.
func (r *PasswordResetKeyRepository) Save(ctx context.Context, key model.IdempotencyKey, record out.PasswordResetKeyRecord) error {
	var passwordResetID *string
	if record.PasswordResetID != "" {
		passwordResetID = &record.PasswordResetID
	}
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`INSERT INTO auth.password_reset_idempotency_key (key, request_hash, password_reset_id) VALUES ($1, $2, $3)`,
		key.String(), record.RequestHash, passwordResetID)
	if isUniqueViolationOf(err, passwordResetKeyPrimaryKey) {
		return model.ErrIdempotencyKeyTaken
	}
	return err
}
