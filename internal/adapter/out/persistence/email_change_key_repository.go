package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const emailChangeKeyPrimaryKey = "pk_email_change_idempotency_key"

// EmailChangeKeyRepository implements out.EmailChangeKeyRepository over
// auth.email_change_idempotency_key. Rows are only inserted and read here; only the purge deletes
// them (NewEmailChangeKeyPurger).
type EmailChangeKeyRepository struct {
	pool *pgxpool.Pool
}

var _ out.EmailChangeKeyRepository = (*EmailChangeKeyRepository)(nil)

// NewEmailChangeKeyRepository creates a repository over pool.
func NewEmailChangeKeyRepository(pool *pgxpool.Pool) *EmailChangeKeyRepository {
	return &EmailChangeKeyRepository{pool: pool}
}

// Find returns the request hash and the pending request stored with key. The link is empty once the
// request was deleted (ON DELETE SET NULL).
func (r *EmailChangeKeyRepository) Find(ctx context.Context, key model.IdempotencyKey) (out.EmailChangeKeyRecord, bool, error) {
	var record out.EmailChangeKeyRecord
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT request_hash, COALESCE(email_verification_id::text, '') FROM auth.email_change_idempotency_key WHERE key = $1`,
		key.String()).Scan(&record.RequestHash, &record.EmailVerificationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return out.EmailChangeKeyRecord{}, false, nil
	}
	if err != nil {
		return out.EmailChangeKeyRecord{}, false, err
	}
	return record, true, nil
}

// Save inserts the key linked to the request it created. A key that is already stored is
// model.ErrIdempotencyKeyTaken, also when the other request is not committed yet: the insert waits
// for it and then fails.
func (r *EmailChangeKeyRepository) Save(ctx context.Context, key model.IdempotencyKey, record out.EmailChangeKeyRecord) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`INSERT INTO auth.email_change_idempotency_key (key, request_hash, email_verification_id) VALUES ($1, $2, $3)`,
		key.String(), record.RequestHash, record.EmailVerificationID)
	if isUniqueViolationOf(err, emailChangeKeyPrimaryKey) {
		return model.ErrIdempotencyKeyTaken
	}
	return err
}
