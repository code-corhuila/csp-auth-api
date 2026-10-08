package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const idempotencyKeyPrimaryKey = "pk_idempotency_key"

// IdempotencyKeyRepository implements out.IdempotencyKeyRepository over auth.idempotency_key.
// Rows are only inserted and read: auth_writer has no UPDATE or DELETE on the table.
type IdempotencyKeyRepository struct {
	pool *pgxpool.Pool
}

var _ out.IdempotencyKeyRepository = (*IdempotencyKeyRepository)(nil)

// NewIdempotencyKeyRepository creates a repository over pool.
func NewIdempotencyKeyRepository(pool *pgxpool.Pool) *IdempotencyKeyRepository {
	return &IdempotencyKeyRepository{pool: pool}
}

// Find returns the account and the request hash stored with key.
func (r *IdempotencyKeyRepository) Find(ctx context.Context, key model.IdempotencyKey) (out.IdempotencyRecord, bool, error) {
	var record out.IdempotencyRecord
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT user_id::text, request_hash FROM auth.idempotency_key WHERE key = $1`,
		key.String()).Scan(&record.UserID, &record.RequestHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return out.IdempotencyRecord{}, false, nil
	}
	if err != nil {
		return out.IdempotencyRecord{}, false, err
	}
	return record, true, nil
}

// Save inserts the key. A key that is already stored is model.ErrIdempotencyKeyTaken, also when
// the other request is not committed yet: the insert waits for it and then fails.
func (r *IdempotencyKeyRepository) Save(ctx context.Context, key model.IdempotencyKey, record out.IdempotencyRecord) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`INSERT INTO auth.idempotency_key (key, user_id, request_hash) VALUES ($1, $2, $3)`,
		key.String(), record.UserID, record.RequestHash)
	if isDuplicateIdempotencyKey(err) {
		return model.ErrIdempotencyKeyTaken
	}
	return err
}

func isDuplicateIdempotencyKey(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == idempotencyKeyPrimaryKey
}
