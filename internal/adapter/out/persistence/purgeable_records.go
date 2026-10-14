package persistence

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// agedRows implements out.PurgeableRecords over one table. The rows to delete are picked by
// eligible, a condition on the placeholder $1 (the cutoff), oldest first by orderBy, and deleted
// by primary key so that a batch is bounded by its limit (ADR-030).
type agedRows struct {
	pool     *pgxpool.Pool
	table    string
	key      string
	eligible string
	orderBy  string
}

var _ out.PurgeableRecords = (*agedRows)(nil)

// NewOutboxPurger purges auth.outbox_event rows created before the cutoff. The relay of
// csp-worker marks nothing in the table, so retention is by age (ADR-019).
func NewOutboxPurger(pool *pgxpool.Pool) out.PurgeableRecords {
	return &agedRows{pool: pool, table: "auth.outbox_event", key: "id", eligible: "created_at < $1", orderBy: "created_at, id"}
}

// NewRefreshTokenPurger purges auth.refresh_token rows that expired or were revoked before the
// cutoff.
func NewRefreshTokenPurger(pool *pgxpool.Pool) out.PurgeableRecords {
	return &agedRows{pool: pool, table: "auth.refresh_token", key: "id", eligible: "(expires_at < $1 OR revoked_at < $1)", orderBy: "expires_at, id"}
}

// NewIdempotencyKeyPurger purges auth.idempotency_key rows created before the cutoff. There is no
// index on created_at, so the first purge of a large table scans it (ADR-030).
func NewIdempotencyKeyPurger(pool *pgxpool.Pool) out.PurgeableRecords {
	return &agedRows{pool: pool, table: "auth.idempotency_key", key: "key", eligible: "created_at < $1", orderBy: "created_at, key"}
}

func (r *agedRows) DeleteOlderThan(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	tag, err := r.pool.Exec(ctx,
		"DELETE FROM "+r.table+" WHERE "+r.key+" IN (SELECT "+r.key+" FROM "+r.table+
			" WHERE "+r.eligible+" ORDER BY "+r.orderBy+" LIMIT $2)", cutoff, limit)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (r *agedRows) ExistOlderThan(ctx context.Context, cutoff time.Time) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM "+r.table+" WHERE "+r.eligible+")", cutoff).Scan(&exists)
	return exists, err
}
