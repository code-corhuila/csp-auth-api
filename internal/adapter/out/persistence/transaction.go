package persistence

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

type transactionKey struct{}

// executor is what a repository needs from a pool or from a transaction.
type executor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row
}

// TransactionManager implements out.TransactionManager (Unit of Work). The transaction travels in
// the context, so the repository and the outbox writer called with it take part in it.
type TransactionManager struct {
	pool *pgxpool.Pool
}

var _ out.TransactionManager = (*TransactionManager)(nil)

// NewTransactionManager creates a manager over pool.
func NewTransactionManager(pool *pgxpool.Pool) *TransactionManager {
	return &TransactionManager{pool: pool}
}

// WithinTransaction commits when work returns nil and rolls back otherwise. When ctx already
// carries a transaction, work joins it and the outer call decides the outcome.
func (m *TransactionManager) WithinTransaction(ctx context.Context, work func(ctx context.Context) error) error {
	if _, joined := ctx.Value(transactionKey{}).(pgx.Tx); joined {
		return work(ctx)
	}
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := work(context.WithValue(ctx, transactionKey{}, tx)); err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return err
	}
	return tx.Commit(ctx)
}

// executorFor returns the transaction carried by ctx or, when there is none, the pool.
func executorFor(ctx context.Context, pool *pgxpool.Pool) executor {
	if tx, ok := ctx.Value(transactionKey{}).(pgx.Tx); ok {
		return tx
	}
	return pool
}
