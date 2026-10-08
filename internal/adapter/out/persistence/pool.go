// Package persistence holds the outbound adapters for PostgreSQL (pgx v5, ADR-023).
// It reads and writes data only; schema and migrations live in csp-auth-db (Norma 5.2.1).
package persistence

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolSettings are the explicit limits of the connection pool (Norma 5.3.10).
// QueryTimeout becomes the statement_timeout of every connection.
type PoolSettings struct {
	URL            string
	MaxConnections int
	MinConnections int
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
}

// NewPool opens a pool with the given limits and checks that the database answers.
func NewPool(ctx context.Context, settings PoolSettings) (*pgxpool.Pool, error) {
	cfg, err := poolConfig(settings)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}

func poolConfig(settings PoolSettings) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(settings.URL)
	if err != nil {
		return nil, fmt.Errorf("parse postgres url: %w", err)
	}
	cfg.MaxConns = int32(settings.MaxConnections)
	cfg.MinConns = int32(settings.MinConnections)
	cfg.ConnConfig.ConnectTimeout = settings.ConnectTimeout
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(settings.QueryTimeout.Milliseconds(), 10)
	return cfg, nil
}
