package persistence

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const refreshTokenHashIndex = "uk_refresh_token_token_hash"

// RefreshTokenRepository implements out.RefreshTokenRepository over auth.refresh_token. Rows are
// never deleted (auth_writer has no DELETE): revoking sets revoked_at.
type RefreshTokenRepository struct {
	pool *pgxpool.Pool
}

var _ out.RefreshTokenRepository = (*RefreshTokenRepository)(nil)

// NewRefreshTokenRepository creates a repository over pool.
func NewRefreshTokenRepository(pool *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{pool: pool}
}

// Save inserts the token. An empty user agent is stored as NULL.
func (r *RefreshTokenRepository) Save(ctx context.Context, token *model.RefreshToken) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`INSERT INTO auth.refresh_token (id, user_id, token_hash, expires_at, user_agent)
		 VALUES ($1, $2, $3, $4, NULLIF($5, ''))`,
		token.ID(), token.UserID(), token.Hash(), token.ExpiresAt(), token.UserAgent())
	if isDuplicateRefreshTokenHash(err) {
		return model.ErrRefreshTokenDuplicated
	}
	return err
}

// FindByHash returns the active record (not soft-deleted) whose digest is hash.
func (r *RefreshTokenRepository) FindByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	var id, userID string
	var userAgent *string
	var expiresAt time.Time
	var revokedAt *time.Time
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT id::text, user_id::text, user_agent, expires_at, revoked_at
		 FROM auth.refresh_token WHERE token_hash = $1 AND deleted_at IS NULL`, hash).
		Scan(&id, &userID, &userAgent, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	agent := ""
	if userAgent != nil {
		agent = *userAgent
	}
	return model.RestoreRefreshToken(id, userID, hash, agent, expiresAt, revokedAt), nil
}

// RevokeByHash is one UPDATE, so the row lock makes concurrent callers with the same token take
// turns and only the first one still finds it active.
func (r *RefreshTokenRepository) RevokeByHash(ctx context.Context, hash string, at time.Time) (string, bool, error) {
	var userID string
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`UPDATE auth.refresh_token SET revoked_at = $2, updated_at = NOW()
		 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2 AND deleted_at IS NULL
		 RETURNING user_id::text`, hash, at).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return userID, true, nil
}

func isDuplicateRefreshTokenHash(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == refreshTokenHashIndex
}
