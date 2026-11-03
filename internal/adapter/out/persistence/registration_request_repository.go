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

const registrationKeyUniqueIndex = "uk_registration_request_idempotency_key"

// RegistrationRequestRepository implements out.RegistrationRequestRepository over auth.registration_request (pattern
// Repository, issue csp-docs#282). A pending request holds a token and has neither used_at nor deleted_at; a superseded
// one is soft-deleted, and the unique index of csp-auth-db keeps one pending request per address.
type RegistrationRequestRepository struct {
	pool *pgxpool.Pool
}

var _ out.RegistrationRequestRepository = (*RegistrationRequestRepository)(nil)

// NewRegistrationRequestRepository creates a repository over pool.
func NewRegistrationRequestRepository(pool *pgxpool.Pool) *RegistrationRequestRepository {
	return &RegistrationRequestRepository{pool: pool}
}

// FindByKey returns the id and the request hash stored with key.
func (r *RegistrationRequestRepository) FindByKey(ctx context.Context, key model.IdempotencyKey) (out.RegistrationRecord, bool, error) {
	var record out.RegistrationRecord
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT id::text, request_hash FROM auth.registration_request WHERE idempotency_key = $1`, key.String()).Scan(&record.ID, &record.RequestHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return out.RegistrationRecord{}, false, nil
	}
	if err != nil {
		return out.RegistrationRecord{}, false, err
	}
	return record, true, nil
}

// LockEmail takes a transaction-scoped advisory lock on the address, so the requests for one address are counted,
// superseded and stored one after the other. There may be no row to lock yet, which is why it is not a row lock.
func (r *RegistrationRequestRepository) LockEmail(ctx context.Context, email model.Email) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, email.String())
	return err
}

// CountRequestsSince counts the requests for the address created at or after since: pending, superseded, used and the
// ones that created nothing.
func (r *RegistrationRequestRepository) CountRequestsSince(ctx context.Context, email model.Email, since time.Time) (int, error) {
	var requested int
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT count(*) FROM auth.registration_request WHERE email = $1 AND created_at >= $2`, email.String(), since).Scan(&requested)
	return requested, err
}

// SupersedePending soft-deletes the pending request for the address, so only the last token is valid.
func (r *RegistrationRequestRepository) SupersedePending(ctx context.Context, email model.Email, at time.Time) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`UPDATE auth.registration_request SET deleted_at = $2, updated_at = $2
		 WHERE email = $1 AND token_hash IS NOT NULL AND used_at IS NULL AND deleted_at IS NULL`, email.String(), at)
	return err
}

// Add stores the record. created_at is the instant of the request, taken from the clock of the use case so the rolling
// count does not depend on the clock of the database. A key that is already stored is model.ErrIdempotencyKeyTaken, also
// when the other request is not committed yet: the insert waits for it and then fails.
func (r *RegistrationRequestRepository) Add(ctx context.Context, key model.IdempotencyKey, record out.RegistrationRecord, email model.Email, at time.Time) error {
	var passwordHash, name, phone, address, tokenHash *string
	var expiresAt *time.Time
	if pending := record.Request; pending != nil {
		hash, pendingName, pendingPhone, pendingAddress, token, expiry := pending.PasswordHash(), pending.Name().String(), pending.Phone().String(), pending.Address().String(), pending.TokenHash(), pending.ExpiresAt()
		passwordHash, name, phone, address, tokenHash, expiresAt = &hash, &pendingName, &pendingPhone, &pendingAddress, &token, &expiry
	}
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`INSERT INTO auth.registration_request
		   (id, idempotency_key, request_hash, email, password_hash, name, phone, address, token_hash, expires_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)`,
		record.ID, key.String(), record.RequestHash, email.String(), passwordHash, name, phone, address, tokenHash, expiresAt, at)
	if isUniqueViolationOf(err, registrationKeyUniqueIndex) {
		return model.ErrIdempotencyKeyTaken
	}
	return err
}

// LockByTokenHash locks and returns the request with that digest. A request that was superseded is gone for the caller.
func (r *RegistrationRequestRepository) LockByTokenHash(ctx context.Context, tokenHash string) (*model.RegistrationRequest, error) {
	var id, email, passwordHash, name, phone, address string
	var expiresAt time.Time
	var usedAt *time.Time
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT id::text, email, password_hash, name, COALESCE(phone, ''), COALESCE(address, ''), expires_at, used_at
		 FROM auth.registration_request WHERE token_hash = $1 AND deleted_at IS NULL FOR UPDATE`,
		tokenHash).Scan(&id, &email, &passwordHash, &name, &phone, &address, &expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrRegistrationRejected
	}
	if err != nil {
		return nil, err
	}
	return restoreRegistrationRequest(id, email, passwordHash, name, phone, address, tokenHash, expiresAt, usedAt)
}

func restoreRegistrationRequest(id, email, passwordHash, name, phone, address, tokenHash string, expiresAt time.Time, usedAt *time.Time) (*model.RegistrationRequest, error) {
	storedEmail, err := model.NewEmail(email)
	if err != nil {
		return nil, err
	}
	storedName, err := model.NewName(name)
	if err != nil {
		return nil, err
	}
	storedPhone, err := model.NewPhone(phone)
	if err != nil {
		return nil, err
	}
	storedAddress, err := model.NewAddress(address)
	if err != nil {
		return nil, err
	}
	return model.RestoreRegistrationRequest(id, storedEmail, passwordHash, storedName, storedPhone, storedAddress, tokenHash, expiresAt, usedAt), nil
}

// MarkUsed stores the consumption of the request.
func (r *RegistrationRequestRepository) MarkUsed(ctx context.Context, request *model.RegistrationRequest) error {
	_, err := executorFor(ctx, r.pool).Exec(ctx,
		`UPDATE auth.registration_request SET used_at = $2, updated_at = $2 WHERE id = $1`, request.ID(), request.UsedAt())
	return err
}
