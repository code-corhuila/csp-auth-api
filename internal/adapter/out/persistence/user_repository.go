package persistence

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	uniqueViolation = "23505"
	emailIndex      = "uk_app_user_email"
)

// UserRepository implements out.UserRepository over auth.app_user and auth.user_role.
type UserRepository struct {
	pool         *pgxpool.Pool
	transactions *TransactionManager
}

var _ out.UserRepository = (*UserRepository)(nil)

// NewUserRepository creates a repository over pool.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool, transactions: NewTransactionManager(pool)}
}

// ExistsByEmail reports whether an active account uses email. Emails are stored lowercase
// (model.Email), so the comparison is exact.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email model.Email) (bool, error) {
	var exists bool
	err := executorFor(ctx, r.pool).QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM auth.app_user WHERE email = $1 AND deleted_at IS NULL)`,
		email.String()).Scan(&exists)
	return exists, err
}

// Save inserts the user and its roles together. A duplicate email is reported as
// model.ErrEmailAlreadyRegistered, which also covers the race that ExistsByEmail cannot see.
func (r *UserRepository) Save(ctx context.Context, user *model.User) error {
	return r.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		db := executorFor(ctx, r.pool)
		_, err := db.Exec(ctx,
			`INSERT INTO auth.app_user (id, email, name, password_hash, status, phone, address)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			user.ID(), user.Email().String(), user.Name().String(), user.PasswordHash(),
			string(user.Status()), user.Phone().String(), user.Address().String())
		if isDuplicateEmail(err) {
			return model.ErrEmailAlreadyRegistered
		}
		if err != nil {
			return err
		}
		return insertRoles(ctx, db, user)
	})
}

// insertRoles links the user to its roles, resolving each role id by name: the ids are seeded
// UUIDs and the domain only knows names.
func insertRoles(ctx context.Context, db executor, user *model.User) error {
	names := make([]string, 0, len(user.Roles()))
	for _, role := range user.Roles() {
		names = append(names, role.String())
	}
	tag, err := db.Exec(ctx,
		`INSERT INTO auth.user_role (user_id, role_id)
		 SELECT $1, id FROM auth.role WHERE name = ANY($2) AND deleted_at IS NULL`,
		user.ID(), names)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(names)) {
		return fmt.Errorf("roles %v: only %d found in auth.role", names, tag.RowsAffected())
	}
	return nil
}

func isDuplicateEmail(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == emailIndex
}
