package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// FindByEmail loads the active account that uses email, with its active roles. Emails are stored
// lowercase (model.Email), so the comparison is exact. An unknown email is model.ErrUserNotFound.
func (r *UserRepository) FindByEmail(ctx context.Context, email model.Email) (*model.User, error) {
	db := executorFor(ctx, r.pool)
	var id, name, hash, status string
	var phone, address *string
	err := db.QueryRow(ctx,
		`SELECT id::text, name, password_hash, status, phone, address
		 FROM auth.app_user WHERE email = $1 AND deleted_at IS NULL`,
		email.String()).Scan(&id, &name, &hash, &status, &phone, &address)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	roles, err := loadRoles(ctx, db, id)
	if err != nil {
		return nil, err
	}
	return restoreUser(id, name, email, hash, status, phone, address, roles)
}

func loadRoles(ctx context.Context, db executor, userID string) ([]model.Role, error) {
	rows, err := db.Query(ctx,
		`SELECT r.name FROM auth.user_role ur
		 JOIN auth.role r ON r.id = ur.role_id AND r.deleted_at IS NULL
		 WHERE ur.user_id = $1 AND ur.deleted_at IS NULL
		 ORDER BY r.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []model.Role
	for rows.Next() {
		var stored string
		if err := rows.Scan(&stored); err != nil {
			return nil, err
		}
		role, err := model.ParseRole(stored)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// restoreUser maps a row to the aggregate. Contact data is optional in storage (ADR-024), so a
// NULL becomes the zero value instead of failing the load.
func restoreUser(id, name string, email model.Email, hash, status string, phone, address *string, roles []model.Role) (*model.User, error) {
	storedName, err := model.NewName(name)
	if err != nil {
		return nil, err
	}
	var storedPhone model.Phone
	if phone != nil {
		if storedPhone, err = model.NewPhone(*phone); err != nil {
			return nil, err
		}
	}
	var storedAddress model.Address
	if address != nil {
		if storedAddress, err = model.NewAddress(*address); err != nil {
			return nil, err
		}
	}
	return model.RestoreUser(id, storedName, email, hash, storedPhone, storedAddress, roles, model.UserStatus(status))
}

// FindByID loads the active account with that id, with its active roles. An unknown id is
// model.ErrUserNotFound.
func (r *UserRepository) FindByID(ctx context.Context, id string) (*model.User, error) {
	db := executorFor(ctx, r.pool)
	var storedEmail, name, hash, status string
	var phone, address *string
	err := db.QueryRow(ctx,
		`SELECT email, name, password_hash, status, phone, address
		 FROM auth.app_user WHERE id = $1 AND deleted_at IS NULL`,
		id).Scan(&storedEmail, &name, &hash, &status, &phone, &address)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	email, err := model.NewEmail(storedEmail)
	if err != nil {
		return nil, err
	}
	roles, err := loadRoles(ctx, db, id)
	if err != nil {
		return nil, err
	}
	return restoreUser(id, name, email, hash, status, phone, address, roles)
}
