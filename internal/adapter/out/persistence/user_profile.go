package persistence

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

var _ out.ProfileUpdater = (*UserRepository)(nil)

// UpdateProfile writes the fields that change carries in one UPDATE: a field that was not sent is NULL in the
// parameters and COALESCE keeps its stored value. An account that does not exist or was deleted is model.ErrUserNotFound.
func (r *UserRepository) UpdateProfile(ctx context.Context, userID string, change model.ProfileChange, at time.Time) error {
	tag, err := executorFor(ctx, r.pool).Exec(ctx,
		`UPDATE auth.app_user
		 SET name = COALESCE($2, name), phone = COALESCE($3, phone), address = COALESCE($4, address),
		     updated_at = $5, updated_by = $1
		 WHERE id = $1 AND deleted_at IS NULL`,
		userID, sentName(change), sentPhone(change), sentAddress(change), at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return model.ErrUserNotFound
	}
	return nil
}

func sentName(change model.ProfileChange) *string {
	if name, sent := change.Name(); sent {
		value := name.String()
		return &value
	}
	return nil
}

func sentPhone(change model.ProfileChange) *string {
	if phone, sent := change.Phone(); sent {
		value := phone.String()
		return &value
	}
	return nil
}

func sentAddress(change model.ProfileChange) *string {
	if address, sent := change.Address(); sent {
		value := address.String()
		return &value
	}
	return nil
}
