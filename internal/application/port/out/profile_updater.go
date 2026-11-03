package out

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// ProfileUpdater writes the personal data of an account, in the transaction carried by the context.
type ProfileUpdater interface {
	// UpdateProfile stores, in one write, the fields that change carries for the active account userID and leaves the
	// others as they are. An account that does not exist or was deleted is model.ErrUserNotFound.
	UpdateProfile(ctx context.Context, userID string, change model.ProfileChange, at time.Time) error
}
