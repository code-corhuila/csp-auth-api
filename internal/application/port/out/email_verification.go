package out

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// EmailVerificationRepository stores the requests to change an email (pattern Repository).
// Implementations take part in the transaction carried by the context.
type EmailVerificationRepository interface {
	// LockRequestsOf serializes the requests of a user until the transaction ends, so two
	// concurrent requests are counted and superseded one after the other.
	LockRequestsOf(ctx context.Context, userID string) error
	// RequestTimesSince returns the instants of the requests of the user made at or after since,
	// superseded ones included, oldest first.
	RequestTimesSince(ctx context.Context, userID string, since time.Time) ([]time.Time, error)
	// SupersedePending soft-deletes the pending request of the user, if any, at at.
	SupersedePending(ctx context.Context, userID string, at time.Time) error
	// Add stores a new pending request.
	Add(ctx context.Context, request *model.EmailChangeRequest) error
	// FindPendingForUpdate locks and returns the pending request of the user, or model.ErrEmailChangeNotFound.
	FindPendingForUpdate(ctx context.Context, userID string) (*model.EmailChangeRequest, error)
	// RecordWrongAttempt stores the attempts of request and soft-deletes it at at once it is exhausted.
	RecordWrongAttempt(ctx context.Context, request *model.EmailChangeRequest, at time.Time) error
	// Invalidate soft-deletes the pending request at at.
	Invalidate(ctx context.Context, request *model.EmailChangeRequest, at time.Time) error
	// ConfirmEmailChange sets the new email of the account, marks it verified and consumes the
	// request at at. When another account uses the address it returns model.ErrEmailAlreadyRegistered
	// and leaves the transaction usable.
	ConfirmEmailChange(ctx context.Context, request *model.EmailChangeRequest, at time.Time) error
}

// VerificationCodeGenerator draws verification codes uniformly at random.
type VerificationCodeGenerator interface {
	NewCode() (model.VerificationCode, error)
}

// VerificationCodeDelivery is what a VerificationCodeSender needs to get the code to the new address.
type VerificationCodeDelivery struct {
	RequestID string
	UserID    string
	NewEmail  model.Email
	Code      model.VerificationCode
	ExpiresAt time.Time
}

// VerificationCodeSender hands the code to whatever delivers it (pattern Strategy: the composition
// root picks the adapter, ADR-034). It is called inside the transaction of the request, so an
// adapter that writes to the database joins it and a failure undoes the request.
type VerificationCodeSender interface {
	Send(ctx context.Context, delivery VerificationCodeDelivery) error
}

// UserEmailChangedOutbox records UserEmailChanged in the auth outbox, in the transaction carried by
// the context (pattern Transactional Outbox, Norma 5.3.11).
type UserEmailChangedOutbox interface {
	AppendEmailChanged(ctx context.Context, event model.UserEmailChanged) error
}
