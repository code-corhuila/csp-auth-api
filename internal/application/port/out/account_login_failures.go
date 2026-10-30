package out

import (
	"context"
	"errors"
)

// ErrAccountLoginFailuresPaused is what an AccountLoginFailures answers while it is paused after a failure of its store
// (ADR-048): it is not called, it answers at once, and the use case goes on without logging it again.
var ErrAccountLoginFailuresPaused = errors.New("the account login failure counter is paused after a failure of its store")

// AccountLoginFailures counts the failed logins of one account, from any address (HU-AUTH-005, STRIDE S). The subject is
// model.AccountSubject. It only counts: it never locks, and an error means the store cannot be reached, in which case the use
// case answers as if the account were not slowed.
type AccountLoginFailures interface {
	// Record counts one failed login of the subject and returns how many it has inside the window of the policy.
	Record(ctx context.Context, subject string) (int, error)
}
