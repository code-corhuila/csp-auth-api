package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// accountFailures is an in-memory out.AccountLoginFailures.
type accountFailures struct {
	counts map[string]int
	err    error
}

func (a *accountFailures) Record(_ context.Context, subject string) (int, error) {
	if a.err != nil {
		return 0, a.err
	}
	a.counts[subject]++
	return a.counts[subject], nil
}

func newSlowdownFixture(t *testing.T) (*loginFixture, *accountFailures) {
	counter := &accountFailures{counts: map[string]int{}}
	policy, err := model.NewAccountFailurePolicy(20, time.Hour, time.Second)
	if err != nil {
		t.Fatalf("NewAccountFailurePolicy() error = %v", err)
	}
	f := newLimitedLoginFixture(t, newLoginAttempts())
	f.useCase.accountFailures, f.useCase.accountPolicy = counter, policy
	return f, counter
}

func failFrom(f *loginFixture, address, email string) error {
	_, err := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: email, Password: "Wrong1234", ClientIP: address})
	return err
}

func TestTheTwentyFirstFailedLoginOfOneEmailIsSlowedEvenFromAnotherAddress(t *testing.T) {
	f, _ := newSlowdownFixture(t)
	for i := range 20 {
		err := failFrom(f, addressNumber(i), "ana@example.com")
		var slowed *model.LoginSlowedError
		if errors.As(err, &slowed) {
			t.Fatalf("failure %d was slowed, the first 20 must not be", i+1)
		}
	}

	err := failFrom(f, addressNumber(20), "ana@example.com")

	var slowed *model.LoginSlowedError
	if !errors.As(err, &slowed) || slowed.Delay != time.Second {
		t.Fatalf("21st failure: error = %v, want a slow answer of 1s", err)
	}
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Errorf("the slowed answer must still be bad credentials, got %v", err)
	}
}

func TestTheAccountCounterNeverLocksTheAccountOrTheRightPassword(t *testing.T) {
	f, _ := newSlowdownFixture(t)
	for i := range 40 {
		_ = failFrom(f, addressNumber(i), "ana@example.com")
	}

	_, err := f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: rightPass, ClientIP: addressNumber(99)})

	if err != nil {
		t.Errorf("right password after 40 failures: error = %v, want a normal login: the account is slowed, never locked", err)
	}
}

func TestEveryWellFormedEmailIsCountedSoAnUnknownOneIsSlowedLikeAKnownOne(t *testing.T) {
	f, counter := newSlowdownFixture(t)
	f.users.user = nil

	for i := range 21 {
		_ = failFrom(f, addressNumber(i), "ghost@example.com")
	}

	err := failFrom(f, addressNumber(21), "ghost@example.com")
	var slowed *model.LoginSlowedError
	if !errors.As(err, &slowed) || len(counter.counts) != 1 {
		t.Errorf("error = %v, counters = %d, want the unknown email slowed too and counted under one subject", err, len(counter.counts))
	}
}

func TestAMalformedEmailCreatesNoAccountCounter(t *testing.T) {
	f, counter := newSlowdownFixture(t)

	for i := range 25 {
		_ = failFrom(f, addressNumber(i), "not-an-email")
	}

	if len(counter.counts) != 0 {
		t.Errorf("counters = %v, want none: only a well-formed email is a subject", counter.counts)
	}
}

func TestOnlyFailedCredentialsCountAgainstTheAccount(t *testing.T) {
	f, counter := newSlowdownFixture(t)
	f.users.user = storedUser(t, model.UserLocked, model.RoleClient)

	_, _ = f.useCase.Login(context.Background(), in.LoginUserCommand{Email: "ana@example.com", Password: rightPass, ClientIP: clientAddress})

	if len(counter.counts) != 0 {
		t.Errorf("counters = %v, want none for a locked account that gave the right password", counter.counts)
	}
}

func TestTheLoginGoesOnWhenTheAccountCounterCannotBeReached(t *testing.T) {
	f, counter := newSlowdownFixture(t)
	counter.err = errors.New("redis down")

	err := failFrom(f, clientAddress, "ana@example.com")

	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Errorf("error = %v, want plain bad credentials, not the store failure", err)
	}
	var slowed *model.LoginSlowedError
	if errors.As(err, &slowed) {
		t.Error("a store that fails must not slow anybody")
	}
}

func TestTheIPLockStillWorksWhileTheAccountIsSlowed(t *testing.T) {
	f, _ := newSlowdownFixture(t)
	for range 10 {
		_ = failFrom(f, clientAddress, "ana@example.com")
	}

	err := failFrom(f, clientAddress, "ana@example.com")

	var limited *model.LoginRateLimitedError
	if !errors.As(err, &limited) {
		t.Errorf("11th failure from one address: error = %v, want the rate limit of the address", err)
	}
}

func addressNumber(i int) string {
	return "198.51.100." + string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}
