package model

import (
	"errors"
	"testing"
	"time"
)

func TestAccountFailurePolicySlowsOnlyAfterTheConfiguredFailures(t *testing.T) {
	policy, err := NewAccountFailurePolicy(20, time.Hour, time.Second)
	if err != nil {
		t.Fatalf("NewAccountFailurePolicy() error = %v", err)
	}

	for failures, want := range map[int]bool{1: false, 20: false, 21: true, 500: true} {
		if got := policy.Slows(failures); got != want {
			t.Errorf("Slows(%d) = %v, want %v", failures, got, want)
		}
	}
}

func TestAccountFailurePolicyNeedsPositiveValues(t *testing.T) {
	for name, values := range map[string][3]any{
		"no failures": {0, time.Hour, time.Second},
		"no window":   {20, time.Duration(0), time.Second},
		"no delay":    {20, time.Hour, time.Duration(0)},
	} {
		_, err := NewAccountFailurePolicy(values[0].(int), values[1].(time.Duration), values[2].(time.Duration))
		if !errors.Is(err, ErrInvalidLoginPolicy) {
			t.Errorf("%s: error = %v, want ErrInvalidLoginPolicy", name, err)
		}
	}
}

func TestTheAccountSubjectIsTheSameForTheSameEmailAndNeverTheEmailItself(t *testing.T) {
	ana, _ := NewEmail("ana@example.com")
	again, _ := NewEmail("  ANA@example.com ")
	other, _ := NewEmail("luis@example.com")

	if AccountSubject(ana) != AccountSubject(again) || AccountSubject(ana) == AccountSubject(other) {
		t.Error("the subject must be equal for the same normalized email and different for another one")
	}
	if subject := AccountSubject(ana); len(subject) != 64 || subject == ana.String() {
		t.Errorf("subject = %q, want the 64 hex characters of a SHA-256 and not the email", subject)
	}
}

func TestALoginSlowedErrorIsStillABadCredentialsError(t *testing.T) {
	err := error(&LoginSlowedError{Delay: time.Second})

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Error("errors.Is(err, ErrInvalidCredentials) = false: the answer must stay a 401 for every caller")
	}
}
