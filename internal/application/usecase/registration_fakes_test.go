package usecase

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const idempotencyKey = "key-0001-register"

type fakeRegistrations struct {
	journal   *journal
	byKey     map[string]out.RegistrationRecord
	byToken   map[string]*model.RegistrationRequest
	added     []out.RegistrationRecord
	requested int
	counted   time.Time
	used      []*model.RegistrationRequest
	superseds int
	failAt    map[string]error
}

func newFakeRegistrations(j *journal) *fakeRegistrations {
	return &fakeRegistrations{journal: j, byKey: map[string]out.RegistrationRecord{}, byToken: map[string]*model.RegistrationRequest{}, failAt: map[string]error{}}
}

func (r *fakeRegistrations) step(name string) error {
	r.journal.record(name)
	return r.failAt[name]
}

func (r *fakeRegistrations) FindByKey(_ context.Context, key model.IdempotencyKey) (out.RegistrationRecord, bool, error) {
	record, ok := r.byKey[key.String()]
	return record, ok, r.step("find-key")
}

func (r *fakeRegistrations) LockEmail(context.Context, model.Email) error {
	return r.step("lock-email")
}

func (r *fakeRegistrations) CountRequestsSince(_ context.Context, _ model.Email, since time.Time) (int, error) {
	r.counted = since
	return r.requested, r.step("count")
}

func (r *fakeRegistrations) SupersedePending(context.Context, model.Email, time.Time) error {
	r.superseds++
	return r.step("supersede")
}

func (r *fakeRegistrations) Add(_ context.Context, key model.IdempotencyKey, record out.RegistrationRecord, _ model.Email, _ time.Time) error {
	if err := r.step("add"); err != nil {
		return err
	}
	if _, exists := r.byKey[key.String()]; exists {
		return model.ErrIdempotencyKeyTaken
	}
	r.byKey[key.String()] = record
	r.added = append(r.added, record)
	return nil
}

func (r *fakeRegistrations) LockByTokenHash(_ context.Context, hash string) (*model.RegistrationRequest, error) {
	if err := r.step("lock-token"); err != nil {
		return nil, err
	}
	if r, ok := r.byToken[hash]; ok {
		// A copy, as a database read gives: a rolled back redemption leaves the stored request as it was.
		return model.RestoreRegistrationRequest(r.ID(), r.Email(), r.PasswordHash(), r.Name(), r.Phone(), r.Address(), r.TokenHash(), r.ExpiresAt(), r.UsedAt()), nil
	}
	return nil, model.ErrRegistrationRejected
}

func (r *fakeRegistrations) MarkUsed(_ context.Context, request *model.RegistrationRequest) error {
	r.used = append(r.used, request)
	return r.step("mark-used")
}

type sentRegistrationMessage struct {
	kind  string
	email string
	token string
}

type fakeRegistrationSender struct {
	journal *journal
	sent    []sentRegistrationMessage
	err     error
}

func (s *fakeRegistrationSender) SendConfirmation(_ context.Context, confirmation out.RegistrationConfirmation) error {
	s.journal.record("send")
	s.sent = append(s.sent, sentRegistrationMessage{"confirmation", confirmation.Email.String(), confirmation.Token.Reveal()})
	return s.err
}

func (s *fakeRegistrationSender) SendAccountNotice(_ context.Context, email model.Email) error {
	s.journal.record("send")
	s.sent = append(s.sent, sentRegistrationMessage{"notice", email.String(), ""})
	return s.err
}
