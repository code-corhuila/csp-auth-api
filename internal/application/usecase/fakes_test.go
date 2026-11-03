package usecase

import (
	"context"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const hashedPassword = "$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

var registeredAt = time.Date(2026, 9, 6, 19, 0, 0, 0, time.UTC)

// journal records the order of the side effects so tests can assert them.
type journal struct{ steps []string }

func (j *journal) record(step string) { j.steps = append(j.steps, step) }

type fakeRepository struct {
	journal            *journal
	taken              map[string]bool
	saved              []*model.User
	byID               map[string]*model.User
	existsErr, saveErr error
	// afterSave replaces the outcome of Save, to play a concurrent request that commits first.
	afterSave func() error
}

func (r *fakeRepository) ExistsByEmail(_ context.Context, email model.Email) (bool, error) {
	return r.taken[email.String()], r.existsErr
}

func (r *fakeRepository) FindByEmail(context.Context, model.Email) (*model.User, error) {
	return nil, model.ErrUserNotFound
}

func (r *fakeRepository) FindByID(_ context.Context, id string) (*model.User, error) {
	r.journal.record("find-user")
	if user, ok := r.byID[id]; ok {
		return user, nil
	}
	return nil, model.ErrUserNotFound
}

func (r *fakeRepository) Save(_ context.Context, user *model.User) error {
	r.journal.record("save")
	if r.afterSave != nil {
		return r.afterSave()
	}
	if r.saveErr != nil {
		return r.saveErr
	}
	r.saved = append(r.saved, user)
	return nil
}

type fakeKeys struct {
	journal *journal
	records map[string]out.IdempotencyRecord
	findErr error
	saveErr error
	// beforeSave runs when Save is called, to play a concurrent request that commits first.
	beforeSave func()
}

func (k *fakeKeys) Find(_ context.Context, key model.IdempotencyKey) (out.IdempotencyRecord, bool, error) {
	k.journal.record("find-key")
	record, ok := k.records[key.String()]
	return record, ok, k.findErr
}

func (k *fakeKeys) Save(_ context.Context, key model.IdempotencyKey, record out.IdempotencyRecord) error {
	k.journal.record("save-key")
	if k.beforeSave != nil {
		k.beforeSave()
	}
	if k.saveErr != nil {
		return k.saveErr
	}
	if _, exists := k.records[key.String()]; exists {
		return model.ErrIdempotencyKeyTaken
	}
	k.records[key.String()] = record
	return nil
}

type fakeOutbox struct {
	journal *journal
	events  []model.UserRegistered
	err     error
}

func (o *fakeOutbox) Append(_ context.Context, event model.UserRegistered) error {
	o.journal.record("outbox")
	if o.err != nil {
		return o.err
	}
	o.events = append(o.events, event)
	return nil
}

type fakeHasher struct {
	hashed []string
	err    error
}

func (h *fakeHasher) Hash(password model.Password) (string, error) {
	h.hashed = append(h.hashed, password.Reveal())
	return hashedPassword, h.err
}

func (h *fakeHasher) Verify(string, string) (bool, error) { return false, nil }

type fakeIDs struct{ next []string }

func (g *fakeIDs) NewID() string {
	id := g.next[0]
	g.next = g.next[1:]
	return id
}

type fakeClock struct{}

func (fakeClock) Now() time.Time { return registeredAt }

type fakeTransactions struct {
	journal   *journal
	committed bool
}

func (m *fakeTransactions) WithinTransaction(ctx context.Context, work func(context.Context) error) error {
	m.journal.record("begin")
	if err := work(ctx); err != nil {
		m.journal.record("rollback")
		return err
	}
	m.journal.record("commit")
	m.committed = true
	return nil
}
