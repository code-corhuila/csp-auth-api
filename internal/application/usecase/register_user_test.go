package usecase

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
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
	existsErr, saveErr error
}

func (r *fakeRepository) ExistsByEmail(_ context.Context, email model.Email) (bool, error) {
	return r.taken[email.String()], r.existsErr
}

func (r *fakeRepository) FindByEmail(context.Context, model.Email) (*model.User, error) {
	return nil, model.ErrUserNotFound
}

func (r *fakeRepository) Save(_ context.Context, user *model.User) error {
	r.journal.record("save")
	if r.saveErr != nil {
		return r.saveErr
	}
	r.saved = append(r.saved, user)
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

func (h *fakeHasher) Verify(string, string) bool { return false }

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

type fixture struct {
	useCase      *RegisterUser
	repository   *fakeRepository
	outbox       *fakeOutbox
	hasher       *fakeHasher
	transactions *fakeTransactions
	journal      *journal
}

func newFixture() *fixture {
	j := &journal{}
	f := &fixture{
		repository:   &fakeRepository{journal: j, taken: map[string]bool{}},
		outbox:       &fakeOutbox{journal: j},
		hasher:       &fakeHasher{},
		transactions: &fakeTransactions{journal: j},
		journal:      j,
	}
	f.useCase = NewRegisterUser(f.repository, f.outbox, f.hasher, &fakeIDs{next: []string{"user-1", "event-1"}}, fakeClock{}, f.transactions)
	return f
}

func validCommand() in.RegisterUserCommand {
	return in.RegisterUserCommand{
		Email: "Ana@Example.com", Password: "Secret123", Name: "Ana Pérez",
		Phone: "3001234567", Address: "Calle 123 #45-67",
	}
}

func TestRegisterCreatesAClientAndRecordsTheEventInOneTransaction(t *testing.T) {
	f := newFixture()

	result, err := f.useCase.Register(context.Background(), validCommand())

	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	want := in.RegisterUserResult{UserID: "user-1", Email: "ana@example.com", Name: "Ana Pérez", Roles: []string{"CLIENT"}}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result = %+v, want %+v", result, want)
	}
	if len(f.repository.saved) != 1 {
		t.Fatalf("saved users = %d, want 1", len(f.repository.saved))
	}
	user := f.repository.saved[0]
	if user.PasswordHash() != hashedPassword || !user.HasRole(model.RoleClient) || user.HasRole(model.RoleAdmin) {
		t.Errorf("saved user hash/roles = %q/%v, want the bcrypt hash and only CLIENT", user.PasswordHash(), user.Roles())
	}
	if user.Phone().String() != "3001234567" || user.Address().String() != "Calle 123 #45-67" {
		t.Errorf("saved contact data = %q/%q, want the submitted values", user.Phone(), user.Address())
	}
	if !reflect.DeepEqual(f.hasher.hashed, []string{"Secret123"}) {
		t.Errorf("hashed passwords = %v, want the submitted one", f.hasher.hashed)
	}
	wantSteps := []string{"begin", "save", "outbox", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	wantEvent := model.UserRegistered{EventID: "event-1", OccurredAt: registeredAt, UserID: "user-1", Email: "ana@example.com", Roles: []string{"CLIENT"}}
	if len(f.outbox.events) != 1 || !reflect.DeepEqual(f.outbox.events[0], wantEvent) {
		t.Errorf("events = %+v, want [%+v]", f.outbox.events, wantEvent)
	}
}

func TestRegisterRejectsInvalidInputWithoutTouchingAnything(t *testing.T) {
	cases := map[string]struct {
		change func(*in.RegisterUserCommand)
		want   error
	}{
		"invalid email": {func(c *in.RegisterUserCommand) { c.Email = "not-an-email" }, model.ErrInvalidEmail},
		"weak password": {func(c *in.RegisterUserCommand) { c.Password = "short" }, model.ErrWeakPassword},
		"empty name":    {func(c *in.RegisterUserCommand) { c.Name = " " }, model.ErrInvalidName},
		"invalid phone": {func(c *in.RegisterUserCommand) { c.Phone = "12" }, model.ErrInvalidPhone},
		"empty address": {func(c *in.RegisterUserCommand) { c.Address = "" }, model.ErrInvalidAddress},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			f := newFixture()
			command := validCommand()
			c.change(&command)

			if _, err := f.useCase.Register(context.Background(), command); !errors.Is(err, c.want) {
				t.Fatalf("Register() error = %v, want %v", err, c.want)
			}
			if len(f.journal.steps) != 0 || len(f.hasher.hashed) != 0 {
				t.Errorf("steps = %v, hashed = %v, want none", f.journal.steps, f.hasher.hashed)
			}
		})
	}
}

func TestRegisterRejectsADuplicateEmailAndCreatesNothing(t *testing.T) {
	f := newFixture()
	f.repository.taken["ana@example.com"] = true

	_, err := f.useCase.Register(context.Background(), validCommand())

	if !errors.Is(err, model.ErrEmailAlreadyRegistered) {
		t.Fatalf("Register() error = %v, want ErrEmailAlreadyRegistered", err)
	}
	if len(f.repository.saved) != 0 || len(f.outbox.events) != 0 || f.transactions.committed {
		t.Errorf("saved/events/committed = %d/%d/%v, want nothing", len(f.repository.saved), len(f.outbox.events), f.transactions.committed)
	}
}

func TestRegisterRollsBackWhenAnOutboundPortFails(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]struct {
		fail  func(*fixture)
		steps []string
	}{
		"hasher":    {func(f *fixture) { f.hasher.err = boom }, nil},
		"existence": {func(f *fixture) { f.repository.existsErr = boom }, []string{"begin", "rollback"}},
		"save":      {func(f *fixture) { f.repository.saveErr = boom }, []string{"begin", "save", "rollback"}},
		"outbox":    {func(f *fixture) { f.outbox.err = boom }, []string{"begin", "save", "outbox", "rollback"}},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			f := newFixture()
			c.fail(f)

			if _, err := f.useCase.Register(context.Background(), validCommand()); !errors.Is(err, boom) {
				t.Fatalf("Register() error = %v, want the port error", err)
			}
			if !reflect.DeepEqual(f.journal.steps, c.steps) || f.transactions.committed {
				t.Errorf("steps = %v committed = %v, want %v and no commit", f.journal.steps, f.transactions.committed, c.steps)
			}
		})
	}
}
