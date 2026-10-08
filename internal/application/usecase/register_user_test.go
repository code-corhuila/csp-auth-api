package usecase

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
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

const idempotencyKey = "key-0001-register"

type fixture struct {
	useCase      *RegisterUser
	repository   *fakeRepository
	keys         *fakeKeys
	outbox       *fakeOutbox
	hasher       *fakeHasher
	transactions *fakeTransactions
	sessions     *loginSessions
	journal      *journal
}

func newFixture() *fixture {
	j := &journal{}
	f := &fixture{
		repository:   &fakeRepository{journal: j, taken: map[string]bool{}, byID: map[string]*model.User{}},
		keys:         &fakeKeys{journal: j, records: map[string]out.IdempotencyRecord{}},
		outbox:       &fakeOutbox{journal: j},
		hasher:       &fakeHasher{},
		transactions: &fakeTransactions{journal: j},
		sessions:     &loginSessions{},
		journal:      j,
	}
	f.useCase = NewRegisterUser(RegisterUserPorts{
		Users: f.repository, Keys: f.keys, Outbox: f.outbox, Hasher: f.hasher,
		IDs: &fakeIDs{next: []string{"user-1", "event-1"}}, Clock: fakeClock{}, Transactions: f.transactions,
		Tokens: loginTokens{}, Sessions: f.sessions,
	})
	return f
}

func validCommand() in.RegisterUserCommand {
	return in.RegisterUserCommand{
		IdempotencyKey: idempotencyKey, Email: "Ana@Example.com", Password: "Secret123", Name: "Ana Pérez",
		Phone: "3001234567", Address: "Calle 123 #45-67", UserAgent: "curl/8",
	}
}

// requestHashOf is the hash the use case must store for command.
func requestHashOf(t *testing.T, command in.RegisterUserCommand) string {
	t.Helper()
	email, err := model.NewEmail(command.Email)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := model.NewName(command.Name)
	phone, _ := model.NewPhone(command.Phone)
	address, _ := model.NewAddress(command.Address)
	return model.RegistrationRequestHash(email, name, phone, address)
}

// winnerRegisters plays a concurrent request that registers command under the key and commits first.
func (f *fixture) winnerRegisters(t *testing.T, command in.RegisterUserCommand) {
	t.Helper()
	f.keys.records[command.IdempotencyKey] = out.IdempotencyRecord{UserID: "user-1", RequestHash: requestHashOf(t, command)}
	f.repository.byID["user-1"] = storedUser(t, model.UserActive, model.RoleClient)
	f.repository.taken["ana@example.com"] = true
}

func TestRegisterCreatesAClientTheKeyAndTheEventInOneTransactionThenOpensTheSession(t *testing.T) {
	f := newFixture()

	result, err := f.useCase.Register(context.Background(), validCommand())

	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if result.Replayed {
		t.Error("Replayed = true for a new key")
	}
	session := result.Session
	if session.AccessToken != accessSecret || session.RefreshToken != "opaque-refresh" || session.ExpiresIn != 3600 {
		t.Errorf("tokens = %q %q %d, want the issued ones and 3600 seconds", session.AccessToken, session.RefreshToken, session.ExpiresIn)
	}
	if session.User.ID != "user-1" || session.User.Email != "ana@example.com" || session.User.Name != "Ana Pérez" ||
		!reflect.DeepEqual(session.User.Roles, []string{"CLIENT"}) || !contains(session.User.Permissions, "booking:create") {
		t.Errorf("user = %+v, want the new CLIENT without contact data", session.User)
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
	wantRecord := out.IdempotencyRecord{UserID: "user-1", RequestHash: requestHashOf(t, validCommand())}
	if got := f.keys.records[idempotencyKey]; got != wantRecord {
		t.Errorf("stored key = %+v, want %+v", got, wantRecord)
	}
	wantSteps := []string{"begin", "find-key", "save", "save-key", "outbox", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	wantEvent := model.UserRegistered{EventID: "event-1", OccurredAt: registeredAt, UserID: "user-1", Email: "ana@example.com", Roles: []string{"CLIENT"}}
	if len(f.outbox.events) != 1 || !reflect.DeepEqual(f.outbox.events[0], wantEvent) {
		t.Errorf("events = %+v, want [%+v]", f.outbox.events, wantEvent)
	}
	wantSession := in.IssueRefreshTokenCommand{UserID: "user-1", UserAgent: "curl/8"}
	if len(f.sessions.commands) != 1 || f.sessions.commands[0] != wantSession {
		t.Errorf("refresh token commands = %+v, want [%+v]", f.sessions.commands, wantSession)
	}
}

func TestRegisterBoundsTheUserAgentOfTheSession(t *testing.T) {
	f := newFixture()
	command := validCommand()
	command.UserAgent = strings.Repeat("é", 300)

	if _, err := f.useCase.Register(context.Background(), command); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if got := f.sessions.commands[0].UserAgent; got != strings.Repeat("é", 255) {
		t.Errorf("user agent has %d characters, want it cut to 255", len([]rune(got)))
	}
}

func TestRegisterRejectsInvalidInputWithoutTouchingAnything(t *testing.T) {
	cases := map[string]struct {
		change func(*in.RegisterUserCommand)
		want   error
	}{
		"short key":     {func(c *in.RegisterUserCommand) { c.IdempotencyKey = "short" }, model.ErrInvalidIdempotencyKey},
		"long key":      {func(c *in.RegisterUserCommand) { c.IdempotencyKey = strings.Repeat("k", 129) }, model.ErrInvalidIdempotencyKey},
		"missing key":   {func(c *in.RegisterUserCommand) { c.IdempotencyKey = "" }, model.ErrInvalidIdempotencyKey},
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
			if len(f.journal.steps) != 0 || len(f.hasher.hashed) != 0 || len(f.sessions.commands) != 0 {
				t.Errorf("steps = %v, hashed = %v, sessions = %v, want none", f.journal.steps, f.hasher.hashed, f.sessions.commands)
			}
		})
	}
}

func TestRegisterReplaysTheSameRequestWithoutCreatingAnythingOrTokens(t *testing.T) {
	f := newFixture()
	f.winnerRegisters(t, validCommand())

	result, err := f.useCase.Register(context.Background(), validCommand())

	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Replayed {
		t.Error("Replayed = false for a repeated key")
	}
	if result.Session.AccessToken != "" || result.Session.RefreshToken != "" || result.Session.ExpiresIn != 0 || len(f.sessions.commands) != 0 {
		t.Errorf("session = %+v, sessions = %v, want no tokens", result.Session, f.sessions.commands)
	}
	if result.Session.User.ID != "user-1" || result.Session.User.Email != "ana@example.com" || !contains(result.Session.User.Permissions, "booking:create") {
		t.Errorf("user = %+v, want the account of the first request", result.Session.User)
	}
	if len(f.repository.saved) != 0 || len(f.outbox.events) != 0 {
		t.Errorf("saved/events = %d/%d, want nothing", len(f.repository.saved), len(f.outbox.events))
	}
	wantSteps := []string{"begin", "find-key", "find-user", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v: the key is checked before the email", f.journal.steps, wantSteps)
	}
}

func TestRegisterReplayIgnoresThePasswordAndTheEmailCase(t *testing.T) {
	f := newFixture()
	f.winnerRegisters(t, validCommand())
	retry := validCommand()
	retry.Password = "Another456"
	retry.Email = "  ANA@example.com "

	result, err := f.useCase.Register(context.Background(), retry)

	if err != nil || !result.Replayed {
		t.Errorf("Register() = %+v, %v, want a replay", result, err)
	}
}

func TestRegisterRejectsTheSameKeyWithADifferentRequest(t *testing.T) {
	for label, change := range map[string]func(*in.RegisterUserCommand){
		"email":   func(c *in.RegisterUserCommand) { c.Email = "bea@example.com" },
		"name":    func(c *in.RegisterUserCommand) { c.Name = "Bea" },
		"phone":   func(c *in.RegisterUserCommand) { c.Phone = "3009999999" },
		"address": func(c *in.RegisterUserCommand) { c.Address = "Carrera 9" },
	} {
		t.Run(label, func(t *testing.T) {
			f := newFixture()
			f.winnerRegisters(t, validCommand())
			command := validCommand()
			change(&command)

			_, err := f.useCase.Register(context.Background(), command)

			if !errors.Is(err, model.ErrIdempotencyKeyConflict) {
				t.Fatalf("Register() error = %v, want ErrIdempotencyKeyConflict", err)
			}
			if len(f.repository.saved) != 0 || len(f.outbox.events) != 0 || f.transactions.committed || len(f.sessions.commands) != 0 {
				t.Errorf("something was created: saved=%d events=%d committed=%v", len(f.repository.saved), len(f.outbox.events), f.transactions.committed)
			}
		})
	}
}

func TestRegisterRejectsADuplicateEmailWithANewKeyAndCreatesNothing(t *testing.T) {
	f := newFixture()
	f.repository.taken["ana@example.com"] = true

	_, err := f.useCase.Register(context.Background(), validCommand())

	if !errors.Is(err, model.ErrEmailAlreadyRegistered) {
		t.Fatalf("Register() error = %v, want ErrEmailAlreadyRegistered", err)
	}
	if len(f.repository.saved) != 0 || len(f.outbox.events) != 0 || len(f.keys.records) != 0 || f.transactions.committed || len(f.sessions.commands) != 0 {
		t.Errorf("something was created: saved=%d events=%d keys=%d", len(f.repository.saved), len(f.outbox.events), len(f.keys.records))
	}
	wantSteps := []string{"begin", "find-key", "rollback", "begin", "find-key", "rollback"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v: one retry, in a new transaction", f.journal.steps, wantSteps)
	}
}

func TestRegisterAnswersAsAReplayWhenAConcurrentRequestWinsTheKey(t *testing.T) {
	f := newFixture()
	f.keys.beforeSave = func() { f.winnerRegisters(t, validCommand()); f.keys.beforeSave = nil }

	result, err := f.useCase.Register(context.Background(), validCommand())

	if err != nil || !result.Replayed || result.Session.User.ID != "user-1" {
		t.Fatalf("Register() = %+v, %v, want a replay of the winner's account", result, err)
	}
	wantSteps := []string{"begin", "find-key", "save", "save-key", "rollback", "begin", "find-key", "find-user", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	if len(f.outbox.events) != 0 || len(f.sessions.commands) != 0 {
		t.Errorf("events/sessions = %d/%d, want none: the loser creates nothing", len(f.outbox.events), len(f.sessions.commands))
	}
}

func TestRegisterAnswersAsAReplayWhenAConcurrentRequestWinsTheEmail(t *testing.T) {
	f := newFixture()
	f.repository.afterSave = func() error {
		f.winnerRegisters(t, validCommand())
		return model.ErrEmailAlreadyRegistered
	}

	result, err := f.useCase.Register(context.Background(), validCommand())

	if err != nil || !result.Replayed {
		t.Fatalf("Register() = %+v, %v, want a replay", result, err)
	}
}

func TestRegisterReportsAConflictWhenAConcurrentRequestWinsTheKeyWithOtherData(t *testing.T) {
	f := newFixture()
	other := validCommand()
	other.Name = "Bea"
	f.repository.afterSave = func() error {
		f.winnerRegisters(t, other)
		return model.ErrEmailAlreadyRegistered
	}

	_, err := f.useCase.Register(context.Background(), validCommand())

	if !errors.Is(err, model.ErrIdempotencyKeyConflict) {
		t.Errorf("Register() error = %v, want ErrIdempotencyKeyConflict", err)
	}
}

func TestRegisterRetriesOnlyOnce(t *testing.T) {
	f := newFixture()
	f.keys.saveErr = model.ErrIdempotencyKeyTaken

	_, err := f.useCase.Register(context.Background(), validCommand())

	if !errors.Is(err, model.ErrIdempotencyKeyTaken) {
		t.Fatalf("Register() error = %v, want the second failure returned", err)
	}
	begins := 0
	for _, step := range f.journal.steps {
		if step == "begin" {
			begins++
		}
	}
	if begins != 2 {
		t.Errorf("transactions = %d, want 2 (the attempt and one retry)", begins)
	}
}

func TestRegisterRollsBackWhenAnOutboundPortFails(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]struct {
		fail  func(*fixture)
		steps []string
	}{
		"hasher":    {func(f *fixture) { f.hasher.err = boom }, nil},
		"key find":  {func(f *fixture) { f.keys.findErr = boom }, []string{"begin", "find-key", "rollback"}},
		"existence": {func(f *fixture) { f.repository.existsErr = boom }, []string{"begin", "find-key", "rollback"}},
		"save":      {func(f *fixture) { f.repository.saveErr = boom }, []string{"begin", "find-key", "save", "rollback"}},
		"key save":  {func(f *fixture) { f.keys.saveErr = boom }, []string{"begin", "find-key", "save", "save-key", "rollback"}},
		"outbox":    {func(f *fixture) { f.outbox.err = boom }, []string{"begin", "find-key", "save", "save-key", "outbox", "rollback"}},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			f := newFixture()
			c.fail(f)

			if _, err := f.useCase.Register(context.Background(), validCommand()); !errors.Is(err, boom) {
				t.Fatalf("Register() error = %v, want the port error", err)
			}
			if !reflect.DeepEqual(f.journal.steps, c.steps) || f.transactions.committed || len(f.sessions.commands) != 0 {
				t.Errorf("steps = %v committed = %v, want %v, no commit and no session", f.journal.steps, f.transactions.committed, c.steps)
			}
		})
	}
}

func TestRegisterSurfacesSessionFailuresAfterTheCommit(t *testing.T) {
	boom := errors.New("boom")
	f := newFixture()
	f.sessions.err = boom

	_, err := f.useCase.Register(context.Background(), validCommand())

	if !errors.Is(err, boom) || !f.transactions.committed {
		t.Errorf("error = %v committed = %v, want the failure after the commit", err, f.transactions.committed)
	}
}

func TestRegisterSurfacesAMissingAccountOfAReplayedKey(t *testing.T) {
	f := newFixture()
	f.keys.records[idempotencyKey] = out.IdempotencyRecord{UserID: "ghost", RequestHash: requestHashOf(t, validCommand())}

	_, err := f.useCase.Register(context.Background(), validCommand())

	if !errors.Is(err, model.ErrUserNotFound) {
		t.Errorf("Register() error = %v, want ErrUserNotFound", err)
	}
}
