//go:build integration

package persistence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// fixedHasher gives every password the same bcrypt-shaped hash: these tests are about the race,
// not about bcrypt, whose cost would only slow them down.
type fixedHasher struct{}

func (fixedHasher) Hash(model.Password) (string, error) { return bcryptHash, nil }
func (fixedHasher) Verify(string, string) bool          { return false }

type fixedTokens struct{}

func (fixedTokens) IssueAccessToken(model.AccessClaims) (out.IssuedAccessToken, error) {
	return out.IssuedAccessToken{Value: "access", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (f fixture) registerUser() *usecase.RegisterUser {
	clock, ids := system.Clock{}, system.UUIDGenerator{}
	return usecase.NewRegisterUser(usecase.RegisterUserPorts{
		Users: f.users, Keys: NewIdempotencyKeyRepository(f.pool), Outbox: f.outbox, Hasher: fixedHasher{},
		IDs: ids, Clock: clock, Transactions: f.transactions, Tokens: fixedTokens{},
		Sessions: usecase.NewIssueRefreshToken(NewRefreshTokenRepository(f.pool), ids, clock, 7*24*time.Hour),
	})
}

func registrationCommand(t *testing.T, key, email string) in.RegisterUserCommand {
	t.Helper()
	return in.RegisterUserCommand{
		IdempotencyKey: key, Email: email, Password: "Secret123", Name: "Ana Perez",
		Phone: "+573001234567", Address: "Calle 1 # 2-3", UserAgent: "integration",
	}
}

type registration struct {
	result in.RegisterUserResult
	err    error
}

// registerConcurrently starts every command at once and returns the outcomes in the same order.
func registerConcurrently(useCase *usecase.RegisterUser, commands ...in.RegisterUserCommand) []registration {
	outcomes := make([]registration, len(commands))
	var start, done sync.WaitGroup
	start.Add(1)
	for i, command := range commands {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			outcomes[i].result, outcomes[i].err = useCase.Register(context.Background(), command)
		}()
	}
	start.Done()
	done.Wait()
	return outcomes
}

func countRows(t *testing.T, f fixture, query string, args ...any) int {
	t.Helper()
	var rows int
	if err := f.pool.QueryRow(context.Background(), query, args...).Scan(&rows); err != nil {
		t.Fatalf("%s error = %v", query, err)
	}
	return rows
}

func TestIdempotencyKeyIsStoredFoundAndNeverOverwritten(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	keys := NewIdempotencyKeyRepository(f.pool)
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	key, _ := model.NewIdempotencyKey("it-key-" + newUUID(t))

	if _, found, err := keys.Find(ctx, key); err != nil || found {
		t.Fatalf("Find() before Save = %v, %v, want not found", found, err)
	}
	record := out.IdempotencyRecord{UserID: user.ID(), RequestHash: "abc123"}
	if err := keys.Save(ctx, key, record); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, found, err := keys.Find(ctx, key)
	if err != nil || !found || got != record {
		t.Errorf("Find() = %+v, %v, %v, want %+v", got, found, err, record)
	}
	other := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, other); err != nil {
		t.Fatalf("register error = %v", err)
	}
	err = keys.Save(ctx, key, out.IdempotencyRecord{UserID: other.ID(), RequestHash: "other"})
	if !errors.Is(err, model.ErrIdempotencyKeyTaken) {
		t.Errorf("second Save() error = %v, want ErrIdempotencyKeyTaken", err)
	}
}

func TestFindByIDLoadsTheUserWithItsRoles(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}

	found, err := f.users.FindByID(ctx, user.ID())

	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != user.ID() || found.Email() != user.Email() || found.Name().String() != "Ana Perez" || !found.HasRole(model.RoleClient) || found.Status() != model.UserActive {
		t.Errorf("found = %q %q %q %v, want the stored user", found.ID(), found.Email(), found.Name(), found.Roles())
	}
	if _, err := f.users.FindByID(ctx, newUUID(t)); !errors.Is(err, model.ErrUserNotFound) {
		t.Errorf("FindByID(unknown) error = %v, want ErrUserNotFound", err)
	}
}

func TestRegisterThenRepeatReplaysWithoutTokensAndCreatesOneOfEverything(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	useCase := f.registerUser()
	command := registrationCommand(t, "it-key-"+newUUID(t), uniqueEmail(t))

	first, err := useCase.Register(ctx, command)
	if err != nil || first.Replayed || first.Session.AccessToken == "" || first.Session.RefreshToken == "" {
		t.Fatalf("first Register() = %+v, %v, want a new account with tokens", first, err)
	}
	command.Password = "Different456"
	second, err := useCase.Register(ctx, command)

	if err != nil || !second.Replayed {
		t.Fatalf("second Register() = %+v, %v, want a replay", second, err)
	}
	if second.Session.User.ID != first.Session.User.ID || second.Session.AccessToken != "" || second.Session.RefreshToken != "" {
		t.Errorf("replayed session = %+v, want the same account and no tokens", second.Session)
	}
	id := first.Session.User.ID
	if n := countRows(t, f, `SELECT count(*) FROM auth.app_user WHERE id = $1`, id); n != 1 {
		t.Errorf("users = %d, want 1", n)
	}
	if n := countRows(t, f, `SELECT count(*) FROM auth.idempotency_key WHERE user_id = $1`, id); n != 1 {
		t.Errorf("keys = %d, want 1", n)
	}
	if n := countRows(t, fixture{pool: openPool(t, readerURLVariable)}, `SELECT count(*) FROM auth.outbox_event WHERE aggregate_id = $1`, id); n != 1 {
		t.Errorf("outbox events = %d, want 1", n)
	}
	if n := countRows(t, f, `SELECT count(*) FROM auth.refresh_token WHERE user_id = $1`, id); n != 1 {
		t.Errorf("refresh tokens = %d, want 1: a replay issues none", n)
	}
	changed := registrationCommand(t, command.IdempotencyKey, command.Email)
	changed.Name = "Bea Gomez"
	if _, err := useCase.Register(ctx, changed); !errors.Is(err, model.ErrIdempotencyKeyConflict) {
		t.Errorf("same key, other name: error = %v, want ErrIdempotencyKeyConflict", err)
	}
	newKey := registrationCommand(t, "it-key-"+newUUID(t), command.Email)
	if _, err := useCase.Register(ctx, newKey); !errors.Is(err, model.ErrEmailAlreadyRegistered) {
		t.Errorf("new key, same email: error = %v, want ErrEmailAlreadyRegistered", err)
	}
}

func TestConcurrentRegistrationsWithTheSameKeyAndDataCreateOneAccountAndReplayTheOther(t *testing.T) {
	f := newFixture(t)
	useCase := f.registerUser()
	for round := range 10 {
		command := registrationCommand(t, "it-key-"+newUUID(t), uniqueEmail(t))

		outcomes := registerConcurrently(useCase, command, command)

		created, replayed := 0, 0
		for _, outcome := range outcomes {
			switch {
			case outcome.err != nil:
				t.Fatalf("round %d: unexpected error %v", round, outcome.err)
			case outcome.result.Replayed:
				replayed++
			default:
				created++
			}
		}
		if created != 1 || replayed != 1 || outcomes[0].result.Session.User.ID != outcomes[1].result.Session.User.ID {
			t.Fatalf("round %d: created=%d replayed=%d ids=%q/%q, want one of each for the same account",
				round, created, replayed, outcomes[0].result.Session.User.ID, outcomes[1].result.Session.User.ID)
		}
		if n := countRows(t, f, `SELECT count(*) FROM auth.app_user WHERE email = lower($1)`, command.Email); n != 1 {
			t.Fatalf("round %d: users with the email = %d, want 1", round, n)
		}
	}
}

func TestConcurrentRegistrationsWithTheSameKeyAndOtherDataConflict(t *testing.T) {
	f := newFixture(t)
	useCase := f.registerUser()
	cases := map[string]func(*in.RegisterUserCommand){
		"same email, other name": func(c *in.RegisterUserCommand) { c.Name = "Bea Gomez" },
		"other email":            func(c *in.RegisterUserCommand) { c.Email = uniqueEmail(t) },
	}
	for label, change := range cases {
		t.Run(label, func(t *testing.T) {
			first := registrationCommand(t, "it-key-"+newUUID(t), uniqueEmail(t))
			second := first
			change(&second)

			outcomes := registerConcurrently(useCase, first, second)

			created, conflicts := 0, 0
			for _, outcome := range outcomes {
				switch {
				case outcome.err == nil && !outcome.result.Replayed:
					created++
				case errors.Is(outcome.err, model.ErrIdempotencyKeyConflict):
					conflicts++
				default:
					t.Errorf("unexpected outcome %+v, %v", outcome.result, outcome.err)
				}
			}
			if created != 1 || conflicts != 1 {
				t.Errorf("created=%d conflicts=%d, want 1 and 1", created, conflicts)
			}
		})
	}
}

func TestConcurrentRegistrationsWithDifferentKeysAndTheSameEmailCreateOne(t *testing.T) {
	f := newFixture(t)
	useCase := f.registerUser()
	email := uniqueEmail(t)

	outcomes := registerConcurrently(useCase,
		registrationCommand(t, "it-key-"+newUUID(t), email),
		registrationCommand(t, "it-key-"+newUUID(t), email))

	created, duplicated := 0, 0
	for _, outcome := range outcomes {
		switch {
		case outcome.err == nil && !outcome.result.Replayed:
			created++
		case errors.Is(outcome.err, model.ErrEmailAlreadyRegistered):
			duplicated++
		default:
			t.Errorf("unexpected outcome %+v, %v", outcome.result, outcome.err)
		}
	}
	if created != 1 || duplicated != 1 {
		t.Errorf("created=%d duplicated=%d, want 1 and 1", created, duplicated)
	}
}
