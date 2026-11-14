//go:build integration

package persistence

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// registrationMail keeps what the use case hands to the sender, so a test can read the token of a confirmation link.
type registrationMail struct {
	mu            sync.Mutex
	confirmations []out.RegistrationConfirmation
	notices       []model.Email
}

func (m *registrationMail) SendConfirmation(_ context.Context, confirmation out.RegistrationConfirmation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.confirmations = append(m.confirmations, confirmation)
	return nil
}

func (m *registrationMail) SendAccountNotice(_ context.Context, email model.Email) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notices = append(m.notices, email)
	return nil
}

func (m *registrationMail) lastToken(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.confirmations) == 0 {
		t.Fatal("no confirmation was sent")
	}
	return m.confirmations[len(m.confirmations)-1].Token.Reveal()
}

func (f fixture) registration() (*usecase.RequestRegistration, *usecase.ConfirmRegistration, *registrationMail) {
	clock, ids, mail := system.Clock{}, system.UUIDGenerator{}, &registrationMail{}
	registrations := NewRegistrationRequestRepository(f.pool)
	request := usecase.NewRequestRegistration(usecase.RequestRegistrationPorts{
		Users: f.users, Registrations: registrations, Hasher: fixedHasher{}, Tokens: system.ResetTokenGenerator{}, Sender: mail,
		IDs: ids, Clock: clock, Transactions: f.transactions,
	})
	confirm := usecase.NewConfirmRegistration(usecase.ConfirmRegistrationPorts{
		Users: f.users, Registrations: registrations, Keys: NewIdempotencyKeyRepository(f.pool), Outbox: f.outbox,
		IDs: ids, Clock: clock, Transactions: f.transactions, Tokens: fixedTokens{},
		Sessions: usecase.NewIssueRefreshToken(NewRefreshTokenRepository(f.pool), ids, clock, 7*24*time.Hour),
	})
	return request, confirm, mail
}

func requestCommand(key, email string) in.RequestRegistrationCommand {
	return in.RequestRegistrationCommand{
		IdempotencyKey: key, Email: email, Password: "Secret123", Name: "Ana Perez", Phone: "+573001234567", Address: "Calle 1 # 2-3",
	}
}

func newKey(t *testing.T) string { return "it-key-" + newUUID(t) }

func TestARequestForAFreeAddressStoresOnePendingRegistrationAndTheNextSupersedesIt(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	request, confirm, mail := f.registration()
	email := uniqueEmail(t)

	first, err := request.Request(ctx, requestCommand(newKey(t), email))
	if err != nil || first.Replayed || first.RequestID == "" {
		t.Fatalf("first Request() = %+v, %v, want a new request", first, err)
	}
	staleToken := mail.lastToken(t)
	if _, err := request.Request(ctx, requestCommand(newKey(t), email)); err != nil {
		t.Fatalf("second Request() error = %v", err)
	}

	if n := countRows(t, f, `SELECT count(*) FROM auth.registration_request WHERE email = lower($1)`, email); n != 2 {
		t.Errorf("requests = %d, want 2", n)
	}
	if n := countRows(t, f, `SELECT count(*) FROM auth.registration_request WHERE email = lower($1) AND token_hash IS NOT NULL AND used_at IS NULL AND deleted_at IS NULL`, email); n != 1 {
		t.Errorf("pending = %d, want 1: the second request supersedes the first", n)
	}
	if n := countRows(t, f, `SELECT count(*) FROM auth.app_user WHERE email = lower($1)`, email); n != 0 {
		t.Errorf("accounts = %d, want none before the confirmation", n)
	}
	if _, err := confirm.Confirm(ctx, in.ConfirmRegistrationCommand{IdempotencyKey: newKey(t), Token: staleToken}); !errors.Is(err, model.ErrRegistrationRejected) {
		t.Errorf("Confirm(superseded token) error = %v, want ErrRegistrationRejected", err)
	}
	created, err := confirm.Confirm(ctx, in.ConfirmRegistrationCommand{IdempotencyKey: newKey(t), Token: mail.lastToken(t), UserAgent: "integration"})
	if err != nil || created.Replayed || created.Session.User.Email != strings.ToLower(email) {
		t.Fatalf("Confirm() = %+v, %v, want the new account", created, err)
	}
	if n := countRows(t, f, `SELECT count(*) FROM auth.app_user WHERE email = lower($1)`, email); n != 1 {
		t.Errorf("accounts = %d, want 1", n)
	}
}

func TestARequestForAnAddressWithAnAccountStoresOnlyTheTraceAndNotifiesTheOwner(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	request, _, mail := f.registration()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}

	result, err := request.Request(ctx, requestCommand(newKey(t), user.Email().String()))

	if err != nil || result.Replayed || result.RequestID == "" {
		t.Fatalf("Request() = %+v, %v, want the same success as for a free address", result, err)
	}
	if n := countRows(t, f, `SELECT count(*) FROM auth.registration_request WHERE id = $1 AND token_hash IS NULL AND password_hash IS NULL`, result.RequestID); n != 1 {
		t.Errorf("rows without payload = %d, want 1: nothing but the trace is stored", n)
	}
	if len(mail.confirmations) != 0 || len(mail.notices) != 1 || mail.notices[0] != user.Email() {
		t.Errorf("confirmations = %d, notices = %v, want only the notice for the owner", len(mail.confirmations), mail.notices)
	}
}

func TestTheFourthRequestOfAnAddressInAnHourStoresTheTraceAndSendsNothing(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	request, _, mail := f.registration()
	email := uniqueEmail(t)

	for range model.MaxRegistrationRequests + 1 {
		if _, err := request.Request(ctx, requestCommand(newKey(t), email)); err != nil {
			t.Fatalf("Request() error = %v", err)
		}
	}

	if n := countRows(t, f, `SELECT count(*) FROM auth.registration_request WHERE email = lower($1)`, email); n != model.MaxRegistrationRequests+1 {
		t.Errorf("requests = %d, want %d", n, model.MaxRegistrationRequests+1)
	}
	if len(mail.confirmations) != model.MaxRegistrationRequests {
		t.Errorf("confirmations = %d, want %d: the fourth sends nothing", len(mail.confirmations), model.MaxRegistrationRequests)
	}
}

func TestARegistrationKeyReplaysTheSameRequestAndConflictsWithAnotherOne(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	request, _, mail := f.registration()
	command := requestCommand(newKey(t), uniqueEmail(t))

	first, err := request.Request(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := request.Request(ctx, command)

	if err != nil || !replay.Replayed || replay.RequestID != first.RequestID || len(mail.confirmations) != 1 {
		t.Errorf("replay = %+v, %v, confirmations = %d, want the first id and no new message", replay, err, len(mail.confirmations))
	}
	changed := command
	changed.Name = "Bea Gomez"
	if _, err := request.Request(ctx, changed); !errors.Is(err, model.ErrIdempotencyKeyConflict) {
		t.Errorf("same key, other name: error = %v, want ErrIdempotencyKeyConflict", err)
	}
}

func TestConcurrentRequestsWithTheSameKeyStoreOneAndReplayTheOther(t *testing.T) {
	f := newFixture(t)
	request, _, _ := f.registration()
	for round := range 10 {
		command := requestCommand(newKey(t), uniqueEmail(t))

		results := make([]in.RequestRegistrationResult, 2)
		errs := make([]error, 2)
		runTogether(2, func(i int) { results[i], errs[i] = request.Request(context.Background(), command) })

		if errs[0] != nil || errs[1] != nil || results[0].RequestID != results[1].RequestID || results[0].Replayed == results[1].Replayed {
			t.Fatalf("round %d: results %+v / %+v, errors %v / %v, want one new request and one replay with the same id", round, results[0], results[1], errs[0], errs[1])
		}
		if n := countRows(t, f, `SELECT count(*) FROM auth.registration_request WHERE email = lower($1)`, command.Email); n != 1 {
			t.Fatalf("round %d: requests = %d, want 1", round, n)
		}
	}
}

func TestConcurrentRequestsWithDifferentKeysForOneAddressLeaveOnePendingRegistration(t *testing.T) {
	f := newFixture(t)
	request, _, _ := f.registration()
	for round := range 10 {
		email := uniqueEmail(t)

		errs := make([]error, 2)
		runTogether(2, func(i int) { _, errs[i] = request.Request(context.Background(), requestCommand(newKey(t), email)) })

		if errs[0] != nil || errs[1] != nil {
			t.Fatalf("round %d: errors %v / %v, want none", round, errs[0], errs[1])
		}
		if n := countRows(t, f, `SELECT count(*) FROM auth.registration_request WHERE email = lower($1) AND token_hash IS NOT NULL AND used_at IS NULL AND deleted_at IS NULL`, email); n != 1 {
			t.Fatalf("round %d: pending = %d, want 1", round, n)
		}
	}
}

func TestConcurrentConfirmationsOfOneTokenCreateOneAccount(t *testing.T) {
	f := newFixture(t)
	request, confirm, mail := f.registration()
	for label, distinctKeys := range map[string]bool{"same key": false, "different keys": true} {
		t.Run(label, func(t *testing.T) {
			email := uniqueEmail(t)
			if _, err := request.Request(context.Background(), requestCommand(newKey(t), email)); err != nil {
				t.Fatal(err)
			}
			token, keys := mail.lastToken(t), []string{newKey(t), newKey(t)}
			if !distinctKeys {
				keys[1] = keys[0]
			}

			results := make([]in.ConfirmRegistrationResult, 2)
			errs := make([]error, 2)
			runTogether(2, func(i int) {
				results[i], errs[i] = confirm.Confirm(context.Background(), in.ConfirmRegistrationCommand{IdempotencyKey: keys[i], Token: token})
			})

			created, other := 0, 0
			for i := range results {
				switch {
				case errs[i] == nil && !results[i].Replayed:
					created++
				case errs[i] == nil && results[i].Replayed, errors.Is(errs[i], model.ErrRegistrationRejected):
					other++
				default:
					t.Errorf("unexpected outcome %+v, %v", results[i], errs[i])
				}
			}
			if created != 1 || other != 1 {
				t.Errorf("created = %d, replayed or rejected = %d, want 1 and 1", created, other)
			}
			if n := countRows(t, f, `SELECT count(*) FROM auth.app_user WHERE email = lower($1)`, email); n != 1 {
				t.Errorf("accounts = %d, want 1", n)
			}
		})
	}
}

// runTogether starts n calls at once.
func runTogether(n int, call func(i int)) {
	var start, done sync.WaitGroup
	start.Add(1)
	for i := range n {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			call(i)
		}()
	}
	start.Done()
	done.Wait()
}
