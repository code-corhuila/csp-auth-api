//go:build integration

package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type fixedCode struct{ code string }

func (g fixedCode) NewCode() (model.VerificationCode, error) {
	return model.NewVerificationCode(g.code)
}

type recordingSender struct {
	mu         sync.Mutex
	deliveries []out.VerificationCodeDelivery
	err        error
}

func (s *recordingSender) Send(_ context.Context, delivery out.VerificationCodeDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.deliveries = append(s.deliveries, delivery)
	return nil
}

type failingEmailChangedOutbox struct{ err error }

func (o failingEmailChangedOutbox) AppendEmailChanged(context.Context, model.UserEmailChanged) error {
	return o.err
}

func (f fixture) emailRequests() *EmailVerificationRepository {
	return NewEmailVerificationRepository(f.pool)
}

func (f fixture) requestEmailChange(sender out.VerificationCodeSender, code string) *usecase.RequestEmailChange {
	return usecase.NewRequestEmailChange(usecase.RequestEmailChangePorts{
		Users: f.users, Requests: f.emailRequests(), Codes: fixedCode{code}, Sender: sender,
		IDs: system.UUIDGenerator{}, Clock: system.Clock{}, Transactions: f.transactions,
	})
}

func (f fixture) verifyEmailChange(outbox out.UserEmailChangedOutbox) *usecase.VerifyEmailChange {
	return usecase.NewVerifyEmailChange(usecase.VerifyEmailChangePorts{
		Requests: f.emailRequests(), Outbox: outbox, IDs: system.UUIDGenerator{}, Clock: system.Clock{}, Transactions: f.transactions,
	})
}

func (f fixture) registeredUser(t *testing.T, ctx context.Context) *model.User {
	t.Helper()
	user := newUser(t, uniqueEmail(t))
	if err := f.register(t, ctx, user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	return user
}

type requestRow struct {
	code               string
	attempts           int
	superseded, active bool
	verified           bool
}

func (f fixture) requestRows(t *testing.T, ctx context.Context, userID string) []requestRow {
	t.Helper()
	rows, err := f.pool.Query(ctx,
		`SELECT verification_code, attempt_count, deleted_at IS NOT NULL, verified_at IS NOT NULL
		 FROM auth.email_verification WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		t.Fatalf("email_verification query error = %v", err)
	}
	defer rows.Close()
	var result []requestRow
	for rows.Next() {
		var row requestRow
		var deleted bool
		if err := rows.Scan(&row.code, &row.attempts, &deleted, &row.verified); err != nil {
			t.Fatal(err)
		}
		row.superseded, row.active = deleted, !deleted && !row.verified
		result = append(result, row)
	}
	return result
}

func (f fixture) accountEmail(t *testing.T, ctx context.Context, userID string) (email string, verified bool) {
	t.Helper()
	if err := f.pool.QueryRow(ctx, `SELECT email, email_verified FROM auth.app_user WHERE id = $1`, userID).Scan(&email, &verified); err != nil {
		t.Fatalf("app_user query error = %v", err)
	}
	return email, verified
}

func activeCount(rows []requestRow) int {
	count := 0
	for _, row := range rows {
		if row.active {
			count++
		}
	}
	return count
}

func TestRequestRoundTripKeepsTheCodeLeadingZerosAndTheNormalizedEmail(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	sender := &recordingSender{}

	err := f.requestEmailChange(sender, "004217").RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: "  New.Mail@Example.COM "})
	if err != nil {
		t.Fatalf("RequestChange() error = %v", err)
	}

	found, err := f.emailRequests().FindPendingForUpdate(ctx, user.ID())
	if err != nil {
		t.Fatalf("FindPendingForUpdate() error = %v", err)
	}
	if found.Code().String() != "004217" || found.NewEmail().String() != "new.mail@example.com" || found.Attempts() != 0 {
		t.Errorf("found = %q %q %d, want 004217 new.mail@example.com 0", found.Code(), found.NewEmail(), found.Attempts())
	}
	if len(sender.deliveries) != 1 || sender.deliveries[0].RequestID != found.ID() || sender.deliveries[0].ExpiresAt.Sub(found.ExpiresAt()).Abs() > time.Millisecond {
		t.Errorf("deliveries = %+v, want one for request %s", sender.deliveries, found.ID())
	}
	if email, verified := f.accountEmail(t, ctx, user.ID()); email != user.Email().String() || verified {
		t.Errorf("account = %q verified %v, want it unchanged until the code is confirmed", email, verified)
	}
}

func TestFindPendingForUpdateReportsNoPendingRequest(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)

	if _, err := f.emailRequests().FindPendingForUpdate(ctx, user.ID()); !errors.Is(err, model.ErrEmailChangeNotFound) {
		t.Errorf("error = %v, want ErrEmailChangeNotFound", err)
	}
}

func TestANewRequestSupersedesThePreviousOneAndTheFourthInAnHourIsRejected(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	useCase := f.requestEmailChange(&recordingSender{}, "111111")

	for i := 0; i < 3; i++ {
		if err := useCase.RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: uniqueEmail(t)}); err != nil {
			t.Fatalf("request %d error = %v", i+1, err)
		}
	}
	err := useCase.RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: uniqueEmail(t)})

	if !errors.Is(err, model.ErrTooManyEmailChangeRequests) {
		t.Fatalf("fourth request error = %v, want ErrTooManyEmailChangeRequests", err)
	}
	rows := f.requestRows(t, ctx, user.ID())
	if len(rows) != 3 || activeCount(rows) != 1 || !rows[0].superseded || !rows[1].superseded || !rows[2].active {
		t.Errorf("rows = %+v, want three requests of which only the last one is active", rows)
	}
}

func TestRequestTimesSinceUsesARollingWindowAndListsTheSupersededOnesOldestFirst(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	repository := f.emailRequests()
	email, _ := model.NewEmail(uniqueEmail(t))
	code, _ := model.NewVerificationCode("222222")
	now := time.Now().UTC()
	for _, age := range []time.Duration{10 * time.Minute, 90 * time.Minute, 59 * time.Minute} {
		request := model.NewEmailChangeRequest(newUUID(t), user.ID(), email, code, now.Add(-age))
		err := f.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
			if err := repository.SupersedePending(ctx, user.ID(), now); err != nil {
				return err
			}
			return repository.Add(ctx, request)
		})
		if err != nil {
			t.Fatalf("store request of %v ago error = %v", age, err)
		}
	}

	times, err := repository.RequestTimesSince(ctx, user.ID(), now.Add(-time.Hour))

	if err != nil || len(times) != 2 ||
		times[0].Sub(now.Add(-59*time.Minute)).Abs() > time.Millisecond || times[1].Sub(now.Add(-10*time.Minute)).Abs() > time.Millisecond {
		t.Errorf("RequestTimesSince() = %v, %v, want the requests of 59 and 10 minutes ago, oldest first (the one of 90 minutes ago is outside the hour)", times, err)
	}
}

func TestTheFourthRequestTellsWhenTheOldestOneLeavesTheWindow(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	repository := f.emailRequests()
	email, _ := model.NewEmail(uniqueEmail(t))
	code, _ := model.NewVerificationCode("444444")
	now := time.Now().UTC()
	for _, age := range []time.Duration{50 * time.Minute, 30 * time.Minute, 10 * time.Minute} {
		request := model.NewEmailChangeRequest(newUUID(t), user.ID(), email, code, now.Add(-age))
		err := f.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
			if err := repository.SupersedePending(ctx, user.ID(), now); err != nil {
				return err
			}
			return repository.Add(ctx, request)
		})
		if err != nil {
			t.Fatalf("store request of %v ago error = %v", age, err)
		}
	}

	err := f.requestEmailChange(&recordingSender{}, "555555").RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: uniqueEmail(t)})

	var limited *model.EmailChangeRateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("error = %v, want an EmailChangeRateLimitedError", err)
	}
	if want := 10 * time.Minute; limited.RetryAfter < want-time.Minute || limited.RetryAfter > want {
		t.Errorf("RetryAfter = %v, want about %v (the request of 50 minutes ago leaves the hour then)", limited.RetryAfter, want)
	}
}

func TestConcurrentRequestsOfOneUserLeaveOneActiveRequest(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	useCase := f.requestEmailChange(&recordingSender{}, "333333")

	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = useCase.RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: uniqueEmail(t)})
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("request %d error = %v, want nil: the requests are serialized, not failed", i+1, err)
		}
	}
	if rows := f.requestRows(t, ctx, user.ID()); len(rows) != 3 || activeCount(rows) != 1 {
		t.Errorf("rows = %+v, want three requests with one active", rows)
	}
}

func TestTheDatabaseRefusesTwoPendingRequestsOfOneUser(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	email, _ := model.NewEmail(uniqueEmail(t))
	code, _ := model.NewVerificationCode("444444")
	repository := f.emailRequests()
	if err := repository.Add(ctx, model.NewEmailChangeRequest(newUUID(t), user.ID(), email, code, time.Now())); err != nil {
		t.Fatalf("first Add() error = %v", err)
	}

	err := repository.Add(ctx, model.NewEmailChangeRequest(newUUID(t), user.ID(), email, code, time.Now()))

	if err == nil {
		t.Error("second Add() error = nil, want the partial unique index to refuse it")
	}
}

func TestARequestWhoseSenderFailsLeavesNothingBehind(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	sendErr := errors.New("sender down")

	err := f.requestEmailChange(&recordingSender{err: sendErr}, "555555").RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: uniqueEmail(t)})

	if !errors.Is(err, sendErr) {
		t.Fatalf("error = %v, want the sender error", err)
	}
	if rows := f.requestRows(t, ctx, user.ID()); len(rows) != 0 {
		t.Errorf("rows = %+v, want none: the request rolled back with the failed delivery", rows)
	}
}

func TestARequestForAnEmailOfAnActiveAccountIsRejected(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user, other := f.registeredUser(t, ctx), f.registeredUser(t, ctx)
	useCase := f.requestEmailChange(&recordingSender{}, "666666")

	for _, email := range []string{other.Email().String(), user.Email().String()} {
		err := useCase.RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: email})
		if !errors.Is(err, model.ErrEmailAlreadyRegistered) {
			t.Errorf("RequestChange(%s) error = %v, want ErrEmailAlreadyRegistered", email, err)
		}
	}
}

func (f fixture) requestChangeTo(t *testing.T, ctx context.Context, user *model.User, email, code string) {
	t.Helper()
	if err := f.requestEmailChange(&recordingSender{}, code).RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: email}); err != nil {
		t.Fatalf("RequestChange() error = %v", err)
	}
}

func TestAWrongCodeCommitsItsAttemptAndTheFifthRetiresTheRequest(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	f.requestChangeTo(t, ctx, user, uniqueEmail(t), "123456")
	verify := f.verifyEmailChange(f.outbox)

	for attempt := 1; attempt <= 5; attempt++ {
		err := verify.VerifyChange(ctx, in.VerifyEmailChangeCommand{UserID: user.ID(), VerificationCode: "654321"})
		if !errors.Is(err, model.ErrVerificationRejected) {
			t.Fatalf("attempt %d error = %v, want ErrVerificationRejected", attempt, err)
		}
		rows := f.requestRows(t, ctx, user.ID())
		if rows[0].attempts != attempt || rows[0].superseded != (attempt == 5) {
			t.Errorf("after attempt %d: attempts = %d, retired = %v, want %d and %v", attempt, rows[0].attempts, rows[0].superseded, attempt, attempt == 5)
		}
	}

	err := verify.VerifyChange(ctx, in.VerifyEmailChangeCommand{UserID: user.ID(), VerificationCode: "123456"})
	if !errors.Is(err, model.ErrVerificationRejected) {
		t.Errorf("right code after exhaustion: error = %v, want ErrVerificationRejected", err)
	}
	if email, verified := f.accountEmail(t, ctx, user.ID()); email != user.Email().String() || verified {
		t.Errorf("account = %q verified %v, want it unchanged", email, verified)
	}
}

func emailChangedEvents(t *testing.T, ctx context.Context, userID string) []string {
	t.Helper()
	reader := openPool(t, readerURLVariable)
	rows, err := reader.Query(ctx, `SELECT payload::text FROM auth.outbox_event WHERE aggregate_id = $1 AND event_type = 'UserEmailChanged'`, userID)
	if err != nil {
		t.Fatalf("outbox query error = %v", err)
	}
	defer rows.Close()
	var payloads []string
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

func TestTheRightCodeChangesTheEmailVerifiesItAndWritesOneEventWithoutTheCode(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	newEmail := uniqueEmail(t)
	f.requestChangeTo(t, ctx, user, newEmail, "090909")

	err := f.verifyEmailChange(f.outbox).VerifyChange(ctx, in.VerifyEmailChangeCommand{UserID: user.ID(), VerificationCode: "090909"})

	if err != nil {
		t.Fatalf("VerifyChange() error = %v", err)
	}
	wantEmail, _ := model.NewEmail(newEmail)
	if email, verified := f.accountEmail(t, ctx, user.ID()); email != wantEmail.String() || !verified {
		t.Errorf("account = %q verified %v, want %q verified", email, verified, wantEmail)
	}
	if rows := f.requestRows(t, ctx, user.ID()); len(rows) != 1 || !rows[0].verified || rows[0].active {
		t.Errorf("rows = %+v, want the request consumed", rows)
	}
	payloads := emailChangedEvents(t, ctx, user.ID())
	if len(payloads) != 1 {
		t.Fatalf("events = %v, want exactly one UserEmailChanged", payloads)
	}
	var event struct {
		EventType string
		Payload   map[string]string
	}
	if err := json.Unmarshal([]byte(payloads[0]), &event); err != nil {
		t.Fatal(err)
	}
	if event.Payload["userId"] != user.ID() || event.Payload["email"] != wantEmail.String() || len(event.Payload) != 2 {
		t.Errorf("payload = %v, want userId and the new email only", event.Payload)
	}
	if err := f.verifyEmailChange(f.outbox).VerifyChange(ctx, in.VerifyEmailChangeCommand{UserID: user.ID(), VerificationCode: "090909"}); !errors.Is(err, model.ErrVerificationRejected) {
		t.Errorf("second verification error = %v, want ErrVerificationRejected (the request was consumed)", err)
	}
	if len(emailChangedEvents(t, ctx, user.ID())) != 1 {
		t.Error("a repeated verification published a second event")
	}
}

func TestAFailedEventRollsBackTheEmailChange(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	f.requestChangeTo(t, ctx, user, uniqueEmail(t), "135790")
	outboxErr := errors.New("outbox down")

	err := f.verifyEmailChange(failingEmailChangedOutbox{outboxErr}).VerifyChange(ctx, in.VerifyEmailChangeCommand{UserID: user.ID(), VerificationCode: "135790"})

	if !errors.Is(err, outboxErr) {
		t.Fatalf("error = %v, want the outbox error", err)
	}
	if email, verified := f.accountEmail(t, ctx, user.ID()); email != user.Email().String() || verified {
		t.Errorf("account = %q verified %v, want it unchanged", email, verified)
	}
	if rows := f.requestRows(t, ctx, user.ID()); len(rows) != 1 || !rows[0].active {
		t.Errorf("rows = %+v, want the request still pending", rows)
	}
}

func TestWhenAnotherAccountTookTheAddressTheRequestIsInvalidatedAndNoEventIsWritten(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	contested := newUser(t, uniqueEmail(t))
	f.requestChangeTo(t, ctx, user, contested.Email().String(), "246810")
	if err := f.register(t, ctx, contested); err != nil {
		t.Fatalf("register the account that takes the address: %v", err)
	}

	err := f.verifyEmailChange(f.outbox).VerifyChange(ctx, in.VerifyEmailChangeCommand{UserID: user.ID(), VerificationCode: "246810"})

	if !errors.Is(err, model.ErrEmailAlreadyRegistered) {
		t.Fatalf("error = %v, want ErrEmailAlreadyRegistered", err)
	}
	if email, verified := f.accountEmail(t, ctx, user.ID()); email != user.Email().String() || verified {
		t.Errorf("account = %q verified %v, want it unchanged", email, verified)
	}
	if rows := f.requestRows(t, ctx, user.ID()); len(rows) != 1 || rows[0].active || !rows[0].superseded || rows[0].verified {
		t.Errorf("rows = %+v, want the request invalidated, not verified", rows)
	}
	if events := emailChangedEvents(t, ctx, user.ID()); len(events) != 0 {
		t.Errorf("events = %v, want none", events)
	}
}

func TestAnExpiredRequestIsRejectedEvenWithTheRightCode(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	email, _ := model.NewEmail(uniqueEmail(t))
	code, _ := model.NewVerificationCode("987654")
	stale := model.NewEmailChangeRequest(newUUID(t), user.ID(), email, code, time.Now().Add(-model.EmailChangeCodeLifetime-time.Minute))
	if err := f.emailRequests().Add(ctx, stale); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	err := f.verifyEmailChange(f.outbox).VerifyChange(ctx, in.VerifyEmailChangeCommand{UserID: user.ID(), VerificationCode: "987654"})

	if !errors.Is(err, model.ErrVerificationRejected) {
		t.Errorf("error = %v, want ErrVerificationRejected", err)
	}
	if got, _ := f.accountEmail(t, ctx, user.ID()); got != user.Email().String() {
		t.Errorf("account email = %q, want it unchanged", got)
	}
}

// slowUsers pauses after the request took the account lock, to widen the window of the race.
type slowUsers struct{ *UserRepository }

func (u slowUsers) ExistsByEmail(ctx context.Context, email model.Email) (bool, error) {
	time.Sleep(3 * time.Millisecond)
	return u.UserRepository.ExistsByEmail(ctx, email)
}

// slowRequests pauses after the verification locked the pending request, to widen the same window.
type slowRequests struct{ *EmailVerificationRepository }

func (r slowRequests) FindPendingForUpdate(ctx context.Context, userID string) (*model.EmailChangeRequest, error) {
	request, err := r.EmailVerificationRepository.FindPendingForUpdate(ctx, userID)
	time.Sleep(3 * time.Millisecond)
	return request, err
}

func TestARequestAndACorrectVerificationRacingNeverDeadlock(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	request := usecase.NewRequestEmailChange(usecase.RequestEmailChangePorts{
		Users: slowUsers{f.users}, Requests: f.emailRequests(), Codes: fixedCode{"222222"}, Sender: &recordingSender{},
		IDs: system.UUIDGenerator{}, Clock: system.Clock{}, Transactions: f.transactions,
	})
	verify := usecase.NewVerifyEmailChange(usecase.VerifyEmailChangePorts{
		Requests: slowRequests{f.emailRequests()}, Outbox: f.outbox, IDs: system.UUIDGenerator{}, Clock: system.Clock{}, Transactions: f.transactions,
	})
	for i := range 30 {
		user := f.registeredUser(t, ctx)
		firstEmail := uniqueEmail(t)
		if err := f.requestEmailChange(&recordingSender{}, "111111").RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: firstEmail}); err != nil {
			t.Fatalf("iteration %d: first request error = %v", i, err)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		var requestErr, verifyErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			requestErr = request.RequestChange(ctx, in.RequestEmailChangeCommand{UserID: user.ID(), Email: uniqueEmail(t)})
		}()
		go func() {
			defer wg.Done()
			<-start
			verifyErr = verify.VerifyChange(ctx, in.VerifyEmailChangeCommand{UserID: user.ID(), VerificationCode: "111111"})
		}()
		close(start)
		wg.Wait()

		var pgErr *pgconn.PgError
		if errors.As(requestErr, &pgErr) || errors.As(verifyErr, &pgErr) {
			t.Fatalf("iteration %d: database error request = %v, verify = %v (40P01 is a deadlock)", i, requestErr, verifyErr)
		}
		if requestErr != nil {
			t.Fatalf("iteration %d: request error = %v, want nil", i, requestErr)
		}
		email, _ := f.accountEmail(t, ctx, user.ID())
		switch {
		case verifyErr == nil && email == strings.ToLower(firstEmail):
		case errors.Is(verifyErr, model.ErrVerificationRejected) && email == user.Email().String():
		default:
			t.Fatalf("iteration %d: verify error = %v, account email = %q, want the new email set or a uniform refusal with the email unchanged", i, verifyErr, email)
		}
	}
}
