package usecase

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

type fakeEmailRequests struct {
	journal         *journal
	pending         *model.EmailChangeRequest
	requestTimes    []time.Time
	added           []*model.EmailChangeRequest
	requestedSince  time.Time
	superseded      bool
	wrongAttempts   []int
	invalidated     []string
	confirmed       []string
	confirmErr      error
	addErr, lockErr error
	countErr        error
	findErr         error
}

func (r *fakeEmailRequests) LockRequestsOf(context.Context, string) error {
	r.journal.record("lock-requests")
	return r.lockErr
}

func (r *fakeEmailRequests) RequestTimesSince(_ context.Context, _ string, since time.Time) ([]time.Time, error) {
	r.journal.record("count")
	r.requestedSince = since
	return r.requestTimes, r.countErr
}

func (r *fakeEmailRequests) SupersedePending(context.Context, string, time.Time) error {
	r.journal.record("supersede")
	r.superseded = true
	return nil
}

func (r *fakeEmailRequests) Add(_ context.Context, request *model.EmailChangeRequest) error {
	r.journal.record("add")
	if r.addErr != nil {
		return r.addErr
	}
	r.added = append(r.added, request)
	return nil
}

func (r *fakeEmailRequests) FindPendingForUpdate(context.Context, string) (*model.EmailChangeRequest, error) {
	r.journal.record("find-pending")
	if r.findErr != nil {
		return nil, r.findErr
	}
	if r.pending == nil {
		return nil, model.ErrEmailChangeNotFound
	}
	return r.pending, nil
}

func (r *fakeEmailRequests) RecordWrongAttempt(_ context.Context, request *model.EmailChangeRequest, _ time.Time) error {
	r.journal.record("wrong-attempt")
	r.wrongAttempts = append(r.wrongAttempts, request.Attempts())
	return nil
}

func (r *fakeEmailRequests) Invalidate(_ context.Context, request *model.EmailChangeRequest, _ time.Time) error {
	r.journal.record("invalidate")
	r.invalidated = append(r.invalidated, request.ID())
	return nil
}

func (r *fakeEmailRequests) ConfirmEmailChange(_ context.Context, request *model.EmailChangeRequest, _ time.Time) error {
	r.journal.record("confirm")
	if r.confirmErr != nil {
		return r.confirmErr
	}
	r.confirmed = append(r.confirmed, request.NewEmail().String())
	return nil
}

type fakeCodes struct {
	code string
	err  error
}

func (g fakeCodes) NewCode() (model.VerificationCode, error) {
	code, _ := model.NewVerificationCode(g.code)
	return code, g.err
}

type fakeSender struct {
	journal    *journal
	deliveries []out.VerificationCodeDelivery
	err        error
}

func (s *fakeSender) Send(_ context.Context, delivery out.VerificationCodeDelivery) error {
	s.journal.record("send")
	if s.err != nil {
		return s.err
	}
	s.deliveries = append(s.deliveries, delivery)
	return nil
}

type fakeEmailChangedOutbox struct {
	journal *journal
	events  []model.UserEmailChanged
	err     error
}

func (o *fakeEmailChangedOutbox) AppendEmailChanged(_ context.Context, event model.UserEmailChanged) error {
	o.journal.record("outbox")
	if o.err != nil {
		return o.err
	}
	o.events = append(o.events, event)
	return nil
}

type requestFixture struct {
	useCase      *RequestEmailChange
	users        *fakeRepository
	requests     *fakeEmailRequests
	sender       *fakeSender
	transactions *fakeTransactions
	journal      *journal
}

func newRequestFixture() *requestFixture {
	j := &journal{}
	f := &requestFixture{
		users:        &fakeRepository{journal: j, taken: map[string]bool{}},
		requests:     &fakeEmailRequests{journal: j},
		sender:       &fakeSender{journal: j},
		transactions: &fakeTransactions{journal: j},
		journal:      j,
	}
	f.useCase = NewRequestEmailChange(RequestEmailChangePorts{
		Users: f.users, Requests: f.requests, Codes: fakeCodes{code: "012345"}, Sender: f.sender,
		IDs: &fakeIDs{next: []string{"request-1"}}, Clock: fakeClock{}, Transactions: f.transactions,
	})
	return f
}

func requestCommand() in.RequestEmailChangeCommand {
	return in.RequestEmailChangeCommand{UserID: "user-1", Email: " New.Address@Example.com "}
}

func TestRequestChangeStoresTheRequestAndSendsTheCodeInsideTheTransaction(t *testing.T) {
	f := newRequestFixture()

	err := f.useCase.RequestChange(context.Background(), requestCommand())

	if err != nil {
		t.Fatalf("RequestChange() error = %v", err)
	}
	wantSteps := []string{"begin", "lock-requests", "count", "supersede", "add", "send", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	if len(f.requests.added) != 1 || f.requests.added[0].NewEmail().String() != "new.address@example.com" || f.requests.added[0].Code().String() != "012345" {
		t.Fatalf("added = %+v, want the request of the normalized email with the generated code", f.requests.added)
	}
	want := out.VerificationCodeDelivery{
		RequestID: "request-1", UserID: "user-1", NewEmail: f.requests.added[0].NewEmail(), Code: f.requests.added[0].Code(),
		ExpiresAt: registeredAt.Add(15 * time.Minute),
	}
	if !reflect.DeepEqual(f.sender.deliveries, []out.VerificationCodeDelivery{want}) {
		t.Errorf("deliveries = %+v, want [%+v]", f.sender.deliveries, want)
	}
}

func TestRequestChangeCountsTheRequestsOfTheLastRollingHour(t *testing.T) {
	f := newRequestFixture()
	f.requests.requestTimes = []time.Time{registeredAt.Add(-50 * time.Minute), registeredAt.Add(-10 * time.Minute)}

	err := f.useCase.RequestChange(context.Background(), requestCommand())

	if err != nil || !f.requests.requestedSince.Equal(registeredAt.Add(-time.Hour)) {
		t.Errorf("error = %v, listed since %v, want nil and %v", err, f.requests.requestedSince, registeredAt.Add(-time.Hour))
	}
}

func TestRequestChangeRejectsTheFourthRequestOfTheHourAndWritesNothing(t *testing.T) {
	f := newRequestFixture()
	f.requests.requestTimes = []time.Time{
		registeredAt.Add(-40 * time.Minute), registeredAt.Add(-20 * time.Minute), registeredAt.Add(-5 * time.Minute),
	}

	err := f.useCase.RequestChange(context.Background(), requestCommand())

	var limited *model.EmailChangeRateLimitedError
	if !errors.Is(err, model.ErrTooManyEmailChangeRequests) || !errors.As(err, &limited) {
		t.Fatalf("error = %v, want ErrTooManyEmailChangeRequests", err)
	}
	if limited.RetryAfter != 20*time.Minute {
		t.Errorf("RetryAfter = %v, want 20m0s (the oldest request is 40 minutes old, the window is an hour)", limited.RetryAfter)
	}
	if f.requests.superseded || len(f.requests.added) != 0 || len(f.sender.deliveries) != 0 || f.transactions.committed {
		t.Errorf("superseded = %v, added = %d, sent = %d, committed = %v, want nothing written",
			f.requests.superseded, len(f.requests.added), len(f.sender.deliveries), f.transactions.committed)
	}
}

func TestRequestChangeTellsTheRemainingWaitFromTheClockOfThePort(t *testing.T) {
	cases := map[string]struct {
		oldestAge time.Duration
		want      time.Duration
	}{
		"one second left":    {time.Hour - time.Second, time.Second},
		"at the window edge": {time.Hour, 0},
		"just requested":     {0, time.Hour},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRequestFixture()
			f.requests.requestTimes = []time.Time{
				registeredAt.Add(-c.oldestAge), registeredAt.Add(-c.oldestAge / 2), registeredAt,
			}

			err := f.useCase.RequestChange(context.Background(), requestCommand())

			var limited *model.EmailChangeRateLimitedError
			if !errors.As(err, &limited) || limited.RetryAfter != c.want {
				t.Errorf("error = %v, want a rate limit with RetryAfter %v", err, c.want)
			}
		})
	}
}

func TestRequestChangeRejectsAnInvalidEmailBeforeOpeningTheTransaction(t *testing.T) {
	f := newRequestFixture()

	err := f.useCase.RequestChange(context.Background(), in.RequestEmailChangeCommand{UserID: "user-1", Email: "not-an-email"})

	if !errors.Is(err, model.ErrInvalidEmail) || len(f.journal.steps) != 0 {
		t.Errorf("error = %v, steps = %v, want ErrInvalidEmail and no step", err, f.journal.steps)
	}
}

func TestRequestChangeRejectsAnEmailUsedByAnActiveAccountEvenTheOwn(t *testing.T) {
	f := newRequestFixture()
	f.users.taken["new.address@example.com"] = true

	err := f.useCase.RequestChange(context.Background(), requestCommand())

	if !errors.Is(err, model.ErrEmailAlreadyRegistered) || len(f.requests.added) != 0 || f.transactions.committed {
		t.Errorf("error = %v, added = %d, committed = %v, want ErrEmailAlreadyRegistered and nothing written", err, len(f.requests.added), f.transactions.committed)
	}
}

func TestRequestChangeRollsBackWhenTheSenderFails(t *testing.T) {
	f := newRequestFixture()
	sendErr := errors.New("sender down")
	f.sender.err = sendErr

	err := f.useCase.RequestChange(context.Background(), requestCommand())

	if !errors.Is(err, sendErr) || f.transactions.committed {
		t.Errorf("error = %v, committed = %v, want the sender error and a rollback", err, f.transactions.committed)
	}
	if got := f.journal.steps[len(f.journal.steps)-1]; got != "rollback" {
		t.Errorf("last step = %q, want rollback", got)
	}
}

func TestRequestChangeStopsWhenAnyPortFails(t *testing.T) {
	failure := errors.New("boom")
	cases := map[string]func(*requestFixture){
		"lock":     func(f *requestFixture) { f.requests.lockErr = failure },
		"exists":   func(f *requestFixture) { f.users.existsErr = failure },
		"count":    func(f *requestFixture) { f.requests.countErr = failure },
		"add":      func(f *requestFixture) { f.requests.addErr = failure },
		"generate": func(f *requestFixture) { f.useCase.ports.Codes = fakeCodes{err: failure} },
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRequestFixture()
			arrange(f)

			err := f.useCase.RequestChange(context.Background(), requestCommand())

			if !errors.Is(err, failure) || f.transactions.committed || len(f.sender.deliveries) != 0 {
				t.Errorf("error = %v, committed = %v, sent = %d, want the failure, a rollback and no delivery", err, f.transactions.committed, len(f.sender.deliveries))
			}
		})
	}
}

type verifyFixture struct {
	useCase      *VerifyEmailChange
	requests     *fakeEmailRequests
	outbox       *fakeEmailChangedOutbox
	transactions *fakeTransactions
	journal      *journal
}

func newVerifyFixture(pending *model.EmailChangeRequest) *verifyFixture {
	j := &journal{}
	f := &verifyFixture{
		requests:     &fakeEmailRequests{journal: j, pending: pending},
		outbox:       &fakeEmailChangedOutbox{journal: j},
		transactions: &fakeTransactions{journal: j},
		journal:      j,
	}
	f.useCase = NewVerifyEmailChange(VerifyEmailChangePorts{
		Requests: f.requests, Outbox: f.outbox, IDs: &fakeIDs{next: []string{"event-1"}}, Clock: fakeClock{}, Transactions: f.transactions,
	})
	return f
}

func pendingChange(t *testing.T, requestedAt time.Time) *model.EmailChangeRequest {
	t.Helper()
	email, _ := model.NewEmail("new.address@example.com")
	code, _ := model.NewVerificationCode("012345")
	return model.NewEmailChangeRequest("request-1", "user-1", email, code, requestedAt)
}

func verifyCommand(code string) in.VerifyEmailChangeCommand {
	return in.VerifyEmailChangeCommand{UserID: "user-1", VerificationCode: code}
}

func TestVerifyChangeConfirmsTheEmailAndPublishesTheEventInOneTransaction(t *testing.T) {
	f := newVerifyFixture(pendingChange(t, registeredAt.Add(-time.Minute)))

	err := f.useCase.VerifyChange(context.Background(), verifyCommand("012345"))

	if err != nil {
		t.Fatalf("VerifyChange() error = %v", err)
	}
	wantSteps := []string{"begin", "lock-requests", "find-pending", "confirm", "outbox", "commit"}
	if !reflect.DeepEqual(f.journal.steps, wantSteps) {
		t.Errorf("steps = %v, want %v", f.journal.steps, wantSteps)
	}
	want := model.UserEmailChanged{EventID: "event-1", OccurredAt: registeredAt, UserID: "user-1", Email: "new.address@example.com"}
	if !reflect.DeepEqual(f.outbox.events, []model.UserEmailChanged{want}) {
		t.Errorf("events = %+v, want [%+v]", f.outbox.events, want)
	}
}

func TestVerifyChangeTakesTheAccountLockBeforeReadingThePendingRequest(t *testing.T) {
	f := newVerifyFixture(pendingChange(t, registeredAt.Add(-time.Minute)))

	_ = f.useCase.VerifyChange(context.Background(), verifyCommand("012345"))

	if got := f.journal.steps[1:3]; !reflect.DeepEqual(got, []string{"lock-requests", "find-pending"}) {
		t.Errorf("steps after begin = %v, want the account lock before the read of the request, as RequestEmailChange does", got)
	}
}

func TestVerifyChangeRefusesUniformlyWhenTheAccountIsGone(t *testing.T) {
	f := newVerifyFixture(pendingChange(t, registeredAt.Add(-time.Minute)))
	f.requests.lockErr = model.ErrUserNotFound

	err := f.useCase.VerifyChange(context.Background(), verifyCommand("012345"))

	if !errors.Is(err, model.ErrVerificationRejected) || len(f.requests.confirmed) != 0 {
		t.Errorf("error = %v, confirmed = %v, want ErrVerificationRejected and nothing confirmed", err, f.requests.confirmed)
	}
}

func TestVerifyChangeAnswersTheSameRejectionForEveryCauseAndPublishesNothing(t *testing.T) {
	expired := pendingChange(t, registeredAt.Add(-model.EmailChangeCodeLifetime))
	exhausted := pendingChange(t, registeredAt)
	for i := 0; i < model.MaxEmailChangeAttempts; i++ {
		wrong, _ := model.NewVerificationCode("999999")
		_ = exhausted.Submit(wrong, registeredAt)
	}
	cases := map[string]struct {
		pending *model.EmailChangeRequest
		code    string
	}{
		"malformed code": {pendingChange(t, registeredAt), "12ab"},
		"no request":     {nil, "012345"},
		"expired":        {expired, "012345"},
		"exhausted":      {exhausted, "012345"},
		"wrong code":     {pendingChange(t, registeredAt), "999999"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newVerifyFixture(c.pending)

			err := f.useCase.VerifyChange(context.Background(), verifyCommand(c.code))

			if err != model.ErrVerificationRejected {
				t.Errorf("error = %v, want ErrVerificationRejected", err)
			}
			if len(f.requests.confirmed) != 0 || len(f.outbox.events) != 0 {
				t.Errorf("confirmed = %v, events = %v, want nothing", f.requests.confirmed, f.outbox.events)
			}
		})
	}
}

func TestVerifyChangeCommitsTheWrongAttemptEvenThoughTheAnswerIsAnError(t *testing.T) {
	f := newVerifyFixture(pendingChange(t, registeredAt))

	err := f.useCase.VerifyChange(context.Background(), verifyCommand("999999"))

	if err != model.ErrVerificationRejected || !f.transactions.committed {
		t.Fatalf("error = %v, committed = %v, want ErrVerificationRejected and a commit", err, f.transactions.committed)
	}
	if !reflect.DeepEqual(f.requests.wrongAttempts, []int{1}) {
		t.Errorf("wrong attempts recorded = %v, want [1]", f.requests.wrongAttempts)
	}
}

func TestVerifyChangeRecordsTheFifthWrongAttemptSoTheRepositoryCanRetireTheRequest(t *testing.T) {
	request := pendingChange(t, registeredAt)
	wrong, _ := model.NewVerificationCode("999999")
	for i := 0; i < model.MaxEmailChangeAttempts-1; i++ {
		_ = request.Submit(wrong, registeredAt)
	}
	f := newVerifyFixture(request)

	_ = f.useCase.VerifyChange(context.Background(), verifyCommand("999999"))

	if !reflect.DeepEqual(f.requests.wrongAttempts, []int{model.MaxEmailChangeAttempts}) || !request.Exhausted() {
		t.Errorf("wrong attempts recorded = %v, exhausted = %v, want [5] and true", f.requests.wrongAttempts, request.Exhausted())
	}
}

func TestVerifyChangeInvalidatesTheRequestWhenAnotherAccountTookTheAddress(t *testing.T) {
	f := newVerifyFixture(pendingChange(t, registeredAt))
	f.requests.confirmErr = model.ErrEmailAlreadyRegistered

	err := f.useCase.VerifyChange(context.Background(), verifyCommand("012345"))

	if !errors.Is(err, model.ErrEmailAlreadyRegistered) || !f.transactions.committed {
		t.Fatalf("error = %v, committed = %v, want ErrEmailAlreadyRegistered and a commit", err, f.transactions.committed)
	}
	if !reflect.DeepEqual(f.requests.invalidated, []string{"request-1"}) || len(f.outbox.events) != 0 {
		t.Errorf("invalidated = %v, events = %v, want the request invalidated and no event", f.requests.invalidated, f.outbox.events)
	}
}

func TestVerifyChangeRollsBackWhenTheEventCannotBeWritten(t *testing.T) {
	f := newVerifyFixture(pendingChange(t, registeredAt))
	failure := errors.New("outbox down")
	f.outbox.err = failure

	err := f.useCase.VerifyChange(context.Background(), verifyCommand("012345"))

	if !errors.Is(err, failure) || f.transactions.committed {
		t.Errorf("error = %v, committed = %v, want the failure and a rollback", err, f.transactions.committed)
	}
}

func TestVerifyChangeRollsBackOnUnexpectedRepositoryFailures(t *testing.T) {
	failure := errors.New("boom")
	cases := map[string]func(*verifyFixture){
		"find":    func(f *verifyFixture) { f.requests.findErr = failure },
		"confirm": func(f *verifyFixture) { f.requests.confirmErr = failure },
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			f := newVerifyFixture(pendingChange(t, registeredAt))
			arrange(f)

			err := f.useCase.VerifyChange(context.Background(), verifyCommand("012345"))

			if !errors.Is(err, failure) || f.transactions.committed || len(f.outbox.events) != 0 {
				t.Errorf("error = %v, committed = %v, events = %v, want the failure and a rollback", err, f.transactions.committed, f.outbox.events)
			}
		})
	}
}

func TestRequestChangeReportsAnAccountThatIsGoneAndWritesNothing(t *testing.T) {
	f := newRequestFixture()
	f.requests.lockErr = model.ErrUserNotFound

	err := f.useCase.RequestChange(context.Background(), requestCommand())

	if !errors.Is(err, model.ErrUserNotFound) || len(f.requests.added) != 0 || len(f.sender.deliveries) != 0 {
		t.Errorf("error = %v, added = %v, deliveries = %v, want ErrUserNotFound and nothing stored or sent", err, f.requests.added, f.sender.deliveries)
	}
	if want := []string{"begin", "lock-requests", "rollback"}; !reflect.DeepEqual(f.journal.steps, want) {
		t.Errorf("steps = %v, want %v", f.journal.steps, want)
	}
}
