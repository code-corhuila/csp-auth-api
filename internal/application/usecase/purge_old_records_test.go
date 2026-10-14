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

// agedTable is a table with a number of eligible rows; it records how it was called.
type agedTable struct {
	name     string
	eligible int
	calls    *[]string
	cutoffs  []time.Time
	limits   []int
	err      error
}

func (a *agedTable) DeleteOlderThan(_ context.Context, cutoff time.Time, limit int) (int, error) {
	*a.calls = append(*a.calls, a.name)
	a.cutoffs = append(a.cutoffs, cutoff)
	a.limits = append(a.limits, limit)
	if a.err != nil {
		return 0, a.err
	}
	deleted := min(limit, a.eligible)
	a.eligible -= deleted
	return deleted, nil
}

func (a *agedTable) ExistOlderThan(context.Context, time.Time) (bool, error) {
	return a.eligible > 0, a.err
}

type purgeFixture struct {
	useCase                    *PurgeOldRecords
	outbox, refreshTokens, key *agedTable
	calls                      []string
}

func newPurgeFixture(outbox, refreshTokens, keys int) *purgeFixture {
	f := &purgeFixture{}
	f.outbox = &agedTable{name: "outbox", eligible: outbox, calls: &f.calls}
	f.refreshTokens = &agedTable{name: "refresh tokens", eligible: refreshTokens, calls: &f.calls}
	f.key = &agedTable{name: "idempotency keys", eligible: keys, calls: &f.calls}
	f.useCase = NewPurgeOldRecords(f.outbox, f.refreshTokens, f.key, fakeClock{})
	return f
}

func purge(f *purgeFixture, batch int) (in.PurgeOldRecordsResult, error) {
	return f.useCase.Purge(context.Background(), in.PurgeOldRecordsCommand{BatchSize: batch})
}

func TestPurgeDeletesOutboxThenRefreshTokensThenIdempotencyKeysWithTheRetentionOfEachOne(t *testing.T) {
	f := newPurgeFixture(1, 1, 1)

	result, err := purge(f, 100)

	if err != nil || result.ProcessedCount != 3 || result.HasMore {
		t.Fatalf("result = %+v, error = %v, want 3 deleted and nothing left", result, err)
	}
	if want := []string{"outbox", "refresh tokens", "idempotency keys"}; !reflect.DeepEqual(f.calls, want) {
		t.Errorf("order = %v, want %v", f.calls, want)
	}
	day := 24 * time.Hour
	if !f.outbox.cutoffs[0].Equal(registeredAt.Add(-30*day)) || !f.refreshTokens.cutoffs[0].Equal(registeredAt.Add(-30*day)) || !f.key.cutoffs[0].Equal(registeredAt.Add(-7*day)) {
		t.Errorf("cutoffs = %v / %v / %v, want now minus 30, 30 and 7 days", f.outbox.cutoffs, f.refreshTokens.cutoffs, f.key.cutoffs)
	}
}

func TestPurgeNeverDeletesMoreThanTheBatchSizeInTotal(t *testing.T) {
	f := newPurgeFixture(2, 5, 5)

	result, err := purge(f, 4)

	if err != nil || result.ProcessedCount != 4 || !result.HasMore {
		t.Fatalf("result = %+v, error = %v, want 4 deleted and more left", result, err)
	}
	if f.outbox.eligible != 0 || f.refreshTokens.eligible != 3 || f.key.eligible != 5 {
		t.Errorf("left = %d / %d / %d, want 0 / 3 / 5: the batch is spent in order", f.outbox.eligible, f.refreshTokens.eligible, f.key.eligible)
	}
	if !reflect.DeepEqual(f.outbox.limits, []int{4}) || !reflect.DeepEqual(f.refreshTokens.limits, []int{2}) {
		t.Errorf("limits = %v / %v, want each table asked only for what is left of the batch", f.outbox.limits, f.refreshTokens.limits)
	}
	if len(f.key.limits) != 0 {
		t.Errorf("the idempotency keys were asked with %v although the batch was spent", f.key.limits)
	}
}

func TestPurgeHasMoreWhileAnyTableStillHasEligibleRows(t *testing.T) {
	cases := map[string]struct {
		outbox, tokens, keys int
		batch                int
		wantMore             bool
	}{
		"everything fits":                 {1, 1, 1, 10, false},
		"exactly the batch":               {1, 1, 1, 3, false},
		"one outbox row left":             {3, 0, 0, 2, true},
		"the last table has rows left":    {0, 0, 4, 3, true},
		"nothing to delete":               {0, 0, 0, 5, false},
		"the batch is spent on the first": {5, 1, 1, 5, true},
	}
	for name, c := range cases {
		f := newPurgeFixture(c.outbox, c.tokens, c.keys)

		result, err := purge(f, c.batch)

		if err != nil || result.HasMore != c.wantMore {
			t.Errorf("%s: result = %+v, error = %v, want HasMore = %v", name, result, err, c.wantMore)
		}
	}
}

func TestPurgeIsIdempotent(t *testing.T) {
	f := newPurgeFixture(1, 2, 3)
	if _, err := purge(f, 500); err != nil {
		t.Fatalf("first Purge() error = %v", err)
	}

	result, err := purge(f, 500)

	if err != nil || result.ProcessedCount != 0 || result.HasMore {
		t.Errorf("second result = %+v, error = %v, want nothing deleted and nothing left", result, err)
	}
}

func TestPurgeRejectsABatchSizeOutsideOneToFiveHundredBeforeTouchingAnyTable(t *testing.T) {
	for _, batch := range []int{0, -1, 501} {
		f := newPurgeFixture(1, 1, 1)

		_, err := purge(f, batch)

		if !errors.Is(err, model.ErrInvalidPurgeBatchSize) || len(f.calls) != 0 {
			t.Errorf("batch %d: error = %v, calls = %v, want ErrInvalidPurgeBatchSize and no table touched", batch, err, f.calls)
		}
	}
}

func TestPurgeSurfacesTheFailureOfAnyTable(t *testing.T) {
	failure := errors.New("boom")
	breakers := map[string]func(*purgeFixture){
		"outbox":           func(f *purgeFixture) { f.outbox.err = failure },
		"refresh tokens":   func(f *purgeFixture) { f.refreshTokens.err = failure },
		"idempotency keys": func(f *purgeFixture) { f.key.err = failure },
	}
	for name, breakIt := range breakers {
		f := newPurgeFixture(1, 1, 1)
		breakIt(f)

		result, err := purge(f, 10)

		if !errors.Is(err, failure) || !reflect.DeepEqual(result, in.PurgeOldRecordsResult{}) {
			t.Errorf("%s: result = %+v, error = %v, want an empty result and the failure", name, result, err)
		}
	}
}
