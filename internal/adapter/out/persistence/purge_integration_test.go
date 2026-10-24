//go:build integration

package persistence

import (
	"context"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// purgeLockKey serializes the tests that purge, in every test package: a purge deletes any old row
// of the shared test database, including the rows that another test has just seeded.
const purgeLockKey = 3012

const day = 24 * time.Hour

// purgeFixture holds the advisory lock for the whole test and empties the five tables of old
// rows first, so the counts of the test are its own.
type purgeFixture struct {
	fixture
	outbox, tokens, keys, verifications, resets *agedRows
}

func newPurgeFixture(t *testing.T) purgeFixture {
	t.Helper()
	f, ctx := newFixture(t), context.Background()
	conn, err := f.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire a connection: %v", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, purgeLockKey); err != nil {
		t.Fatalf("take the purge lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, purgeLockKey)
		conn.Release()
	})
	p := purgeFixture{
		fixture:       f,
		outbox:        NewOutboxPurger(f.pool).(*agedRows),
		tokens:        NewRefreshTokenPurger(f.pool).(*agedRows),
		keys:          NewIdempotencyKeyPurger(f.pool).(*agedRows),
		verifications: NewEmailVerificationPurger(f.pool).(*agedRows),
		resets:        NewPasswordResetPurger(f.pool).(*agedRows),
	}
	p.drain(t)
	return p
}

func (p purgeFixture) drain(t *testing.T) {
	t.Helper()
	now := time.Now()
	for _, step := range []struct {
		records *agedRows
		cutoff  time.Time
	}{{p.outbox, now.Add(-30 * day)}, {p.tokens, now.Add(-30 * day)}, {p.keys, now.Add(-7 * day)}, {p.verifications, now.Add(-7 * day)}, {p.resets, now.Add(-7 * day)}} {
		for {
			deleted, err := step.records.DeleteOlderThan(context.Background(), step.cutoff, 500)
			if err != nil {
				t.Fatalf("empty %s: %v", step.records.table, err)
			}
			if deleted == 0 {
				break
			}
		}
	}
}

func (p purgeFixture) seedOutbox(t *testing.T, age time.Duration) string {
	t.Helper()
	id := newUUID(t)
	_, err := p.pool.Exec(context.Background(),
		`INSERT INTO auth.outbox_event (id, aggregate_type, aggregate_id, event_type, payload, created_at)
		 VALUES ($1, 'User', $2, 'UserRegistered', '{}', $3)`, id, newUUID(t), time.Now().Add(-age))
	if err != nil {
		t.Fatalf("seed an outbox event: %v", err)
	}
	return id
}

// seedToken stores a refresh token that expired expiredAgo ago and, if revokedAgo is positive,
// was revoked revokedAgo ago.
func (p purgeFixture) seedToken(t *testing.T, expiredAgo, revokedAgo time.Duration) string {
	t.Helper()
	ctx := context.Background()
	token, _ := saveToken(t, p.fixture, ctx, NewRefreshTokenRepository(p.pool))
	var revokedAt *time.Time
	if revokedAgo > 0 {
		at := time.Now().Add(-revokedAgo)
		revokedAt = &at
	}
	if _, err := p.pool.Exec(ctx, `UPDATE auth.refresh_token SET expires_at = $2, revoked_at = $3 WHERE id = $1`,
		token.ID(), time.Now().Add(-expiredAgo), revokedAt); err != nil {
		t.Fatalf("age a refresh token: %v", err)
	}
	return token.ID()
}

func (p purgeFixture) seedKey(t *testing.T, age time.Duration) string {
	t.Helper()
	user := newUser(t, uniqueEmail(t))
	if err := p.register(t, context.Background(), user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	key := "purge-" + newUUID(t)
	if _, err := p.pool.Exec(context.Background(),
		`INSERT INTO auth.idempotency_key (key, user_id, request_hash, created_at) VALUES ($1, $2, 'hash', $3)`,
		key, user.ID(), time.Now().Add(-age)); err != nil {
		t.Fatalf("seed an idempotency key: %v", err)
	}
	return key
}

// seedVerification stores an email change request that expired expiredAgo ago and, if verified,
// was confirmed. Each one belongs to a user of its own because only one request per user is pending.
func (p purgeFixture) seedVerification(t *testing.T, expiredAgo time.Duration, verified bool) string {
	t.Helper()
	user := newUser(t, uniqueEmail(t))
	if err := p.register(t, context.Background(), user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	id := newUUID(t)
	expiresAt := time.Now().Add(-expiredAgo)
	var verifiedAt *time.Time
	if verified {
		verifiedAt = &expiresAt
	}
	if _, err := p.pool.Exec(context.Background(),
		`INSERT INTO auth.email_verification (id, user_id, verification_code, expires_at, verified_at, new_email)
		 VALUES ($1, $2, '123456', $3, $4, 'purge-target@example.com')`,
		id, user.ID(), expiresAt, verifiedAt); err != nil {
		t.Fatalf("seed an email verification: %v", err)
	}
	return id
}

// seedReset stores a password reset that expired expiredAgo ago and, if used, was consumed. Each one belongs to a
// user of its own, as only one request per user is pending.
func (p purgeFixture) seedReset(t *testing.T, expiredAgo time.Duration, used bool) string {
	t.Helper()
	user := newUser(t, uniqueEmail(t))
	if err := p.register(t, context.Background(), user); err != nil {
		t.Fatalf("register error = %v", err)
	}
	id := newUUID(t)
	expiresAt := time.Now().Add(-expiredAgo)
	var usedAt *time.Time
	if used {
		usedAt = &expiresAt
	}
	if _, err := p.pool.Exec(context.Background(),
		`INSERT INTO auth.password_reset (id, user_id, token_hash, expires_at, used_at) VALUES ($1, $2, $3, $4, $5)`,
		id, user.ID(), model.HashOpaqueToken(id), expiresAt, usedAt); err != nil {
		t.Fatalf("seed a password reset: %v", err)
	}
	return id
}

func (p purgeFixture) present(t *testing.T, table, column, id string) bool {
	t.Helper()
	var found bool
	if err := p.pool.QueryRow(context.Background(), "SELECT EXISTS (SELECT 1 FROM "+table+" WHERE "+column+"::text = $1)", id).Scan(&found); err != nil {
		t.Fatalf("look for %s in %s: %v", id, table, err)
	}
	return found
}

func TestOutboxPurgerDeletesOnlyEventsOlderThanTheCutoffAndOnlyUpToTheLimit(t *testing.T) {
	p, ctx := newPurgeFixture(t), context.Background()
	old := []string{p.seedOutbox(t, 31*day), p.seedOutbox(t, 32*day), p.seedOutbox(t, 33*day)}
	young := []string{p.seedOutbox(t, 29*day), p.seedOutbox(t, time.Minute)}
	cutoff := time.Now().Add(-30 * day)

	first, err := p.outbox.DeleteOlderThan(ctx, cutoff, 2)
	if err != nil || first != 2 {
		t.Fatalf("DeleteOlderThan(limit 2) = %d, %v, want 2", first, err)
	}
	if left, _ := p.outbox.ExistOlderThan(ctx, cutoff); !left {
		t.Error("ExistOlderThan() = false, want true: one old event is left")
	}
	if !p.present(t, "auth.outbox_event", "id", old[0]) {
		t.Error("the oldest events go first: the youngest of the old ones should be the one left")
	}
	rest, err := p.outbox.DeleteOlderThan(ctx, cutoff, 10)
	if err != nil || rest != 1 {
		t.Fatalf("DeleteOlderThan(limit 10) = %d, %v, want the 1 left", rest, err)
	}
	if again, _ := p.outbox.DeleteOlderThan(ctx, cutoff, 10); again != 0 {
		t.Errorf("a repeated call deleted %d, want 0", again)
	}
	if left, _ := p.outbox.ExistOlderThan(ctx, cutoff); left {
		t.Error("ExistOlderThan() = true, want false")
	}
	for _, id := range young {
		if !p.present(t, "auth.outbox_event", "id", id) {
			t.Errorf("event %s younger than the cutoff was deleted", id)
		}
	}
}

func TestRefreshTokenPurgerDeletesTokensExpiredOrRevokedBeforeTheCutoff(t *testing.T) {
	p, ctx := newPurgeFixture(t), context.Background()
	expired := p.seedToken(t, 31*day, 0)
	revoked := p.seedToken(t, -day, 31*day)
	survivors := map[string]string{
		"expired recently":  p.seedToken(t, 29*day, 0),
		"revoked recently":  p.seedToken(t, -day, 29*day),
		"active":            p.seedToken(t, -day, 0),
		"expired, revoked":  p.seedToken(t, 29*day, 28*day),
		"revoked but alive": p.seedToken(t, -6*day, time.Minute),
	}

	deleted, err := p.tokens.DeleteOlderThan(ctx, time.Now().Add(-30*day), 100)

	if err != nil || deleted != 2 {
		t.Fatalf("DeleteOlderThan() = %d, %v, want 2", deleted, err)
	}
	for name, id := range map[string]string{"expired long ago": expired, "revoked long ago": revoked} {
		if p.present(t, "auth.refresh_token", "id", id) {
			t.Errorf("token %s was not deleted", name)
		}
	}
	for name, id := range survivors {
		if !p.present(t, "auth.refresh_token", "id", id) {
			t.Errorf("token %s was deleted", name)
		}
	}
}

func TestIdempotencyKeyPurgerDeletesOnlyKeysOlderThanTheCutoff(t *testing.T) {
	p, ctx := newPurgeFixture(t), context.Background()
	old, young := p.seedKey(t, 8*day), p.seedKey(t, 6*day)
	cutoff := time.Now().Add(-7 * day)

	deleted, err := p.keys.DeleteOlderThan(ctx, cutoff, 100)

	if err != nil || deleted != 1 || p.present(t, "auth.idempotency_key", "key", old) || !p.present(t, "auth.idempotency_key", "key", young) {
		t.Errorf("deleted = %d, error = %v, want only the key of 8 days to go", deleted, err)
	}
	if left, _ := p.keys.ExistOlderThan(ctx, cutoff); left {
		t.Error("ExistOlderThan() = true, want false")
	}
}

func TestPurgeUseCaseOverTheRealTablesIsBoundedByTheBatchSizeAndFinishesInTwoCalls(t *testing.T) {
	p, ctx := newPurgeFixture(t), context.Background()
	outbox := []string{p.seedOutbox(t, 31*day), p.seedOutbox(t, 32*day)}
	tokens := []string{p.seedToken(t, 31*day, 0), p.seedToken(t, 40*day, 0)}
	keys := []string{p.seedKey(t, 8*day), p.seedKey(t, 9*day)}
	youngKey := p.seedKey(t, day)
	verifications := []string{p.seedVerification(t, 8*day, false), p.seedVerification(t, 9*day, true)}
	youngVerification := p.seedVerification(t, 6*day, false)
	resets := []string{p.seedReset(t, 8*day, false), p.seedReset(t, 9*day, true)}
	youngReset := p.seedReset(t, 6*day, false)
	purge := usecase.NewPurgeOldRecords(p.outbox, p.tokens, p.keys, p.verifications, p.resets, system.Clock{})

	first, err := purge.Purge(ctx, in.PurgeOldRecordsCommand{BatchSize: 3})

	if err != nil || first.ProcessedCount != 3 || !first.HasMore {
		t.Fatalf("first Purge() = %+v, %v, want 3 deleted and more left", first, err)
	}
	for _, id := range outbox {
		if p.present(t, "auth.outbox_event", "id", id) {
			t.Errorf("outbox event %s should go first", id)
		}
	}
	second, err := purge.Purge(ctx, in.PurgeOldRecordsCommand{BatchSize: model.MaxPurgeBatchSize})
	if err != nil || second.ProcessedCount != 7 || second.HasMore {
		t.Fatalf("second Purge() = %+v, %v, want the 7 left and nothing more", second, err)
	}
	third, err := purge.Purge(ctx, in.PurgeOldRecordsCommand{BatchSize: 10})
	if err != nil || third.ProcessedCount != 0 || third.HasMore {
		t.Errorf("third Purge() = %+v, %v, want nothing to do", third, err)
	}
	for _, id := range tokens {
		if p.present(t, "auth.refresh_token", "id", id) {
			t.Errorf("refresh token %s was not deleted", id)
		}
	}
	for _, key := range keys {
		if p.present(t, "auth.idempotency_key", "key", key) {
			t.Errorf("idempotency key %s was not deleted", key)
		}
	}
	if !p.present(t, "auth.idempotency_key", "key", youngKey) {
		t.Error("the idempotency key of one day was deleted")
	}
	for _, id := range verifications {
		if p.present(t, "auth.email_verification", "id", id) {
			t.Errorf("email verification %s was not deleted", id)
		}
	}
	if !p.present(t, "auth.email_verification", "id", youngVerification) {
		t.Error("the email verification that expired 6 days ago was deleted")
	}
	for _, id := range resets {
		if p.present(t, "auth.password_reset", "id", id) {
			t.Errorf("password reset %s was not deleted", id)
		}
	}
	if !p.present(t, "auth.password_reset", "id", youngReset) {
		t.Error("the password reset that expired 6 days ago was deleted")
	}
}

func TestPasswordResetPurgerDeletesResetsExpiredBeforeTheCutoffWhetherUsedOrNot(t *testing.T) {
	p, ctx := newPurgeFixture(t), context.Background()
	cutoff := time.Now().Add(-7 * day)
	old := map[string]string{
		"unused, expired 8 days ago": p.seedReset(t, 8*day, false),
		"used, expired 9 days ago":   p.seedReset(t, 9*day, true),
	}
	survivors := map[string]string{
		"expired 6 days ago, unused": p.seedReset(t, 6*day, false),
		"expired 6 days ago, used":   p.seedReset(t, 6*day, true),
		"still pending":              p.seedReset(t, -10*time.Minute, false),
	}

	first, err := p.resets.DeleteOlderThan(ctx, cutoff, 1)
	if err != nil || first != 1 {
		t.Fatalf("DeleteOlderThan(limit 1) = %d, %v, want 1", first, err)
	}
	if left, _ := p.resets.ExistOlderThan(ctx, cutoff); !left {
		t.Error("ExistOlderThan() = false, want true: one old reset is left")
	}
	if !p.present(t, "auth.password_reset", "id", old["unused, expired 8 days ago"]) {
		t.Error("the oldest resets go first: the youngest of the old ones should be the one left")
	}
	if rest, err := p.resets.DeleteOlderThan(ctx, cutoff, 5); err != nil || rest != 1 {
		t.Fatalf("second DeleteOlderThan(limit 5) = %d, %v, want the 1 left", rest, err)
	}
	if left, _ := p.resets.ExistOlderThan(ctx, cutoff); left {
		t.Error("ExistOlderThan() = true, want false")
	}
	for name, id := range old {
		if p.present(t, "auth.password_reset", "id", id) {
			t.Errorf("reset %s was not deleted", name)
		}
	}
	for name, id := range survivors {
		if !p.present(t, "auth.password_reset", "id", id) {
			t.Errorf("reset %s was deleted", name)
		}
	}
}

func TestPurgersDeleteTheOldestRowsUpToTheLimitAndKeepTheYoungOnesAcrossRepeatedCalls(t *testing.T) {
	p, ctx := newPurgeFixture(t), context.Background()
	tokenCutoff, keyCutoff := time.Now().Add(-30*day), time.Now().Add(-7*day)
	oldTokens := []string{p.seedToken(t, 33*day, 0), p.seedToken(t, 31*day, 0), p.seedToken(t, -day, 32*day)}
	youngToken := p.seedToken(t, 29*day, 0)
	oldKeys := []string{p.seedKey(t, 10*day), p.seedKey(t, 9*day), p.seedKey(t, 8*day)}
	youngKey := p.seedKey(t, 6*day)

	for name, run := range map[string]func(limit int) (int, error){
		"tokens": func(limit int) (int, error) { return p.tokens.DeleteOlderThan(ctx, tokenCutoff, limit) },
		"keys":   func(limit int) (int, error) { return p.keys.DeleteOlderThan(ctx, keyCutoff, limit) },
	} {
		if first, err := run(2); err != nil || first != 2 {
			t.Fatalf("%s: DeleteOlderThan(limit 2) = %d, %v, want 2", name, first, err)
		}
		if rest, err := run(2); err != nil || rest != 1 {
			t.Fatalf("%s: second DeleteOlderThan(limit 2) = %d, %v, want the 1 left", name, rest, err)
		}
		if again, err := run(2); err != nil || again != 0 {
			t.Errorf("%s: a repeated call deleted %d, %v, want 0", name, again, err)
		}
	}
	for _, id := range oldTokens {
		if p.present(t, "auth.refresh_token", "id", id) {
			t.Errorf("token %s older than the cutoff was not deleted", id)
		}
	}
	for _, key := range oldKeys {
		if p.present(t, "auth.idempotency_key", "key", key) {
			t.Errorf("key %s older than the cutoff was not deleted", key)
		}
	}
	if !p.present(t, "auth.refresh_token", "id", youngToken) || !p.present(t, "auth.idempotency_key", "key", youngKey) {
		t.Error("a row younger than the cutoff was deleted")
	}
}

func TestEmailVerificationPurgerDeletesRequestsExpiredBeforeTheCutoffWhetherVerifiedOrNot(t *testing.T) {
	p, ctx := newPurgeFixture(t), context.Background()
	cutoff := time.Now().Add(-7 * day)
	old := map[string]string{
		"unverified, expired 8 days ago":  p.seedVerification(t, 8*day, false),
		"verified, expired 9 days ago":    p.seedVerification(t, 9*day, true),
		"unverified, expired 10 days ago": p.seedVerification(t, 10*day, false),
	}
	survivors := map[string]string{
		"expired 6 days ago, unverified": p.seedVerification(t, 6*day, false),
		"expired 6 days ago, verified":   p.seedVerification(t, 6*day, true),
		"still pending":                  p.seedVerification(t, -10*time.Minute, false),
	}

	first, err := p.verifications.DeleteOlderThan(ctx, cutoff, 2)
	if err != nil || first != 2 {
		t.Fatalf("DeleteOlderThan(limit 2) = %d, %v, want 2", first, err)
	}
	if left, _ := p.verifications.ExistOlderThan(ctx, cutoff); !left {
		t.Error("ExistOlderThan() = false, want true: one old request is left")
	}
	if !p.present(t, "auth.email_verification", "id", old["unverified, expired 8 days ago"]) {
		t.Error("the oldest requests go first: the youngest of the old ones should be the one left")
	}
	if rest, err := p.verifications.DeleteOlderThan(ctx, cutoff, 2); err != nil || rest != 1 {
		t.Fatalf("second DeleteOlderThan(limit 2) = %d, %v, want the 1 left", rest, err)
	}
	if again, err := p.verifications.DeleteOlderThan(ctx, cutoff, 2); err != nil || again != 0 {
		t.Errorf("a repeated call deleted %d, %v, want 0", again, err)
	}
	if left, _ := p.verifications.ExistOlderThan(ctx, cutoff); left {
		t.Error("ExistOlderThan() = true, want false")
	}
	for name, id := range old {
		if p.present(t, "auth.email_verification", "id", id) {
			t.Errorf("request %s was not deleted", name)
		}
	}
	for name, id := range survivors {
		if !p.present(t, "auth.email_verification", "id", id) {
			t.Errorf("request %s was deleted", name)
		}
	}
}
