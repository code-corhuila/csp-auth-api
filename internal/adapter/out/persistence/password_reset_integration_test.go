//go:build integration

package persistence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/security"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/application/usecase"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const resetPassword = "NewSecret123"

// recordingResetSender keeps what the use case hands to the sender, so a test knows the raw token.
type recordingResetSender struct {
	mu         sync.Mutex
	deliveries []out.PasswordResetDelivery
}

func (s *recordingResetSender) Send(_ context.Context, delivery out.PasswordResetDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries = append(s.deliveries, delivery)
	return nil
}

func (s *recordingResetSender) tokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw []string
	for _, delivery := range s.deliveries {
		raw = append(raw, delivery.Token.Reveal())
	}
	return raw
}

type failingRevoker struct{ err error }

func (r failingRevoker) RevokeAllActiveByUser(context.Context, string, time.Time) (int, error) {
	return 0, r.err
}

func (f fixture) passwordResets() *PasswordResetRepository { return NewPasswordResetRepository(f.pool) }

func (f fixture) requestPasswordReset(sender out.PasswordResetSender) *usecase.RequestPasswordReset {
	return usecase.NewRequestPasswordReset(usecase.RequestPasswordResetPorts{
		Users: f.users, Resets: f.passwordResets(), Tokens: system.ResetTokenGenerator{}, Sender: sender,
		IDs: system.UUIDGenerator{}, Clock: system.Clock{}, Transactions: f.transactions,
	})
}

func (f fixture) resetPassword(sessions out.RefreshTokenRevoker) *usecase.ResetPassword {
	return usecase.NewResetPassword(usecase.ResetPasswordPorts{
		Resets: f.passwordResets(), Hasher: security.NewBcryptHasher(4), Passwords: f.users, Sessions: sessions,
		Clock: system.Clock{}, Transactions: f.transactions,
	})
}

type resetRow struct {
	hash               string
	pending, used, old bool
}

func (f fixture) resetRows(t *testing.T, ctx context.Context, userID string) []resetRow {
	t.Helper()
	rows, err := f.pool.Query(ctx,
		`SELECT token_hash, used_at IS NOT NULL, deleted_at IS NOT NULL FROM auth.password_reset WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		t.Fatalf("password_reset query error = %v", err)
	}
	defer rows.Close()
	var result []resetRow
	for rows.Next() {
		var row resetRow
		var deleted bool
		if err := rows.Scan(&row.hash, &row.used, &deleted); err != nil {
			t.Fatal(err)
		}
		row.old, row.pending = deleted, !deleted && !row.used
		result = append(result, row)
	}
	return result
}

func pendingResets(rows []resetRow) int {
	count := 0
	for _, row := range rows {
		if row.pending {
			count++
		}
	}
	return count
}

func (f fixture) passwordHash(t *testing.T, ctx context.Context, userID string) string {
	t.Helper()
	var hash string
	if err := f.pool.QueryRow(ctx, `SELECT password_hash FROM auth.app_user WHERE id = $1`, userID).Scan(&hash); err != nil {
		t.Fatalf("app_user query error = %v", err)
	}
	return hash
}

// openSessions stores n active refresh tokens of the user.
func (f fixture) openSessions(t *testing.T, ctx context.Context, userID string, n int) {
	t.Helper()
	for range n {
		opaque, err := model.NewOpaqueToken()
		if err != nil {
			t.Fatal(err)
		}
		token, err := model.NewRefreshToken(newUUID(t), userID, opaque, "test", time.Now().UTC(), 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := NewRefreshTokenRepository(f.pool).Save(ctx, token); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}
}

func (f fixture) activeSessions(t *testing.T, ctx context.Context, userID string) int {
	t.Helper()
	var active int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth.refresh_token WHERE user_id = $1 AND revoked_at IS NULL`, userID).Scan(&active); err != nil {
		t.Fatalf("refresh_token query error = %v", err)
	}
	return active
}

func requestFor(user *model.User) in.RequestPasswordResetCommand {
	return in.RequestPasswordResetCommand{Email: user.Email().String()}
}

func TestRequestStoresOnlyTheDigestOfTheTokenItDelivers(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	sender := &recordingResetSender{}

	if err := f.requestPasswordReset(sender).RequestReset(ctx, requestFor(user)); err != nil {
		t.Fatalf("RequestReset() error = %v", err)
	}

	tokens := sender.tokens()
	rows := f.resetRows(t, ctx, user.ID())
	if len(tokens) != 1 || len(rows) != 1 || !rows[0].pending || rows[0].hash != model.HashOpaqueToken(tokens[0]) || rows[0].hash == tokens[0] {
		t.Fatalf("tokens = %v, rows = %+v, want one pending row holding only the digest of the delivered token", tokens, rows)
	}
	var expiresAt, createdAt time.Time
	if err := f.pool.QueryRow(ctx, `SELECT expires_at, created_at FROM auth.password_reset WHERE user_id = $1`, user.ID()).Scan(&expiresAt, &createdAt); err != nil {
		t.Fatal(err)
	}
	if expiresAt.Sub(createdAt) != time.Hour || time.Since(createdAt) > time.Minute {
		t.Errorf("created %v, expires %v, want a request of now that lasts one hour", createdAt, expiresAt)
	}
}

func TestANewRequestSupersedesThePreviousTokenAndTheFourthInAnHourCreatesNothing(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	sender := &recordingResetSender{}
	request := f.requestPasswordReset(sender)

	for i := range 4 {
		if err := request.RequestReset(ctx, requestFor(user)); err != nil {
			t.Fatalf("request %d error = %v, want the same success every time", i+1, err)
		}
	}

	tokens := sender.tokens()
	rows := f.resetRows(t, ctx, user.ID())
	if len(tokens) != 3 || len(rows) != 3 || pendingResets(rows) != 1 || !rows[0].old || !rows[1].old || !rows[2].pending {
		t.Fatalf("tokens = %d, rows = %+v, want three requests of which only the last one is pending and no message for the fourth", len(tokens), rows)
	}
	err := f.resetPassword(NewRefreshTokenRepository(f.pool)).Reset(ctx, in.ResetPasswordCommand{Token: tokens[0], Password: resetPassword})
	if !errors.Is(err, model.ErrPasswordResetRejected) {
		t.Errorf("Reset() with a superseded token error = %v, want ErrPasswordResetRejected", err)
	}
}

func TestConcurrentRequestsOfOneUserLeaveOnePendingToken(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	sender := &recordingResetSender{}
	request := f.requestPasswordReset(sender)

	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = request.RequestReset(ctx, requestFor(user))
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("request %d error = %v, want nil: the requests are serialized, not failed", i+1, err)
		}
	}
	if rows := f.resetRows(t, ctx, user.ID()); len(rows) != 3 || pendingResets(rows) != 1 {
		t.Errorf("rows = %+v, want three requests with one pending", rows)
	}
}

func TestUnknownAndLockedAccountsGetTheSameSuccessAndNothingIsStored(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	locked := f.registeredUser(t, ctx)
	if _, err := f.pool.Exec(ctx, `UPDATE auth.app_user SET status = 'LOCKED' WHERE id = $1`, locked.ID()); err != nil {
		t.Fatalf("lock error = %v", err)
	}
	sender := &recordingResetSender{}
	request := f.requestPasswordReset(sender)

	unknownErr := request.RequestReset(ctx, in.RequestPasswordResetCommand{Email: uniqueEmail(t)})
	lockedErr := request.RequestReset(ctx, requestFor(locked))

	if unknownErr != nil || lockedErr != nil || len(sender.tokens()) != 0 || len(f.resetRows(t, ctx, locked.ID())) != 0 {
		t.Errorf("errors = %v / %v, tokens = %d, rows = %d, want success for both and nothing stored or sent",
			unknownErr, lockedErr, len(sender.tokens()), len(f.resetRows(t, ctx, locked.ID())))
	}
}

func TestResetChangesTheHashConsumesTheTokenAndRevokesEverySessionOfTheUserOnly(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user, other := f.registeredUser(t, ctx), f.registeredUser(t, ctx)
	f.openSessions(t, ctx, user.ID(), 2)
	f.openSessions(t, ctx, other.ID(), 1)
	sender := &recordingResetSender{}
	if err := f.requestPasswordReset(sender).RequestReset(ctx, requestFor(user)); err != nil {
		t.Fatalf("RequestReset() error = %v", err)
	}
	command := in.ResetPasswordCommand{Token: sender.tokens()[0], Password: resetPassword}
	reset := f.resetPassword(NewRefreshTokenRepository(f.pool))

	if err := reset.Reset(ctx, command); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}

	hash := f.passwordHash(t, ctx, user.ID())
	if hash == bcryptHash || !security.NewBcryptHasher(4).Verify(hash, resetPassword) {
		t.Errorf("password hash = %q, want the bcrypt hash of the new password", hash)
	}
	if rows := f.resetRows(t, ctx, user.ID()); len(rows) != 1 || !rows[0].used || pendingResets(rows) != 0 {
		t.Errorf("rows = %+v, want the request consumed", rows)
	}
	if active, otherActive := f.activeSessions(t, ctx, user.ID()), f.activeSessions(t, ctx, other.ID()); active != 0 || otherActive != 1 {
		t.Errorf("active sessions = %d of the user and %d of another user, want 0 and 1", active, otherActive)
	}
	if err := reset.Reset(ctx, command); !errors.Is(err, model.ErrPasswordResetRejected) {
		t.Errorf("replay error = %v, want ErrPasswordResetRejected", err)
	}
	if again := f.passwordHash(t, ctx, user.ID()); again != hash {
		t.Error("the replay changed the password hash")
	}
}

func TestResetIsAllOrNothingAndTheTokenStaysUsableAfterAFailure(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	f.openSessions(t, ctx, user.ID(), 2)
	sender := &recordingResetSender{}
	if err := f.requestPasswordReset(sender).RequestReset(ctx, requestFor(user)); err != nil {
		t.Fatalf("RequestReset() error = %v", err)
	}
	command := in.ResetPasswordCommand{Token: sender.tokens()[0], Password: resetPassword}
	failure := errors.New("revocation failed")

	err := f.resetPassword(failingRevoker{err: failure}).Reset(ctx, command)

	if !errors.Is(err, failure) {
		t.Fatalf("Reset() error = %v, want %v", err, failure)
	}
	if hash := f.passwordHash(t, ctx, user.ID()); hash != bcryptHash {
		t.Error("the password changed although the revocation failed")
	}
	if rows := f.resetRows(t, ctx, user.ID()); len(rows) != 1 || !rows[0].pending {
		t.Errorf("rows = %+v, want the token still pending", rows)
	}
	if active := f.activeSessions(t, ctx, user.ID()); active != 2 {
		t.Errorf("active sessions = %d, want 2", active)
	}
	if err := f.resetPassword(NewRefreshTokenRepository(f.pool)).Reset(ctx, command); err != nil {
		t.Errorf("Reset() after the failure error = %v, want the token to work", err)
	}
}

func TestAWeakPasswordDoesNotConsumeTheToken(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	user := f.registeredUser(t, ctx)
	sender := &recordingResetSender{}
	if err := f.requestPasswordReset(sender).RequestReset(ctx, requestFor(user)); err != nil {
		t.Fatalf("RequestReset() error = %v", err)
	}
	reset, token := f.resetPassword(NewRefreshTokenRepository(f.pool)), sender.tokens()[0]

	weakErr := reset.Reset(ctx, in.ResetPasswordCommand{Token: token, Password: "weak"})
	strongErr := reset.Reset(ctx, in.ResetPasswordCommand{Token: token, Password: resetPassword})

	if !errors.Is(weakErr, model.ErrWeakPassword) || strongErr != nil {
		t.Errorf("errors = %v / %v, want ErrWeakPassword and then success with the same token", weakErr, strongErr)
	}
}

func TestResetRejectsExpiredTokensAndTokensOfAccountsThatAreNotActive(t *testing.T) {
	f, ctx := newFixture(t), context.Background()
	repository := f.passwordResets()
	store := func(user *model.User, requestedAt time.Time) string {
		raw, err := model.NewOpaqueToken()
		if err != nil {
			t.Fatal(err)
		}
		token, _ := model.NewResetToken(raw)
		stored := model.NewPasswordReset(newUUID(t), user.ID(), token, requestedAt)
		if err := repository.Add(ctx, stored); err != nil {
			t.Fatalf("Add() error = %v", err)
		}
		return raw
	}
	expiredUser, lockedUser, deletedUser := f.registeredUser(t, ctx), f.registeredUser(t, ctx), f.registeredUser(t, ctx)
	cases := map[string]string{
		"expired":         store(expiredUser, time.Now().Add(-2*time.Hour)),
		"locked account":  store(lockedUser, time.Now()),
		"deleted account": store(deletedUser, time.Now()),
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.app_user SET status = 'LOCKED' WHERE id = $1`, lockedUser.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE auth.app_user SET deleted_at = NOW() WHERE id = $1`, deletedUser.ID()); err != nil {
		t.Fatal(err)
	}

	for name, raw := range cases {
		err := f.resetPassword(NewRefreshTokenRepository(f.pool)).Reset(ctx, in.ResetPasswordCommand{Token: raw, Password: resetPassword})
		if !errors.Is(err, model.ErrPasswordResetRejected) {
			t.Errorf("%s: Reset() error = %v, want ErrPasswordResetRejected", name, err)
		}
	}
	unknown, _ := model.NewOpaqueToken()
	if err := f.resetPassword(NewRefreshTokenRepository(f.pool)).Reset(ctx, in.ResetPasswordCommand{Token: unknown, Password: resetPassword}); !errors.Is(err, model.ErrPasswordResetRejected) {
		t.Errorf("unknown token: Reset() error = %v, want ErrPasswordResetRejected", err)
	}
}

func TestUpdatePasswordHashOfAnAccountThatDoesNotExistIsNotFound(t *testing.T) {
	f, ctx := newFixture(t), context.Background()

	err := f.users.UpdatePasswordHash(ctx, newUUID(t), bcryptHash, time.Now())

	if !errors.Is(err, model.ErrUserNotFound) {
		t.Errorf("UpdatePasswordHash() error = %v, want ErrUserNotFound", err)
	}
}
