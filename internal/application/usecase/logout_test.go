package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// fakeRevokedTokens records the entries of the revoked list and when they were written.
type fakeRevokedTokens struct {
	journal *journal
	ttls    map[string]time.Duration
	err     error
}

func (f *fakeRevokedTokens) Revoke(_ context.Context, jti string, ttl time.Duration) error {
	f.journal.record("revoke jti")
	if f.err != nil {
		return f.err
	}
	f.ttls[jti] = ttl
	return nil
}

func (f *fakeRevokedTokens) IsRevoked(_ context.Context, jti string) (bool, error) {
	_, listed := f.ttls[jti]
	return listed, f.err
}

type logoutFixture struct {
	useCase *Logout
	tokens  *storedRefreshTokens
	revoked *fakeRevokedTokens
	journal *journal
}

// newLogoutFixture stores the tokens "mine-1" and "mine-2" of user-1 and "theirs" of user-2, all
// valid for a day.
func newLogoutFixture(t *testing.T) *logoutFixture {
	t.Helper()
	journal := &journal{}
	tokens := &storedRefreshTokens{rows: map[string]*model.RefreshToken{}}
	for id, owner := range map[string]string{"mine-1": "user-1", "mine-2": "user-1", "theirs": "user-2"} {
		stored, err := model.NewRefreshToken(id, owner, "opaque-"+id, "agent", registeredAt, 24*time.Hour)
		if err != nil {
			t.Fatalf("NewRefreshToken() error = %v", err)
		}
		tokens.rows[stored.Hash()] = stored
	}
	revoked := &fakeRevokedTokens{journal: journal, ttls: map[string]time.Duration{}}
	transactions := &fakeTransactions{journal: journal}
	return &logoutFixture{useCase: NewLogout(tokens, revoked, transactions, fakeClock{}), tokens: tokens, revoked: revoked, journal: journal}
}

func (f *logoutFixture) isRevoked(id string) bool {
	return !f.tokens.rows[model.HashOpaqueToken("opaque-"+id)].IsValidAt(registeredAt)
}

func logoutOf(overrides func(*in.LogoutCommand)) in.LogoutCommand {
	command := in.LogoutCommand{UserID: "user-1", TokenID: "jti-1", ExpiresAt: registeredAt.Add(40 * time.Minute)}
	if overrides != nil {
		overrides(&command)
	}
	return command
}

func TestLogoutListsTheAccessTokenForItsRemainingLife(t *testing.T) {
	f := newLogoutFixture(t)

	if err := f.useCase.Logout(context.Background(), logoutOf(nil)); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	if f.revoked.ttls["jti-1"] != 40*time.Minute {
		t.Errorf("ttl = %v, want the remaining 40m", f.revoked.ttls["jti-1"])
	}
	if f.isRevoked("mine-1") || f.isRevoked("mine-2") {
		t.Error("the refresh tokens were revoked although none was sent")
	}
}

func TestLogoutListsATokenAboutToExpireForAtLeastOneSecond(t *testing.T) {
	f := newLogoutFixture(t)

	err := f.useCase.Logout(context.Background(), logoutOf(func(c *in.LogoutCommand) { c.ExpiresAt = registeredAt.Add(200 * time.Millisecond) }))

	if err != nil || f.revoked.ttls["jti-1"] != time.Second {
		t.Errorf("ttl = %v, error = %v, want 1s and no error", f.revoked.ttls["jti-1"], err)
	}
}

func TestLogoutRevokesThePresentedRefreshTokenOfTheUserOnly(t *testing.T) {
	f := newLogoutFixture(t)

	err := f.useCase.Logout(context.Background(), logoutOf(func(c *in.LogoutCommand) { c.RefreshToken = "opaque-mine-1" }))

	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if !f.isRevoked("mine-1") || f.isRevoked("mine-2") || f.isRevoked("theirs") {
		t.Errorf("revoked: mine-1 = %v, mine-2 = %v, theirs = %v; want only mine-1", f.isRevoked("mine-1"), f.isRevoked("mine-2"), f.isRevoked("theirs"))
	}
}

func TestLogoutWithAllDevicesRevokesEveryTokenOfTheUserAndNoOneElses(t *testing.T) {
	f := newLogoutFixture(t)

	err := f.useCase.Logout(context.Background(), logoutOf(func(c *in.LogoutCommand) {
		c.AllDevices, c.RefreshToken = true, "opaque-theirs"
	}))

	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if !f.isRevoked("mine-1") || !f.isRevoked("mine-2") || f.isRevoked("theirs") {
		t.Errorf("revoked: mine-1 = %v, mine-2 = %v, theirs = %v; want the two of user-1", f.isRevoked("mine-1"), f.isRevoked("mine-2"), f.isRevoked("theirs"))
	}
}

func TestLogoutIsNotAnErrorForARefreshTokenThatIsNotTheUsersUnknownOrAlreadyRevoked(t *testing.T) {
	for name, presented := range map[string]string{"another user's": "opaque-theirs", "unknown": "never-issued", "already revoked": "opaque-mine-2"} {
		f := newLogoutFixture(t)
		f.tokens.rows[model.HashOpaqueToken("opaque-mine-2")].Revoke(registeredAt.Add(-time.Hour))

		err := f.useCase.Logout(context.Background(), logoutOf(func(c *in.LogoutCommand) { c.RefreshToken = presented }))

		if err != nil || f.isRevoked("theirs") || f.isRevoked("mine-1") {
			t.Errorf("%s: error = %v, theirs revoked = %v, mine-1 revoked = %v; want no error and nothing else revoked", name, err, f.isRevoked("theirs"), f.isRevoked("mine-1"))
		}
		if _, listed := f.revoked.ttls["jti-1"]; !listed {
			t.Errorf("%s: the access token was not listed", name)
		}
	}
}

func TestLogoutCommitsTheRefreshTokensBeforeListingTheAccessToken(t *testing.T) {
	f := newLogoutFixture(t)

	if err := f.useCase.Logout(context.Background(), logoutOf(func(c *in.LogoutCommand) { c.AllDevices = true })); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	if got := f.journal.steps; len(got) != 3 || got[0] != "begin" || got[1] != "commit" || got[2] != "revoke jti" {
		t.Errorf("steps = %v, want begin, commit, revoke jti", got)
	}
}

func TestLogoutKeepsTheRefreshTokensRevokedWhenTheListFails(t *testing.T) {
	f := newLogoutFixture(t)
	failure := errors.New("redis down")
	f.revoked.err = failure

	err := f.useCase.Logout(context.Background(), logoutOf(func(c *in.LogoutCommand) { c.AllDevices = true }))

	if !errors.Is(err, failure) {
		t.Errorf("error = %v, want the failure of the list", err)
	}
	if !f.isRevoked("mine-1") || !f.isRevoked("mine-2") {
		t.Error("the refresh tokens were not revoked: they must stay revoked so a retry is idempotent")
	}
}

func TestLogoutDoesNotListTheAccessTokenWhenTheRevocationFails(t *testing.T) {
	f := newLogoutFixture(t)
	failure := errors.New("database down")
	f.tokens.err = failure

	err := f.useCase.Logout(context.Background(), logoutOf(func(c *in.LogoutCommand) { c.RefreshToken = "opaque-mine-1" }))

	if !errors.Is(err, failure) {
		t.Errorf("error = %v, want the failure of the database", err)
	}
	if _, listed := f.revoked.ttls["jti-1"]; listed {
		t.Error("the access token was listed although the refresh token could not be revoked")
	}
}
