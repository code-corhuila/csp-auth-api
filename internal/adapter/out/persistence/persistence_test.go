package persistence

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const userID = "6f1d2c3e-0000-4000-8000-000000000001"

func registeredEvent(t *testing.T) model.UserRegistered {
	t.Helper()
	name, _ := model.NewName("Ana Perez")
	email, _ := model.NewEmail("Ana@Example.com")
	phone, _ := model.NewPhone("+573001234567")
	address, _ := model.NewAddress("Calle 1 # 2-3")
	user, err := model.NewUser(userID, name, email, "$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234", phone, address, []model.Role{model.RoleClient})
	if err != nil {
		t.Fatalf("NewUser() error = %v", err)
	}
	occurredAt := time.Date(2026, 9, 6, 14, 0, 0, 0, time.FixedZone("COT", -5*3600))
	return model.NewUserRegistered("0a9b8c7d-0000-4000-8000-000000000002", occurredAt, user)
}

func TestEnvelopeFollowsTheEventContract(t *testing.T) {
	raw, err := userRegisteredEnvelope(registeredEvent(t))
	if err != nil {
		t.Fatalf("userRegisteredEnvelope() error = %v", err)
	}
	want := `{"eventId":"0a9b8c7d-0000-4000-8000-000000000002","eventType":"UserRegistered","occurredAt":"2026-09-06T19:00:00Z",` +
		`"version":1,"source":"auth-service","aggregateId":"` + userID + `","payload":{"userId":"` + userID + `","email":"ana@example.com","roles":["CLIENT"]}}`
	if string(raw) != want {
		t.Errorf("envelope =\n%s\nwant\n%s", raw, want)
	}
}

func TestEnvelopeNeverCarriesContactDataOrSecrets(t *testing.T) {
	raw, _ := userRegisteredEnvelope(registeredEvent(t))
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	for _, forbidden := range []string{"phone", "address", "password", "passwordHash", "3001234567", "Calle 1"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("envelope contains %q: %s", forbidden, raw)
		}
	}
}

func TestPoolConfigAppliesTheExplicitLimits(t *testing.T) {
	cfg, err := poolConfig(PoolSettings{
		URL:            "postgresql://auth_app:secret@localhost:5432/csp",
		MaxConnections: 12,
		MinConnections: 3,
		ConnectTimeout: 4 * time.Second,
		QueryTimeout:   7 * time.Second,
	})
	if err != nil {
		t.Fatalf("poolConfig() error = %v", err)
	}
	if cfg.MaxConns != 12 || cfg.MinConns != 3 || cfg.ConnConfig.ConnectTimeout != 4*time.Second {
		t.Errorf("limits not applied: max=%d min=%d connect=%v", cfg.MaxConns, cfg.MinConns, cfg.ConnConfig.ConnectTimeout)
	}
	if got := cfg.ConnConfig.RuntimeParams["statement_timeout"]; got != "7000" {
		t.Errorf("statement_timeout = %q, want 7000", got)
	}
}

func TestPoolConfigRejectsAnInvalidURL(t *testing.T) {
	if _, err := poolConfig(PoolSettings{URL: "not a url"}); err == nil {
		t.Error("poolConfig() error = nil, want an error")
	}
}

func TestIsDuplicateEmailOnlyMatchesTheEmailIndex(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"email index":        {&pgconn.PgError{Code: "23505", ConstraintName: "uk_app_user_email"}, true},
		"other unique index": {&pgconn.PgError{Code: "23505", ConstraintName: "pk_app_user"}, false},
		"other error code":   {&pgconn.PgError{Code: "23514", ConstraintName: "uk_app_user_email"}, false},
		"not a postgres err": {errors.New("boom"), false},
		"no error":           {nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := isDuplicateEmail(tc.err); got != tc.want {
				t.Errorf("isDuplicateEmail() = %v, want %v", got, tc.want)
			}
		})
	}
}
