//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/config"
)

const (
	confirmationPortalURL = "https://portal.cinesync.local/confirm-registration"
	confirmPath           = "/api/v1/auth/register/confirm"
)

var tokenInMessage = regexp.MustCompile(`#token=([0-9a-f-]{36})`)

// registrationRelay is the relay that the registrations of the running test write to; registerAccount reads the
// confirmation link from it the way a person reads the message in Mailpit.
var registrationRelay *fakeSMTP

// useRegistrationRelay points the registration messages of cfg at a new in-process relay and makes registerAccount read it.
func useRegistrationRelay(t *testing.T, cfg *config.Config) *fakeSMTP {
	t.Helper()
	relay := startFakeSMTP(t)
	relay.configure(cfg)
	shareRelayWithRegistration(t, cfg, relay)
	return relay
}

// shareRelayWithRegistration makes the registration messages of cfg go to a relay that the test already uses for other mail.
func shareRelayWithRegistration(t *testing.T, cfg *config.Config, relay *fakeSMTP) {
	t.Helper()
	cfg.RegistrationConfirmURL = confirmationPortalURL
	registrationRelay = relay
	t.Cleanup(func() { registrationRelay = nil })
}

// waitForMessage returns the last message sent to address, waiting for the queue of the sender to deliver it.
func (f *fakeSMTP) waitForMessage(t *testing.T, address string) string {
	t.Helper()
	return f.waitForMessageMatching(t, address, regexp.MustCompile(``))
}

// waitForMessageMatching waits until the last message sent to address matches pattern: the relay keeps one message per
// address, so an older one (a verification code, a notice) may still be there while the awaited one is queued.
func (f *fakeSMTP) waitForMessageMatching(t *testing.T, address string, pattern *regexp.Regexp) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		raw, found := f.messages[address]
		f.mu.Unlock()
		if found {
			message, err := mail.ReadMessage(strings.NewReader(raw))
			if err != nil {
				t.Fatalf("the message to %s cannot be read: %v", address, err)
			}
			body, _ := io.ReadAll(quotedprintable.NewReader(message.Body))
			if pattern.Match(body) {
				return string(body)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no message to %s that matches %q after 10 seconds", address, pattern)
	return ""
}

// tokenFor returns the token of the confirmation link in the last message sent to address.
func (f *fakeSMTP) tokenFor(t *testing.T, address string) string {
	t.Helper()
	return tokenInMessage.FindStringSubmatch(f.waitForMessageMatching(t, address, tokenInMessage))[1]
}

// registerAccount registers body and confirms it with the link of the message, and answers what the confirmation answered
// (201 with the tokens), so a test that needs an account keeps reading as before. The confirmation uses the same
// Idempotency-Key: the two keys live in different tables.
func registerAccount(t *testing.T, baseURL, idempotencyKey, body string) (int, map[string]any) {
	t.Helper()
	status, payload, _ := registerAccountToken(t, baseURL, idempotencyKey, body)
	return status, payload
}

// registerAccountToken is registerAccount that also returns the token of the link.
func registerAccountToken(t *testing.T, baseURL, idempotencyKey, body string) (int, map[string]any, string) {
	t.Helper()
	if registrationRelay == nil {
		t.Fatal("the test did not call useRegistrationRelay")
	}
	status, payload := register(t, baseURL, idempotencyKey, body)
	if status != http.StatusCreated {
		t.Fatalf("register status = %d, want 201; body = %v", status, payload)
	}
	var request struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatalf("the body of the registration is not JSON: %v", err)
	}
	token := registrationRelay.tokenFor(t, strings.ToLower(request.Email))
	status, payload = confirmRegistration(t, baseURL, idempotencyKey, token)
	return status, payload, token
}

// signUpUserDirectly gives a test an account with tokens without going through the registration, for the tests of other
// features: the account is inserted the way the confirmation inserts it (CLIENT role) and signed in with POST /login. It is the
// way for a server that has no relay for the registration messages. The hash has the cost of production (12), because some
// tests measure what the hasher does with the hash of the account.
func signUpUserDirectly(t *testing.T, baseURL, name string) (email, id, access, refreshToken string) {
	t.Helper()
	ctx := context.Background()
	conn := connect(t, ctx, os.Getenv("AUTH_TEST_DATABASE_URL"))
	email = name + "-" + system.UUIDGenerator{}.NewID() + "@example.com"
	id = system.UUIDGenerator{}.NewID()
	hash, err := bcrypt.GenerateFromPassword([]byte(e2ePassword), 12)
	if err != nil {
		t.Fatalf("hash the password: %v", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO auth.app_user (id, email, name, password_hash, phone, address) VALUES ($1, $2, 'Ada Lovelace', $3, '+573001234567', 'Calle 1 # 2-3')`, id, email, string(hash)); err != nil {
		t.Fatalf("insert the account: %v", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO auth.user_role (user_id, role_id) SELECT $1, id FROM auth.role WHERE name = 'CLIENT'`, id); err != nil {
		t.Fatalf("insert the role: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/login", strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST /login error = %v", err)
	}
	defer response.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, error = %v, want 200", response.StatusCode, err)
	}
	access, _ = payload["accessToken"].(string)
	refreshToken, _ = payload["refreshToken"].(string)
	return email, id, access, refreshToken
}

func confirmRegistration(t *testing.T, baseURL, idempotencyKey, token string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+confirmPath, strings.NewReader(`{"token":"`+token+`"}`))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST %s error = %v", confirmPath, err)
	}
	defer response.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode the response (status %d): %v", response.StatusCode, err)
	}
	return response.StatusCode, payload
}
