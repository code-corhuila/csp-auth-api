//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const resetPortalURL = "https://portal.cinesync.local/reset-password"

var tokenInLink = regexp.MustCompile(`#token=([0-9a-f-]{36})`)

// lockedBuffer is a log destination that the workers of the sender and the test can use at the same time.
type lockedBuffer struct {
	mu   sync.Mutex
	text strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text.String()
}

// resetToken waits for the message to address, which the service sends after answering, and returns the token of its link.
func (f *fakeSMTP) resetToken(t *testing.T, address string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		raw := f.messages[address]
		f.mu.Unlock()
		if message, err := mail.ReadMessage(strings.NewReader(raw)); err == nil {
			body, _ := io.ReadAll(quotedprintable.NewReader(message.Body))
			if found := tokenInLink.FindSubmatch(body); found != nil && strings.Contains(string(body), resetPortalURL+"#token=") {
				return string(found[1])
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no message with a reset link to %s", address)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *fakeSMTP) received(address string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, found := f.messages[address]
	return found
}

func callPublic(t *testing.T, baseURL, path, body string) (int, http.Header, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST %s error = %v", path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header, string(raw)
}

func forgotPassword(t *testing.T, baseURL, email string) (int, http.Header, string) {
	t.Helper()
	return callPublic(t, baseURL, forgotPasswordPath, fmt.Sprintf(`{"email":%q}`, email))
}

func resetPassword(t *testing.T, baseURL, token, password string) (int, string) {
	t.Helper()
	status, _, body := callPublic(t, baseURL, resetPasswordPath, fmt.Sprintf(`{"token":%q,"password":%q}`, token, password))
	return status, body
}

func startPasswordResetServer(t *testing.T, relayDelay time.Duration) (*httptest.Server, *fakeSMTP, *lockedBuffer, string) {
	t.Helper()
	databaseURL := os.Getenv("AUTH_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set: the end-to-end test needs a PostgreSQL with the csp-auth-db migrations")
	}
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	cfg.PasswordResetURL = resetPortalURL
	relay := startFakeSMTP(t)
	relay.configure(&cfg)
	relay.delay = relayDelay
	cfg.SMTPTimeout = 4 * time.Second
	var logs lockedBuffer
	handler, closeAll, err := newHandler(context.Background(), slogTo(&logs), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeAll)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, relay, &logs, databaseURL
}

// The test resets a password over HTTP with PostgreSQL (migrations V001-V030) and an in-process SMTP relay (ADR-050,
// HU-AUTH-006): registered and unknown emails get the same 202, the link carries the token in the fragment, a weak password does not
// consume it, the right one changes the password and ends the sessions, a replay is 401, nothing reaches the outbox and
// neither the token nor the address reaches a log.
func TestPasswordResetEndToEndAgainstTheDatabase(t *testing.T) {
	server, relay, logs, _ := startPasswordResetServer(t, 0)
	email, userID, _, refreshToken := signUpUser(t, server.URL, "e2e-reset")
	unknown := "e2e-nobody-" + userID + "@example.com"
	const newPassword = "Brand-New-Pass1"

	registeredStatus, registeredHeader, registeredBody := forgotPassword(t, server.URL, "  "+strings.ToUpper(email)+" ")
	unknownStatus, unknownHeader, unknownBody := forgotPassword(t, server.URL, unknown)

	if registeredStatus != http.StatusAccepted || unknownStatus != http.StatusAccepted || registeredBody != "" || unknownBody != "" ||
		registeredHeader.Get("Content-Type") != unknownHeader.Get("Content-Type") {
		t.Fatalf("registered = %d %q, unknown = %d %q, want the same 202 without body", registeredStatus, registeredBody, unknownStatus, unknownBody)
	}
	token := relay.resetToken(t, email)
	time.Sleep(200 * time.Millisecond)
	if relay.received(unknown) {
		t.Error("a message was sent to an email without an account")
	}

	t.Run("a weak password or a malformed token is 400 and the token stays usable", func(t *testing.T) {
		if status, body := resetPassword(t, server.URL, token, "weak"); status != http.StatusBadRequest || !strings.Contains(body, `"field":"password"`) {
			t.Errorf("weak password: status = %d, body = %s, want 400 for password", status, body)
		}
		if status, body := resetPassword(t, server.URL, "not-a-token", newPassword); status != http.StatusBadRequest || !strings.Contains(body, `"field":"token"`) {
			t.Errorf("malformed token: status = %d, body = %s, want 400 for token", status, body)
		}
	})

	t.Run("the right token changes the password and ends the sessions", func(t *testing.T) {
		if status, body := resetPassword(t, server.URL, token, newPassword); status != http.StatusNoContent || body != "" {
			t.Fatalf("status = %d, body = %q, want 204 and no body", status, body)
		}
		if status, _, _ := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword)); status != http.StatusUnauthorized {
			t.Errorf("login with the old password: status = %d, want 401", status)
		}
		if status, _, _ := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, newPassword)); status != http.StatusOK {
			t.Errorf("login with the new password: status = %d, want 200", status)
		}
		if status, _, _ := refresh(t, server.URL, refreshToken); status != http.StatusUnauthorized {
			t.Errorf("refresh with a token from before the reset: status = %d, want 401", status)
		}
	})

	t.Run("a replay and an unknown token are the same 401", func(t *testing.T) {
		replayStatus, replayBody := resetPassword(t, server.URL, token, "Another-Pass2")
		unknownToken, _ := model.NewOpaqueToken()
		unknownStatus, unknownBody := resetPassword(t, server.URL, unknownToken, "Another-Pass2")
		if replayStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized || !strings.Contains(replayBody, `"error":"INVALID_TOKEN"`) {
			t.Fatalf("replay = %d %s, unknown = %d %s, want 401 INVALID_TOKEN twice", replayStatus, replayBody, unknownStatus, unknownBody)
		}
		if status, _, _ := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, newPassword)); status != http.StatusOK {
			t.Errorf("login after the replay: status = %d, want the password of the first reset to stand", status)
		}
	})

	t.Run("nothing reaches the outbox and neither the token nor the address reaches a log", func(t *testing.T) {
		readerURL := os.Getenv("AUTH_TEST_OUTBOX_READER_URL")
		if readerURL == "" {
			t.Skip("AUTH_TEST_OUTBOX_READER_URL is not set: the outbox can only be read by the worker login")
		}
		conn := connect(t, context.Background(), readerURL)
		var passwordEvents int
		if err := conn.QueryRow(context.Background(), `SELECT count(*) FROM auth.outbox_event WHERE aggregate_id = $1 AND event_type <> 'UserRegistered'`, userID).Scan(&passwordEvents); err != nil {
			t.Fatalf("outbox query error = %v", err)
		}
		if passwordEvents != 0 {
			t.Errorf("%d events other than UserRegistered for the account, want none", passwordEvents)
		}
		for _, secret := range []string{token, model.HashOpaqueToken(token), resetPortalURL + "#token=", email, "Brand-New-Pass1"} {
			if strings.Contains(logs.String(), secret) {
				t.Errorf("the log leaks %q", secret)
			}
		}
	})
}

func TestPasswordResetFourthRequestInAnHourIsTheSameSilent202AndSendsNothing(t *testing.T) {
	server, relay, _, databaseURL := startPasswordResetServer(t, 0)
	email, userID, _, _ := signUpUser(t, server.URL, "e2e-reset-limit")
	var last string

	for i := range 4 {
		if status, _, body := forgotPassword(t, server.URL, email); status != http.StatusAccepted || body != "" {
			t.Fatalf("request %d: status = %d, body = %q, want 202 without body every time", i+1, status, body)
		}
		if i < 3 {
			last = relay.resetToken(t, email)
			relay.mu.Lock()
			delete(relay.messages, email)
			relay.mu.Unlock()
		}
	}

	time.Sleep(300 * time.Millisecond)
	if relay.received(email) {
		t.Error("the fourth request sent a message")
	}
	conn := connect(t, context.Background(), databaseURL)
	var rows, pending int
	if err := conn.QueryRow(context.Background(),
		`SELECT count(*), count(*) FILTER (WHERE used_at IS NULL AND deleted_at IS NULL) FROM auth.password_reset WHERE user_id = $1`, userID).Scan(&rows, &pending); err != nil {
		t.Fatalf("password_reset query error = %v", err)
	}
	if rows != 3 || pending != 1 {
		t.Errorf("rows = %d, pending = %d, want three requests with one pending", rows, pending)
	}
	if status, _ := resetPassword(t, server.URL, last, "Brand-New-Pass1"); status != http.StatusNoContent {
		t.Errorf("reset with the token of the third request: status = %d, want 204", status)
	}
}

// The relay takes 1.5 s to accept a message. The delivery is queued after the commit, so the answer does not wait for
// it and an existing account cannot be told from an unknown one by the duration of the request (ADR-050).
func TestForgotPasswordDoesNotWaitForASlowRelay(t *testing.T) {
	const relayDelay = 1500 * time.Millisecond
	server, relay, _, _ := startPasswordResetServer(t, relayDelay)
	email, userID, _, _ := signUpUser(t, server.URL, "e2e-reset-slow")

	registeredStarted := time.Now()
	registeredStatus, _, _ := forgotPassword(t, server.URL, email)
	registeredTook := time.Since(registeredStarted)
	unknownStarted := time.Now()
	unknownStatus, _, _ := forgotPassword(t, server.URL, "e2e-nobody-"+userID+"@example.com")
	unknownTook := time.Since(unknownStarted)

	if registeredStatus != http.StatusAccepted || unknownStatus != http.StatusAccepted {
		t.Fatalf("statuses = %d and %d, want 202", registeredStatus, unknownStatus)
	}
	if registeredTook > relayDelay/2 || unknownTook > relayDelay/2 {
		t.Errorf("registered took %v and unknown %v with a relay that takes %v, want neither to wait for it", registeredTook, unknownTook, relayDelay)
	}
	relay.resetToken(t, email)
}
