//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/persistence"
)

const (
	emailChangePath = "/api/v1/auth/me/email"
	emailVerifyPath = "/api/v1/auth/me/email/verify"
)

func callEmail(t *testing.T, baseURL, method, path, bearer, body string) (int, http.Header, string) {
	t.Helper()
	request, err := http.NewRequest(method, baseURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "e2e-email-"+strings.ReplaceAll(body, " ", ""))
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s error = %v", method, path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header, string(raw)
}

// requestChangeWithKey sends the request with an Idempotency-Key of the caller instead of the one derived from the body.
func requestChangeWithKey(t *testing.T, baseURL, bearer, key, email string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPatch, baseURL+emailChangePath, strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("PATCH %s error = %v", emailChangePath, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(raw)
}

func requestChange(t *testing.T, baseURL, bearer, email string) (int, http.Header, string) {
	t.Helper()
	return callEmail(t, baseURL, http.MethodPatch, emailChangePath, bearer, fmt.Sprintf(`{"email":%q}`, email))
}

func verifyCode(t *testing.T, baseURL, bearer, code string) (int, string) {
	t.Helper()
	status, _, body := callEmail(t, baseURL, http.MethodPost, emailVerifyPath, bearer, fmt.Sprintf(`{"verificationCode":%q}`, code))
	return status, body
}

func emailChangedEventCount(t *testing.T, ctx context.Context, url, userID string) (count int, payload string) {
	t.Helper()
	conn := connect(t, ctx, url)
	rows, err := conn.Query(ctx, `SELECT payload::text FROM auth.outbox_event WHERE aggregate_id = $1 AND event_type = 'UserEmailChanged'`, userID)
	if err != nil {
		t.Fatalf("outbox query error = %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		count++
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
	}
	return count, payload
}

// The test changes an email over HTTP with real access tokens, PostgreSQL with the csp-auth-db
// migrations (V001-V025) and an in-process SMTP relay as the delivery of the code (ADR-034, HU-AUTH-004): the
// account is untouched until the right code arrives, a wrong code is counted, the right one changes
// the email and publishes one event without the code, the session keeps working, and an address
// that is taken or a fourth request in the hour is refused.
func TestEmailChangeEndToEndAgainstTheDatabase(t *testing.T) {
	databaseURL, readerURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_OUTBOX_READER_URL")
	if databaseURL == "" || readerURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL and AUTH_TEST_OUTBOX_READER_URL are not set: the end-to-end test needs a PostgreSQL with the csp-auth-db migrations")
	}
	ctx := context.Background()
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	relay := startFakeSMTP(t)
	relay.configure(&cfg)
	handler, closeDatabase, err := newHandler(ctx, discardLogger(), cfg, persistence.NewPool)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	t.Cleanup(closeDatabase)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	oldEmail, userID, access, _ := signUpUser(t, server.URL, "e2e-change")
	otherEmail, _, _, _ := signUpUser(t, server.URL, "e2e-other")
	newEmail := "e2e-new-" + userID + "@example.com"
	signedInAs := func(email string) (int, string) {
		status, _, payload := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword))
		user, _ := payload["user"].(map[string]any)
		shown, _ := user["email"].(string)
		return status, shown
	}

	t.Run("a missing token is 401", func(t *testing.T) {
		if status, _, _ := requestChange(t, server.URL, "", newEmail); status != http.StatusUnauthorized {
			t.Errorf("PATCH status = %d, want 401", status)
		}
		if status, _ := verifyCode(t, server.URL, "", "123456"); status != http.StatusUnauthorized {
			t.Errorf("POST verify status = %d, want 401", status)
		}
	})

	t.Run("an invalid email is 400 and an address in use is 409, the own one included", func(t *testing.T) {
		if status, _, _ := requestChange(t, server.URL, access, "not-an-email"); status != http.StatusBadRequest {
			t.Errorf("invalid email: status = %d, want 400", status)
		}
		for name, email := range map[string]string{"another account": otherEmail, "own account": strings.ToUpper(oldEmail)} {
			if status, _, body := requestChange(t, server.URL, access, email); status != http.StatusConflict || !strings.Contains(body, "EMAIL_ALREADY_REGISTERED") {
				t.Errorf("%s: status = %d, body = %s, want 409 EMAIL_ALREADY_REGISTERED", name, status, body)
			}
		}
	})

	t.Run("a request is 202 without body and leaves the account and the outbox untouched", func(t *testing.T) {
		status, _, body := requestChange(t, server.URL, access, "  "+strings.ToUpper(newEmail)+" ")
		if status != http.StatusAccepted || body != "" {
			t.Fatalf("status = %d, body = %q, want 202 and no body", status, body)
		}
		code := relay.codeFor(t, newEmail)
		if strings.Contains(body, code) {
			t.Error("the response carries the code")
		}
		if status, shown := signedInAs(oldEmail); status != http.StatusOK || shown != oldEmail {
			t.Errorf("login with the old email: status = %d, email = %q, want 200 and the old email", status, shown)
		}
		if status, _ := signedInAs(newEmail); status != http.StatusUnauthorized {
			t.Errorf("login with the new email: status = %d, want 401 until it is verified", status)
		}
		if count, _ := emailChangedEventCount(t, ctx, readerURL, userID); count != 0 {
			t.Errorf("UserEmailChanged events = %d, want none before the verification", count)
		}
	})

	t.Run("a wrong, malformed or missing code is the same 400 and the right code is still accepted", func(t *testing.T) {
		code := relay.codeFor(t, newEmail)
		wrong := "000000"
		if code == wrong {
			wrong = "000001"
		}
		var first string
		for _, attempt := range []string{wrong, "12ab", ""} {
			status, body := verifyCode(t, server.URL, access, attempt)
			if status != http.StatusBadRequest || !strings.Contains(body, "VALIDATION_ERROR") {
				t.Fatalf("code %q: status = %d, body = %s, want 400 VALIDATION_ERROR", attempt, status, body)
			}
			var parsed struct{ Message, Error string }
			_ = json.Unmarshal([]byte(body), &parsed)
			if first == "" {
				first = parsed.Message
			} else if parsed.Message != first {
				t.Errorf("code %q: message = %q, want the same as the first rejection %q", attempt, parsed.Message, first)
			}
		}
		if status, _ := signedInAs(newEmail); status != http.StatusUnauthorized {
			t.Errorf("login with the new email after wrong codes: status = %d, want 401", status)
		}
	})

	t.Run("the right code is 204, changes the email, keeps the session and publishes one event without the code", func(t *testing.T) {
		code := relay.codeFor(t, newEmail)

		if status, body := verifyCode(t, server.URL, access, code); status != http.StatusNoContent {
			t.Fatalf("status = %d, body = %s, want 204", status, body)
		}
		if status, shown := signedInAs(newEmail); status != http.StatusOK || shown != newEmail {
			t.Errorf("login with the new email: status = %d, email = %q, want 200 and %q", status, shown, newEmail)
		}
		if status, _ := signedInAs(oldEmail); status != http.StatusUnauthorized {
			t.Errorf("login with the old email: status = %d, want 401", status)
		}
		count, payload := emailChangedEventCount(t, ctx, readerURL, userID)
		if count != 1 || !strings.Contains(payload, newEmail) || strings.Contains(payload, code) || strings.Contains(payload, oldEmail) {
			t.Errorf("events = %d, payload = %s, want one with the new email and neither the code nor the old email", count, payload)
		}
		if status, _ := verifyCode(t, server.URL, access, code); status != http.StatusBadRequest {
			t.Errorf("a second verification: status = %d, want 400 (the request was consumed)", status)
		}
		if count, _ := emailChangedEventCount(t, ctx, readerURL, userID); count != 1 {
			t.Errorf("events after the repeated verification = %d, want 1", count)
		}
		if status, _, _ := requestChange(t, server.URL, access, "e2e-again-"+userID+"@example.com"); status != http.StatusAccepted {
			t.Errorf("the token issued before the change: status = %d, want 202 (no session is revoked)", status)
		}
	})

	t.Run("a relay that is down is 500 and the account can ask again", func(t *testing.T) {
		down := cfg
		down.SMTPPort = 1
		downServer := startLogoutServer(t, down)
		_, downID, downAccess, _ := signUpUser(t, downServer.URL, "e2e-down")
		target := "e2e-down-" + downID + "@example.com"

		if status, _, _ := requestChange(t, downServer.URL, downAccess, target); status != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (the request rolls back)", status)
		}
		if status, _, _ := requestChange(t, server.URL, downAccess, target); status != http.StatusAccepted {
			t.Errorf("the same request with the relay up: status = %d, want 202 (a failed delivery does not count)", status)
		}
	})

	t.Run("the fourth request in the hour is 429 with Retry-After", func(t *testing.T) {
		_, limitedID, limitedAccess, _ := signUpUser(t, server.URL, "e2e-limited")
		for i := 1; i <= 3; i++ {
			if status, _, _ := requestChange(t, server.URL, limitedAccess, fmt.Sprintf("e2e-limit-%d-%s@example.com", i, limitedID)); status != http.StatusAccepted {
				t.Fatalf("request %d: status = %d, want 202", i, status)
			}
		}
		status, header, body := requestChange(t, server.URL, limitedAccess, "e2e-limit-4-"+limitedID+"@example.com")
		if status != http.StatusTooManyRequests || !strings.Contains(body, "TOO_MANY_REQUESTS") {
			t.Errorf("status = %d, body = %s, want 429 TOO_MANY_REQUESTS", status, body)
		}
		if seconds, err := strconv.Atoi(header.Get("Retry-After")); err != nil || seconds < 3590 || seconds > 3600 {
			t.Errorf("Retry-After = %q, want the seconds until the first request of this test leaves the hour (3590 to 3600)", header.Get("Retry-After"))
		}
	})

	t.Run("the same key again is 202 without a new code or a count, another address with it is 409 IDEMPOTENCY_KEY_CONFLICT", func(t *testing.T) {
		_, replayID, replayAccess, _ := signUpUser(t, server.URL, "e2e-replay")
		key, target := "e2e-replay-key-"+replayID, "e2e-replay-"+replayID+"@example.com"
		status, body := requestChangeWithKey(t, server.URL, replayAccess, key, target)
		if status != http.StatusAccepted || body != "" {
			t.Fatalf("first request: status = %d, body = %q, want 202 and no body", status, body)
		}
		code := relay.codeFor(t, target)

		for i := 1; i <= 4; i++ {
			if status, body := requestChangeWithKey(t, server.URL, replayAccess, key, target); status != http.StatusAccepted || body != "" {
				t.Fatalf("replay %d: status = %d, body = %q, want 202 and no body", i, status, body)
			}
		}

		if again := relay.codeFor(t, target); again != code {
			t.Errorf("the code changed from %s to %s: a replay sent a new message", code, again)
		}
		if status, body := requestChangeWithKey(t, server.URL, replayAccess, key, "e2e-replay-other-"+replayID+"@example.com"); status != http.StatusConflict || !strings.Contains(body, "IDEMPOTENCY_KEY_CONFLICT") {
			t.Errorf("another address with the key: status = %d, body = %s, want 409 IDEMPOTENCY_KEY_CONFLICT", status, body)
		}
		for i := 1; i <= 2; i++ {
			if status, _, _ := requestChange(t, server.URL, replayAccess, fmt.Sprintf("e2e-replay-%d-%s@example.com", i, replayID)); status != http.StatusAccepted {
				t.Errorf("new request %d: status = %d, want 202: the replays are not counted against the limit of 3", i, status)
			}
		}
		if status, body := verifyCode(t, server.URL, replayAccess, code); status != http.StatusBadRequest {
			t.Errorf("verify the code of the first request after newer requests: status = %d, body = %s, want 400 (superseded)", status, body)
		}
	})

	t.Run("an address taken after the request is 409 and publishes nothing", func(t *testing.T) {
		_, contestedID, contestedAccess, _ := signUpUser(t, server.URL, "e2e-contested")
		target := "e2e-taken-" + contestedID + "@example.com"
		if status, _, _ := requestChange(t, server.URL, contestedAccess, target); status != http.StatusAccepted {
			t.Fatalf("request status = %d, want 202", status)
		}
		code := relay.codeFor(t, target)
		registerBody := fmt.Sprintf(`{"email":%q,"password":%q,"name":"Ada Lovelace","phone":"+573001234567","address":"Calle 1 # 2-3"}`, target, e2ePassword)
		if status, payload := register(t, server.URL, "e2e-taken-key-"+contestedID, registerBody); status != http.StatusCreated {
			t.Fatalf("register the account that takes the address: status = %d, body = %v", status, payload)
		}

		if status, body := verifyCode(t, server.URL, contestedAccess, code); status != http.StatusConflict || !strings.Contains(body, "EMAIL_ALREADY_REGISTERED") {
			t.Errorf("status = %d, body = %s, want 409 EMAIL_ALREADY_REGISTERED", status, body)
		}
		if count, _ := emailChangedEventCount(t, ctx, readerURL, contestedID); count != 0 {
			t.Errorf("events = %d, want none", count)
		}
		if status, _ := verifyCode(t, server.URL, contestedAccess, code); status != http.StatusBadRequest {
			t.Errorf("the invalidated request: status = %d, want 400", status)
		}
	})

	t.Run("a valid token of a deleted account is 401 and not a server error", func(t *testing.T) {
		_, goneID, goneAccess, _ := signUpUser(t, server.URL, "e2e-gone")
		if _, err := connect(t, ctx, databaseURL).Exec(ctx, `UPDATE auth.app_user SET deleted_at = now() WHERE id = $1`, goneID); err != nil {
			t.Fatalf("soft delete error = %v", err)
		}

		status, _, body := requestChange(t, server.URL, goneAccess, "e2e-gone-"+goneID+"@example.com")

		if status != http.StatusUnauthorized || !strings.Contains(body, "UNAUTHORIZED") {
			t.Errorf("status = %d, body = %s, want 401 UNAUTHORIZED", status, body)
		}
	})
}

// The email change checks the list of revoked access tokens like the other protected routes (ADR-033):
// after a logout the same token is 401 on both steps, and with Redis down they fail closed with 500.
func TestEmailChangeRejectsARevokedTokenAndFailsClosedWhenTheListIsDownEndToEnd(t *testing.T) {
	databaseURL, redisURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL and AUTH_TEST_REDIS_URL are not set: the end-to-end test needs PostgreSQL with the csp-auth-db migrations and the Redis of csp-infra-redis")
	}
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.RedisURL = redisURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	startFakeSMTP(t).configure(&cfg)
	server := startLogoutServer(t, cfg)
	redisDown := cfg
	redisDown.RedisURL = "redis://auth_app:unused@127.0.0.1:1/0"
	redisDown.RedisTimeout = 300 * time.Millisecond
	downServer := startLogoutServer(t, redisDown)
	_, userID, access, _ := signUpUser(t, server.URL, "e2e-email-revoked")
	target := "e2e-revoked-" + userID + "@example.com"

	if status, _, _ := requestChange(t, server.URL, access, target); status != http.StatusAccepted {
		t.Fatalf("request before the logout: status = %d, want 202", status)
	}
	for name, status := range map[string]int{
		"request": func() int { s, _, _ := requestChange(t, downServer.URL, access, target); return s }(),
		"verify":  func() int { s, _ := verifyCode(t, downServer.URL, access, "123456"); return s }(),
	} {
		if status != http.StatusInternalServerError {
			t.Errorf("%s with Redis down: status = %d, want 500 (fail closed)", name, status)
		}
	}
	if status := logout(t, server.URL, access, ""); status != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", status)
	}
	if status, _, _ := requestChange(t, server.URL, access, target); status != http.StatusUnauthorized {
		t.Errorf("request with a revoked token: status = %d, want 401", status)
	}
	if status, _ := verifyCode(t, server.URL, access, "123456"); status != http.StatusUnauthorized {
		t.Errorf("verify with a revoked token: status = %d, want 401", status)
	}
}
