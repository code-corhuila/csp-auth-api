//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
)

const newE2EPassword = "N3w-Passw0rd!Long"

func callPassword(t *testing.T, baseURL, bearer, current, replacement string) (int, http.Header, map[string]any) {
	t.Helper()
	body := fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, current, replacement)
	request, err := http.NewRequest(http.MethodPost, baseURL+passwordChangePath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST %s error = %v", passwordChangePath, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	return response.StatusCode, response.Header, payload
}

// firstDetail returns the field and the message of the first entry of details[] of an error response.
func firstDetail(payload map[string]any) (field, message string) {
	details, _ := payload["details"].([]any)
	if len(details) == 0 {
		return "", ""
	}
	detail, _ := details[0].(map[string]any)
	field, _ = detail["field"].(string)
	message, _ = detail["message"].(string)
	return field, message
}

// The test changes a password over HTTP with real access tokens, PostgreSQL with the csp-auth-db migrations and the Redis of the
// auth state (ADR-051, HU-AUTH-007): a wrong current password is 400 on its field and never 401, the new password must differ,
// a success revokes every refresh token and answers a fresh session, five wrong passwords lock that user and nobody else, and
// the correct password is refused with Retry-After during the lock.
func TestPasswordChangeEndToEndAgainstTheDatabaseAndRedis(t *testing.T) {
	databaseURL, redisURL, readerURL := os.Getenv("AUTH_TEST_DATABASE_URL"), os.Getenv("AUTH_TEST_REDIS_URL"), os.Getenv("AUTH_TEST_OUTBOX_READER_URL")
	if databaseURL == "" || redisURL == "" || readerURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL, AUTH_TEST_REDIS_URL and AUTH_TEST_OUTBOX_READER_URL are not set: the end-to-end test needs PostgreSQL with the csp-auth-db migrations and the Redis of csp-infra-redis")
	}
	ctx := context.Background()
	cfg := testConfig(t)
	cfg.DatabaseURL = databaseURL
	cfg.RedisURL = redisURL
	cfg.BcryptRounds = 4
	cfg.JWTPrivateKey = generatedKeyPEM(t)
	server := startLogoutServer(t, cfg)
	email, userID, access, firstRefresh := signUpUser(t, server.URL, "e2e-password")
	_, _, otherAccess, _ := signUpUser(t, server.URL, "e2e-password-other")

	t.Run("a wrong current password is 400 on currentPassword, not 401, and the session keeps working", func(t *testing.T) {
		status, _, payload := callPassword(t, server.URL, access, e2eWrongPassword, newE2EPassword)

		field, message := firstDetail(payload)
		if status != http.StatusBadRequest || payload["error"] != "VALIDATION_ERROR" || field != "currentPassword" || message != "The current password is incorrect" {
			t.Errorf("status = %d, body = %v, want 400 VALIDATION_ERROR on currentPassword", status, payload)
		}
		if status, _ := callProfile(t, server.URL, http.MethodGet, access, ""); status != http.StatusOK {
			t.Errorf("GET /me after the failure: status = %d, want 200: the token is still good", status)
		}
	})

	t.Run("the new password must differ from the current one and follow the rules of registration", func(t *testing.T) {
		status, _, payload := callPassword(t, server.URL, access, e2ePassword, e2ePassword)
		field, message := firstDetail(payload)
		if status != http.StatusBadRequest || field != "newPassword" || message != "The new password must differ from the current one" {
			t.Errorf("same password: status = %d, body = %v, want 400 on newPassword with the stable message", status, payload)
		}
		status, _, payload = callPassword(t, server.URL, access, e2ePassword, "weakpass")
		if field, _ := firstDetail(payload); status != http.StatusBadRequest || field != "newPassword" {
			t.Errorf("weak password: status = %d, body = %v, want 400 on newPassword", status, payload)
		}
	})

	t.Run("a missing or invalid token is 401", func(t *testing.T) {
		for _, bearer := range []string{"", "not-a-token"} {
			if status, _, _ := callPassword(t, server.URL, bearer, e2ePassword, newE2EPassword); status != http.StatusUnauthorized {
				t.Errorf("token %q: status = %d, want 401", bearer, status)
			}
		}
	})

	t.Run("a success revokes every refresh token and answers a fresh session", func(t *testing.T) {
		status, _, payload := callPassword(t, server.URL, access, e2ePassword, newE2EPassword)

		freshAccess, _ := payload["accessToken"].(string)
		freshRefresh, _ := payload["refreshToken"].(string)
		if status != http.StatusOK || freshAccess == "" || freshRefresh == "" || freshRefresh == firstRefresh {
			t.Fatalf("status = %d, body = %v, want 200 with a new access token and a new refresh token", status, payload)
		}
		if status, _, _ := refresh(t, server.URL, firstRefresh); status != http.StatusUnauthorized {
			t.Errorf("refresh with the old refresh token: status = %d, want 401: it was revoked", status)
		}
		if status, _, _ := refresh(t, server.URL, freshRefresh); status != http.StatusOK {
			t.Errorf("refresh with the fresh refresh token: status = %d, want 200", status)
		}
		if status, _, _ := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, e2ePassword)); status != http.StatusUnauthorized {
			t.Errorf("login with the old password: status = %d, want 401", status)
		}
		if status, _, _ := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, newE2EPassword)); status != http.StatusOK {
			t.Errorf("login with the new password: status = %d, want 200", status)
		}
		if status, _ := callProfile(t, server.URL, http.MethodGet, access, ""); status != http.StatusOK {
			t.Errorf("GET /me with the old access token: status = %d, want 200: access tokens live until they expire", status)
		}
		if count := outboxEventCount(t, ctx, readerURL, userID); count != 1 {
			t.Errorf("outbox events of the user = %d, want only the UserRegistered of the registration", count)
		}
	})

	t.Run("five wrong passwords lock that user only, and the right one is 429 with Retry-After", func(t *testing.T) {
		for i := range 5 {
			if status, _, _ := callPassword(t, server.URL, access, e2eWrongPassword, e2ePassword); status != http.StatusBadRequest {
				t.Fatalf("wrong password #%d: status = %d, want 400", i+1, status)
			}
		}

		status, header, payload := callPassword(t, server.URL, access, newE2EPassword, e2ePassword)

		seconds, err := strconv.Atoi(header.Get("Retry-After"))
		if status != http.StatusTooManyRequests || payload["error"] != "RATE_LIMITED" || err != nil || seconds < 1 || seconds > 900 {
			t.Errorf("status = %d, Retry-After = %q, body = %v, want 429 RATE_LIMITED with up to 900 seconds even for the right password", status, header.Get("Retry-After"), payload)
		}
		if status, _, _ := callPassword(t, server.URL, otherAccess, e2ePassword, newE2EPassword); status != http.StatusOK {
			t.Errorf("another user: status = %d, want 200: the lock is per user", status)
		}
		if status, _, _ := login(t, server.URL, fmt.Sprintf(`{"email":%q,"password":%q}`, email, newE2EPassword)); status != http.StatusOK {
			t.Errorf("login of the locked user: status = %d, want 200: the lock is only on the change of password", status)
		}
	})
}
