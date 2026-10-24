//go:build integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func callProfile(t *testing.T, baseURL, method, bearer, body string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(method, baseURL+profilePath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s error = %v", method, profilePath, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	return response.StatusCode, payload
}

func outboxEventCount(t *testing.T, ctx context.Context, url, userID string) int {
	t.Helper()
	var count int
	if err := connect(t, ctx, url).QueryRow(ctx, `SELECT count(*) FROM auth.outbox_event WHERE aggregate_id = $1`, userID).Scan(&count); err != nil {
		t.Fatalf("outbox query error = %v", err)
	}
	return count
}

// The test reads and edits the own profile over HTTP with real access tokens, PostgreSQL with the csp-auth-db
// migrations and the Redis of the auth state (ADR-051, HU-AUTH-007): the profile is the one of the token, an edit writes
// only the fields sent, an edit that is not acceptable changes nothing, an account created before the phone and the address
// has null for both, no event is written, and a token revoked by logout is 401.
func TestOwnProfileEndToEndAgainstTheDatabase(t *testing.T) {
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
	email, userID, access, _ := signUpUser(t, server.URL, "e2e-profile")
	_, otherID, otherAccess, _ := signUpUser(t, server.URL, "e2e-profile-other")

	t.Run("the profile is the one of the token and carries the personal data", func(t *testing.T) {
		status, profile := callProfile(t, server.URL, http.MethodGet, access, "")

		roles, _ := profile["roles"].([]any)
		if status != http.StatusOK || profile["id"] != userID || profile["email"] != email || profile["name"] != "Ada Lovelace" ||
			profile["phone"] != "+573001234567" || profile["address"] != "Calle 1 # 2-3" || len(roles) != 1 || roles[0] != "CLIENT" {
			t.Errorf("status = %d, profile = %v, want the data given at registration", status, profile)
		}
		if _, leaked := profile["passwordHash"]; leaked || len(profile) != 6 {
			t.Errorf("profile = %v, want exactly id, email, name, phone, address and roles", profile)
		}
	})

	t.Run("an edit writes only the fields sent and answers the profile after the change", func(t *testing.T) {
		status, profile := callProfile(t, server.URL, http.MethodPatch, access, `{"name":"Ada Byron","address":"Carrera 7 # 8-9"}`)

		if status != http.StatusOK || profile["name"] != "Ada Byron" || profile["address"] != "Carrera 7 # 8-9" || profile["phone"] != "+573001234567" {
			t.Fatalf("status = %d, profile = %v, want the new name and address and the same phone", status, profile)
		}
		if _, read := callProfile(t, server.URL, http.MethodGet, access, ""); read["name"] != "Ada Byron" {
			t.Errorf("GET after the edit = %v, want the new name", read)
		}
		if _, other := callProfile(t, server.URL, http.MethodGet, otherAccess, ""); other["name"] != "Ada Lovelace" || other["id"] != otherID {
			t.Errorf("profile of the other user = %v, want it untouched", other)
		}
		_, _, signedIn := login(t, server.URL, `{"email":"`+email+`","password":"`+e2ePassword+`"}`)
		if user, _ := signedIn["user"].(map[string]any); user["name"] != "Ada Byron" {
			t.Errorf("login summary = %v, want the new name", user)
		}
	})

	t.Run("an edit that is not acceptable is 400 and changes nothing", func(t *testing.T) {
		for name, body := range map[string]string{
			"email":         `{"email":"other@example.com"}`,
			"null phone":    `{"phone":null}`,
			"empty body":    `{}`,
			"invalid phone": `{"name":"Changed","phone":"12-34"}`,
		} {
			status, payload := callProfile(t, server.URL, http.MethodPatch, access, body)

			if status != http.StatusBadRequest || payload["error"] != "VALIDATION_ERROR" {
				t.Errorf("%s: status = %d, body = %v, want 400 VALIDATION_ERROR", name, status, payload)
			}
		}
		if _, profile := callProfile(t, server.URL, http.MethodGet, access, ""); profile["name"] != "Ada Byron" || profile["email"] != email {
			t.Errorf("profile = %v, want it as before the rejected edits", profile)
		}
	})

	t.Run("no event is written by the edits", func(t *testing.T) {
		if count := outboxEventCount(t, ctx, readerURL, userID); count != 1 {
			t.Errorf("outbox events of the user = %d, want only the UserRegistered of the registration", count)
		}
	})

	t.Run("an account created before the phone and the address has null for both", func(t *testing.T) {
		if _, err := connect(t, ctx, databaseURL).Exec(ctx, `UPDATE auth.app_user SET phone = NULL, address = NULL WHERE id = $1`, otherID); err != nil {
			t.Fatalf("clear the contact data: %v", err)
		}

		status, profile := callProfile(t, server.URL, http.MethodGet, otherAccess, "")

		phone, hasPhone := profile["phone"]
		address, hasAddress := profile["address"]
		if status != http.StatusOK || !hasPhone || phone != nil || !hasAddress || address != nil {
			t.Errorf("status = %d, profile = %v, want phone and address present as null", status, profile)
		}
	})

	t.Run("a missing token is 401 and a token revoked by logout is 401", func(t *testing.T) {
		if status, _ := callProfile(t, server.URL, http.MethodGet, "", ""); status != http.StatusUnauthorized {
			t.Errorf("GET without token: status = %d, want 401", status)
		}
		if status := logout(t, server.URL, access, ""); status != http.StatusNoContent {
			t.Fatalf("logout: status = %d, want 204", status)
		}

		for _, method := range []string{http.MethodGet, http.MethodPatch} {
			if status, _ := callProfile(t, server.URL, method, access, `{"name":"Late Edit"}`); status != http.StatusUnauthorized {
				t.Errorf("%s with the revoked token: status = %d, want 401", method, status)
			}
		}
	})
}
