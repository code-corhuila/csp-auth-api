package redis

import (
	"strings"
	"testing"
	"time"
)

func TestNewClientAppliesTheTimeoutToEveryPhase(t *testing.T) {
	client, err := NewClient(ClientSettings{URL: "redis://auth_app:secret@redis:6379/0", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	options := client.Options()
	if options.DialTimeout != 3*time.Second || options.ReadTimeout != 3*time.Second || options.WriteTimeout != 3*time.Second {
		t.Errorf("timeouts = %v/%v/%v, want 3s each", options.DialTimeout, options.ReadTimeout, options.WriteTimeout)
	}
	if options.Username != "auth_app" || options.Addr != "redis:6379" {
		t.Errorf("user = %q, addr = %q", options.Username, options.Addr)
	}
}

func TestNewClientRejectsAnInvalidURLWithoutRevealingIt(t *testing.T) {
	_, err := NewClient(ClientSettings{URL: "http://auth_app:topsecret@redis", Timeout: time.Second})
	if err == nil {
		t.Fatal("NewClient() error = nil, want an error")
	}
	if strings.Contains(err.Error(), "topsecret") {
		t.Errorf("error = %q reveals the password", err)
	}
}

func TestRevokedTokenKeyUsesTheBlacklistPattern(t *testing.T) {
	if got := revokedTokenKey("0b6f"); got != "blacklist:0b6f" {
		t.Errorf("revokedTokenKey() = %q, want blacklist:0b6f", got)
	}
}
