package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

type fixture struct {
	dir    string
	key    *rsa.PrivateKey
	env    map[string]string
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "jwt-private.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &fixture{dir: dir, key: key, env: map[string]string{"APP_AUTH_JWT_PRIVATE_KEY_FILE": keyFile}}
}

func (f *fixture) run(args ...string) int {
	lookup := func(name string) (string, bool) { value, ok := f.env[name]; return value, ok }
	return run(args, lookup, &f.stdout, &f.stderr)
}

func (f *fixture) out() string { return filepath.Join(f.dir, "token.txt") }

func TestIssuesAVerifiableTokenToAFileAndPrintsNothingOnStdout(t *testing.T) {
	f := newFixture(t)
	if code := f.run("-subject", "csp-worker", "-lifetime", "720h", "-out", f.out()); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, f.stderr.String())
	}
	raw, err := os.ReadFile(f.out())
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	claims := jwt.MapClaims{}
	if _, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})).ParseWithClaims(token, claims,
		func(*jwt.Token) (any, error) { return &f.key.PublicKey, nil }); err != nil {
		t.Fatalf("the token does not verify: %v", err)
	}
	if claims["sub"] != "csp-worker" || claims["aud"] != "csp-internal" || claims["jti"] == nil {
		t.Errorf("claims = %v, want sub csp-worker, aud csp-internal and a jti", claims)
	}
	if f.stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", f.stdout.String())
	}
	audit := f.stderr.String()
	if !strings.Contains(audit, "subject=csp-worker") || !strings.Contains(audit, "jti="+claims["jti"].(string)) {
		t.Errorf("audit line = %q, want the subject and the jti", audit)
	}
	if strings.Contains(audit, token) || strings.Contains(audit, "PRIVATE KEY") {
		t.Errorf("the audit line leaks the token or the key: %q", audit)
	}
}

func TestWritesTheFileWithModeZeroSixHundred(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not enforced on Windows")
	}
	f := newFixture(t)
	if code := f.run("-subject", "csp-workflow", "-out", f.out()); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, f.stderr.String())
	}
	info, err := os.Stat(f.out())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
}

func TestRefusesWhatTheDomainRefusesAndWritesNoFile(t *testing.T) {
	cases := map[string][]string{
		"a user id":          {"-subject", "550e8400-e29b-41d4-a716-446655440000"},
		"an unknown service": {"-subject", "catalog-service"},
		"a long lifetime":    {"-subject", "csp-worker", "-lifetime", "2161h"},
		"no lifetime":        {"-subject", "csp-worker", "-lifetime", "0s"},
		"no subject":         {},
	}
	for name, args := range cases {
		f := newFixture(t)
		if code := f.run(append(args, "-out", f.out())...); code == 0 {
			t.Errorf("%s: exit code = 0, want a failure", name)
		}
		if _, err := os.Stat(f.out()); err == nil {
			t.Errorf("%s: a file was written", name)
		}
	}
}

func TestRefusesToRunWithoutTheKeyOrWithoutAnOutputFile(t *testing.T) {
	f := newFixture(t)
	f.env = map[string]string{}
	if code := f.run("-subject", "csp-worker", "-out", f.out()); code == 0 {
		t.Error("exit code = 0 without a key, want a failure")
	}
	g := newFixture(t)
	if code := g.run("-subject", "csp-worker"); code == 0 {
		t.Error("exit code = 0 without -out, want a failure")
	}
}

func TestDoesNotOverwriteWithoutForce(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(f.out(), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := f.run("-subject", "csp-worker", "-out", f.out()); code == 0 {
		t.Fatal("exit code = 0, want a failure when the file exists")
	}
	if raw, _ := os.ReadFile(f.out()); string(raw) != "old" {
		t.Errorf("the file was changed: %q", raw)
	}
	if code := f.run("-subject", "csp-worker", "-out", f.out(), "-force"); code != 0 {
		t.Fatalf("exit code with -force = %d, stderr = %s", code, f.stderr.String())
	}
	if raw, _ := os.ReadFile(f.out()); string(raw) == "old" {
		t.Error("the file was not replaced with -force")
	}
}
