// Command auth-token issues the credential of a service (ADR-052): an RS256 token signed with the
// key of the identity service, written to a file and never printed. It is an offline command, not an
// endpoint. The key comes from the same variables as the service: APP_AUTH_JWT_PRIVATE_KEY or
// APP_AUTH_JWT_PRIVATE_KEY_FILE.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/system"
	"github.com/code-corhuila/csp-auth-api/internal/adapter/out/token"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

func main() {
	os.Exit(run(os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr))
}

// run writes nothing to stdout: the token goes only to the file and the record of the issuance to stderr.
func run(args []string, lookup func(string) (string, bool), _ io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("auth-token", flag.ContinueOnError)
	flags.SetOutput(stderr)
	subject := flags.String("subject", "", "service that holds the credential: csp-worker, booking-service or csp-workflow")
	lifetime := flags.Duration("lifetime", model.MaxServiceTokenLifetime, "lifetime of the token, at most 2160h (90 days)")
	out := flags.String("out", "", "file the token is written to (mode 0600)")
	force := flags.Bool("force", false, "replace the file if it exists")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		return fail(stderr, "-out is required: the token is never printed")
	}
	request, err := model.NewServiceTokenRequest(*subject, *lifetime)
	if err != nil {
		return fail(stderr, err.Error())
	}
	privateKey, _ := lookup("APP_AUTH_JWT_PRIVATE_KEY")
	privateKeyFile, _ := lookup("APP_AUTH_JWT_PRIVATE_KEY_FILE")
	key, err := token.LoadPrivateKey(privateKey, privateKeyFile)
	if err != nil {
		return fail(stderr, err.Error())
	}
	issuer, err := token.NewIssuer(key, time.Minute, system.Clock{}, system.UUIDGenerator{})
	if err != nil {
		return fail(stderr, err.Error())
	}
	issued, err := issuer.IssueServiceToken(request)
	if err != nil {
		return fail(stderr, err.Error())
	}
	if err := writeToken(*out, issued.Value, *force); err != nil {
		return fail(stderr, err.Error())
	}
	fmt.Fprintf(stderr, "issued service token subject=%s jti=%s expires=%s file=%s\n",
		request.Subject, issued.TokenID, issued.ExpiresAt.UTC().Format(time.RFC3339), *out)
	return 0
}

// writeToken creates the file with mode 0600 and refuses to replace an existing one unless force is set.
func writeToken(path, value string, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return fmt.Errorf("write the token file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil && !os.IsPermission(err) {
		_ = file.Close()
		return fmt.Errorf("restrict the token file: %w", err)
	}
	if _, err := fmt.Fprintln(file, value); err != nil {
		_ = file.Close()
		return fmt.Errorf("write the token file: %w", err)
	}
	return file.Close()
}

func fail(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "auth-token: %s\n", message)
	return 1
}
