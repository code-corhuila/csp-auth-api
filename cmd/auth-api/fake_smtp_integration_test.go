//go:build integration

package main

import (
	"bufio"
	"io"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"mime/quotedprintable"

	"github.com/code-corhuila/csp-auth-api/internal/config"
)

var codeInMessage = regexp.MustCompile(`verificación es: (\d{6})`)

// fakeSMTP is an in-process SMTP relay without TLS (APP_AUTH_SMTP_TLS=none) that keeps the last
// message of each recipient, the way a developer reads it in Mailpit.
type fakeSMTP struct {
	listener net.Listener
	mu       sync.Mutex
	messages map[string]string
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{listener: listener, messages: map[string]string{}}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

// configure points the email change of cfg at this relay.
func (f *fakeSMTP) configure(cfg *config.Config) {
	address := f.listener.Addr().(*net.TCPAddr)
	cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPFrom = "127.0.0.1", address.Port, "no-reply@cinesync.local"
	cfg.SMTPTLS, cfg.SMTPTimeout = config.SMTPTLSNone, 2*time.Second
}

// codeFor returns the six digits of the last message sent to address.
func (f *fakeSMTP) codeFor(t *testing.T, address string) string {
	t.Helper()
	f.mu.Lock()
	raw := f.messages[address]
	f.mu.Unlock()
	message, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("no message to %s: %v", address, err)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(message.Body))
	found := codeInMessage.FindSubmatch(body)
	if found == nil {
		t.Fatalf("the message to %s has no code:\n%s", address, body)
	}
	return string(found[1])
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reply := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") }
	reader, recipient := bufio.NewReader(conn), ""
	reply("220 fake ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		switch verb := strings.ToUpper(strings.Fields(line + " x")[0]); verb {
		case "RCPT":
			recipient = line[strings.Index(line, "<")+1 : strings.Index(line, ">")]
			reply("250 ok")
		case "DATA":
			reply("354 go")
			var data strings.Builder
			for part, err := reader.ReadString('\n'); err == nil && part != ".\r\n"; part, err = reader.ReadString('\n') {
				data.WriteString(part)
			}
			f.mu.Lock()
			f.messages[recipient] = data.String()
			f.mu.Unlock()
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}
