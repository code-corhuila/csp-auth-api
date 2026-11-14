package mail

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	testCode    = "048213"
	testAddress = "ada.new@example.com"
	testUserID  = "3f2c1b7e-0000-4000-8000-000000000001"
	testFrom    = "no-reply@cinesync.local"
)

var testNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func delivery(t *testing.T) out.VerificationCodeDelivery {
	t.Helper()
	email, err := model.NewEmail(testAddress)
	if err != nil {
		t.Fatal(err)
	}
	code, err := model.NewVerificationCode(testCode)
	if err != nil {
		t.Fatal(err)
	}
	return out.VerificationCodeDelivery{RequestID: "req-1", UserID: testUserID, NewEmail: email, Code: code, ExpiresAt: testNow.Add(15 * time.Minute)}
}

func newSender(settings Settings, logs io.Writer) *SMTPVerificationCodeSender {
	settings.From = testFrom
	if settings.Timeout == 0 {
		settings.Timeout = 2 * time.Second
	}
	sender, err := NewSMTPVerificationCodeSender(settings, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		panic(err)
	}
	sender.now = func() time.Time { return testNow }
	return sender
}

func parseMessage(t *testing.T, raw string) (*mail.Message, string) {
	t.Helper()
	message, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadMessage() error = %v\n%s", err, raw)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(message.Body))
	return message, string(body)
}

func TestBuildMessageHasTheHeadersAndTheSpanishText(t *testing.T) {
	raw, err := buildMessage(testFrom, testAddress, testCode, testNow.Add(15*time.Minute), testNow, "id123")
	if err != nil {
		t.Fatalf("buildMessage() error = %v", err)
	}
	message, body := parseMessage(t, string(raw))

	from, _ := mail.ParseAddress(message.Header.Get("From"))
	to, _ := mail.ParseAddress(message.Header.Get("To"))
	if from == nil || from.Address != testFrom || to == nil || to.Address != testAddress {
		t.Errorf("From = %q, To = %q", message.Header.Get("From"), message.Header.Get("To"))
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subject != "Código de verificación de tu correo" {
		t.Errorf("Subject = %q (%v), want the Spanish subject", subject, err)
	}
	if strings.Contains(message.Header.Get("Subject"), "ó") {
		t.Error("the subject is not RFC 2047 encoded")
	}
	if got := message.Header.Get("Content-Type"); got != "text/plain; charset=UTF-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if message.Header.Get("MIME-Version") != "1.0" || message.Header.Get("Message-ID") != "<id123@cinesync.local>" {
		t.Errorf("MIME-Version = %q, Message-ID = %q", message.Header.Get("MIME-Version"), message.Header.Get("Message-ID"))
	}
	if date, err := message.Header.Date(); err != nil || !date.Equal(testNow) {
		t.Errorf("Date = %v, %v, want %v", date, err, testNow)
	}
	for _, want := range []string{testCode, "15 minutos", "Si no lo solicitaste, puedes ignorar este mensaje."} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q:\n%s", want, body)
		}
	}
	if strings.Contains(strings.ReplaceAll(string(raw), "\r\n", ""), "\n") {
		t.Error("a line ends without CR")
	}
}

func TestBuildMessageDerivesTheLifetimeFromExpiresAt(t *testing.T) {
	raw, err := buildMessage(testFrom, testAddress, testCode, testNow.Add(10*time.Minute+20*time.Second), testNow, "id")
	if err != nil {
		t.Fatal(err)
	}
	if _, body := parseMessage(t, string(raw)); !strings.Contains(body, "10 minutos") {
		t.Errorf("body = %s, want 10 minutes", body)
	}
}

func TestBuildMessageRejectsHeaderInjection(t *testing.T) {
	for name, c := range map[string]struct{ from, to string }{
		"line feed in the destination":       {testFrom, "a@example.com\nBcc: evil@example.com"},
		"carriage return in the destination": {testFrom, "a@example.com\rBcc: evil@example.com"},
		"line feed in the sender":            {"a@example.com\nBcc: evil@example.com", testAddress},
	} {
		if _, err := buildMessage(c.from, c.to, testCode, testNow, testNow, "id"); err == nil {
			t.Errorf("%s: buildMessage() error = nil", name)
		}
	}
}

func TestSendDeliversOverStartTLSWithAuthentication(t *testing.T) {
	server := newFakeServer(t, true)
	server.start()
	var logs bytes.Buffer
	sender := newSender(Settings{Host: "127.0.0.1", Port: server.port(), User: "relay", Password: "s3cret", TLS: TLSStartTLS, RootCAs: server.rootCAs}, &logs)

	if err := sender.Send(context.Background(), delivery(t)); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	mails := server.mails()
	if len(mails) != 1 {
		t.Fatalf("received %d messages, want 1", len(mails))
	}
	got := mails[0]
	_, body := parseMessage(t, got.data)
	plain := base64.StdEncoding.EncodeToString([]byte("\x00relay\x00s3cret"))
	if !got.encrypted || got.from != testFrom || len(got.to) != 1 || got.to[0] != testAddress || !strings.Contains(body, testCode) || !strings.HasSuffix(got.auth, plain) {
		t.Errorf("encrypted = %v, from = %q, to = %v, auth ok = %v, body = %q", got.encrypted, got.from, got.to, strings.HasSuffix(got.auth, plain), body)
	}
	assertNothingSecretIn(t, logs.String())
}

func TestSendWithoutTLSAgainstALocalCatcher(t *testing.T) {
	server := newFakeServer(t, false)
	server.start()
	var logs bytes.Buffer
	sender := newSender(Settings{Host: "127.0.0.1", Port: server.port(), TLS: TLSNone}, &logs)

	if err := sender.Send(context.Background(), delivery(t)); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	mails := server.mails()
	if len(mails) != 1 || mails[0].encrypted || mails[0].auth != "" || mails[0].to[0] != testAddress {
		t.Fatalf("mails = %+v, want one plain message to %s and no AUTH", mails, testAddress)
	}
	assertNothingSecretIn(t, logs.String())
}

func TestSendFailsWhenStartTLSIsRequiredAndNotOffered(t *testing.T) {
	server := newFakeServer(t, false)
	server.start()
	var logs bytes.Buffer
	sender := newSender(Settings{Host: "127.0.0.1", Port: server.port(), TLS: TLSStartTLS}, &logs)

	if err := sender.Send(context.Background(), delivery(t)); err == nil {
		t.Fatal("Send() error = nil, want an error: the code must not travel in clear")
	}
	if len(server.mails()) != 0 {
		t.Error("a message was sent without TLS")
	}
	assertNothingSecretIn(t, logs.String())
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), testUserID) || !strings.Contains(logs.String(), "errorClass=tls") {
		t.Errorf("log = %q, want a WARN with the user id and errorClass=tls", logs.String())
	}
}

func TestTheConstructorRejectsAnyTLSModeThatIsNotStartTLSOrNone(t *testing.T) {
	for _, mode := range []string{"", "STARTTLS", "tls", "false"} {
		if _, err := NewSMTPVerificationCodeSender(Settings{Host: "127.0.0.1", Port: 25, TLS: mode}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
			t.Errorf("TLS %q: error = nil, want the mode rejected", mode)
		}
	}
}

func TestSendNeverFallsBackToClearForAnUnknownTLSMode(t *testing.T) {
	server := newFakeServer(t, true)
	server.start()
	var logs bytes.Buffer
	sender := newSender(Settings{Host: "127.0.0.1", Port: server.port(), TLS: TLSNone}, &logs)
	sender.settings.TLS = ""

	if err := sender.Send(context.Background(), delivery(t)); err == nil {
		t.Fatal("Send() error = nil, want an error for an unknown TLS mode")
	}
	if len(server.mails()) != 0 {
		t.Error("a message was sent for an unknown TLS mode")
	}
	assertNothingSecretIn(t, logs.String())
}

func TestSendFailures(t *testing.T) {
	refused, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedPort := refused.Addr().(*net.TCPAddr).Port
	_ = refused.Close()
	rejecting := newFakeServer(t, false)
	rejecting.rejectTo = true
	rejecting.start()
	silent := newFakeServer(t, false)
	silent.silent = true
	silent.start()
	cancelled, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	for name, c := range map[string]struct {
		ctx      context.Context
		settings Settings
		class    string
	}{
		"connection refused":        {context.Background(), Settings{Host: "127.0.0.1", Port: refusedPort, TLS: TLSNone}, "connect"},
		"recipient rejected":        {context.Background(), Settings{Host: "127.0.0.1", Port: rejecting.port(), TLS: TLSNone}, "rejected"},
		"server that never answers": {context.Background(), Settings{Host: "127.0.0.1", Port: silent.port(), TLS: TLSNone, Timeout: 200 * time.Millisecond}, "timeout"},
		"cancelled context":         {cancelled, Settings{Host: "127.0.0.1", Port: silent.port(), TLS: TLSNone, Timeout: 5 * time.Second}, "canceled"},
	} {
		var logs bytes.Buffer
		started := time.Now()
		err := newSender(c.settings, &logs).Send(c.ctx, delivery(t))
		if err == nil {
			t.Errorf("%s: Send() error = nil", name)
			continue
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Errorf("%s: took %v, want the timeout or the cancellation to end it", name, elapsed)
		}
		if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), testUserID) || !strings.Contains(logs.String(), "errorClass="+c.class) {
			t.Errorf("%s: log = %q, want a WARN with the user id and errorClass=%s", name, logs.String(), c.class)
		}
		assertNothingSecretIn(t, logs.String(), err.Error())
	}
}

func assertNothingSecretIn(t *testing.T, texts ...string) {
	t.Helper()
	for _, text := range texts {
		for _, secret := range []string{testCode, testAddress, "s3cret"} {
			if strings.Contains(text, secret) {
				t.Errorf("%q leaks %q", text, secret)
			}
		}
	}
}
