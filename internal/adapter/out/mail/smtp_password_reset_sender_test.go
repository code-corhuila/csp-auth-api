package mail

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	resetURL   = "https://portal.cinesync.local/reset-password"
	resetToken = "3f2c1b7e-5a9d-4c1e-8b6f-0a1b2c3d4e5f"
	resetLink  = resetURL + "#token=" + resetToken
)

// syncBuffer is a log destination that the workers of the sender and the test can use at the same time.
type syncBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func resetDelivery(t *testing.T) out.PasswordResetDelivery {
	t.Helper()
	email, err := model.NewEmail(testAddress)
	if err != nil {
		t.Fatal(err)
	}
	token, err := model.NewResetToken(resetToken)
	if err != nil {
		t.Fatal(err)
	}
	return out.PasswordResetDelivery{UserID: testUserID, Email: email, Token: token, ExpiresAt: time.Now().Add(model.PasswordResetLifetime)}
}

func newResetSender(t *testing.T, settings Settings, logs io.Writer) *SMTPPasswordResetSender {
	t.Helper()
	settings.From = testFrom
	if settings.Timeout == 0 {
		settings.Timeout = 10 * time.Second // generous: a loaded machine can take seconds to finish a TLS handshake
	}
	sender, err := NewSMTPPasswordResetSender(settings, resetURL, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatalf("NewSMTPPasswordResetSender() error = %v", err)
	}
	t.Cleanup(sender.Close)
	return sender
}

// deliveryGuard only catches a message that never arrives: the wait ends as soon as the relay has it, and it is longer
// than the delivery timeout of the sender so a loaded machine cannot fail the test before the sender gives up.
const deliveryGuard = 30 * time.Second

func waitForMails(t *testing.T, server *fakeServer, count int) []receivedMail {
	t.Helper()
	deadline := time.Now().Add(deliveryGuard)
	for time.Now().Before(deadline) {
		if mails := server.mails(); len(mails) >= count {
			return mails
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("received %d messages, want %d", len(server.mails()), count)
	return nil
}

func assertNoResetSecretIn(t *testing.T, texts ...string) {
	t.Helper()
	for _, text := range texts {
		for _, secret := range []string{resetToken, model.HashOpaqueToken(resetToken), resetLink, testAddress, "s3cret"} {
			if strings.Contains(text, secret) {
				t.Errorf("%q leaks %q", text, secret)
			}
		}
	}
}

func TestBuildResetMessageCarriesTheLinkAndTheLifetimeInSpanish(t *testing.T) {
	raw, err := buildResetMessage(testFrom, testAddress, resetLink, testNow.Add(time.Hour), testNow, "id123")
	if err != nil {
		t.Fatalf("buildResetMessage() error = %v", err)
	}
	message, body := parseMessage(t, string(raw))

	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subject != "Restablece tu contraseña" {
		t.Errorf("Subject = %q (%v), want the Spanish subject", subject, err)
	}
	if message.Header.Get("To") != "<"+testAddress+">" || message.Header.Get("Content-Type") != "text/plain; charset=UTF-8" {
		t.Errorf("To = %q, Content-Type = %q", message.Header.Get("To"), message.Header.Get("Content-Type"))
	}
	for _, want := range []string{resetLink, "60 minutos", "una sola vez", "Si no lo solicitaste, puedes ignorar este mensaje."} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q:\n%s", want, body)
		}
	}
}

func TestBuildResetMessageRejectsHeaderInjection(t *testing.T) {
	if _, err := buildResetMessage(testFrom, "a@example.com\nBcc: evil@example.com", resetLink, testNow, testNow, "id"); err == nil {
		t.Error("buildResetMessage() error = nil, want the line break rejected")
	}
}

func TestSendReturnsAtOnceAndTheMessageIsDeliveredAfterwards(t *testing.T) {
	server := newFakeServer(t, true)
	server.start()
	var logs syncBuffer
	sender := newResetSender(t, Settings{Host: "127.0.0.1", Port: server.port(), User: "relay", Password: "s3cret", TLS: TLSStartTLS, RootCAs: server.rootCAs}, &logs)

	if err := sender.Send(context.Background(), resetDelivery(t)); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	got := waitForMails(t, server, 1)[0]
	_, body := parseMessage(t, got.data)
	if !got.encrypted || got.from != testFrom || len(got.to) != 1 || got.to[0] != testAddress || !strings.Contains(body, resetLink) {
		t.Errorf("encrypted = %v, from = %q, to = %v, body = %q, want the link sent over STARTTLS to the user", got.encrypted, got.from, got.to, body)
	}
	assertNoResetSecretIn(t, logs.String())
}

func TestSendDoesNotWaitForASlowRelay(t *testing.T) {
	silent := newFakeServer(t, false)
	silent.silent = true
	silent.start()
	var logs syncBuffer
	sender := newResetSender(t, Settings{Host: "127.0.0.1", Port: silent.port(), TLS: TLSNone, Timeout: 1500 * time.Millisecond}, &logs)

	started := time.Now()
	err := sender.Send(context.Background(), resetDelivery(t))

	if elapsed := time.Since(started); err != nil || elapsed > 200*time.Millisecond {
		t.Errorf("Send() = %v after %v, want a success without waiting for the relay", err, elapsed)
	}
}

func TestAFailedDeliveryIsLoggedWithTheUserAndTheClassOnly(t *testing.T) {
	rejecting := newFakeServer(t, false)
	rejecting.rejectTo = true
	rejecting.start()
	var logs syncBuffer
	sender := newResetSender(t, Settings{Host: "127.0.0.1", Port: rejecting.port(), TLS: TLSNone}, &logs)

	if err := sender.Send(context.Background(), resetDelivery(t)); err != nil {
		t.Fatalf("Send() error = %v, want the failure to be the business of the worker", err)
	}

	deadline := time.Now().Add(deliveryGuard)
	for !strings.Contains(logs.String(), "errorClass=rejected") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), testUserID) || !strings.Contains(logs.String(), "errorClass=rejected") {
		t.Errorf("log = %q, want a WARN with the user id and errorClass=rejected", logs.String())
	}
	assertNoResetSecretIn(t, logs.String())
}

func TestSendRefusesWhenTheQueueIsFullInsteadOfWaiting(t *testing.T) {
	silent := newFakeServer(t, false)
	silent.silent = true
	silent.start()
	sender := newResetSender(t, Settings{Host: "127.0.0.1", Port: silent.port(), TLS: TLSNone, Timeout: 5 * time.Second}, io.Discard)

	var accepted int
	var refusal error
	for accepted = 0; accepted < 3*passwordResetQueueSize; accepted++ {
		if refusal = sender.Send(context.Background(), resetDelivery(t)); refusal != nil {
			break
		}
	}

	if !errors.Is(refusal, ErrPasswordResetQueueFull) || accepted < passwordResetQueueSize || accepted > passwordResetQueueSize+passwordResetWorkers {
		t.Errorf("accepted = %d, refusal = %v, want ErrPasswordResetQueueFull after the queue of %d and the workers are busy", accepted, refusal, passwordResetQueueSize)
	}
	assertNoResetSecretIn(t, refusal.Error())
}

func TestSendAfterCloseIsRefused(t *testing.T) {
	sender := newResetSender(t, Settings{Host: "127.0.0.1", Port: 1, TLS: TLSNone}, io.Discard)
	sender.Close()

	if err := sender.Send(context.Background(), resetDelivery(t)); !errors.Is(err, ErrPasswordResetSenderClosed) {
		t.Errorf("Send() error = %v, want ErrPasswordResetSenderClosed", err)
	}
}

func TestTheResetSenderRejectsAnyTLSModeThatIsNotStartTLSOrNone(t *testing.T) {
	for _, mode := range []string{"", "STARTTLS", "tls"} {
		if _, err := NewSMTPPasswordResetSender(Settings{Host: "127.0.0.1", Port: 25, TLS: mode}, resetURL, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
			t.Errorf("TLS %q: error = nil, want the mode rejected", mode)
		}
	}
}
