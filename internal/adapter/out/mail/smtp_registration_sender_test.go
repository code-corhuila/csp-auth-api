package mail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"strings"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	confirmURL  = "https://portal.cinesync.local/confirm-registration"
	confirmLink = confirmURL + "#token=" + resetToken
)

func registrationConfirmation(t *testing.T) out.RegistrationConfirmation {
	t.Helper()
	email, err := model.NewEmail(testAddress)
	if err != nil {
		t.Fatal(err)
	}
	token, err := model.NewResetToken(resetToken)
	if err != nil {
		t.Fatal(err)
	}
	return out.RegistrationConfirmation{Email: email, Token: token, ExpiresAt: time.Now().Add(model.RegistrationLifetime)}
}

func newRegistrationSender(t *testing.T, settings Settings, logs io.Writer) *SMTPRegistrationSender {
	t.Helper()
	settings.From = testFrom
	if settings.Timeout == 0 {
		settings.Timeout = 10 * time.Second
	}
	sender, err := NewSMTPRegistrationSender(settings, confirmURL, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatalf("NewSMTPRegistrationSender() error = %v", err)
	}
	t.Cleanup(sender.Close)
	return sender
}

func TestBuildRegistrationMessageCarriesTheLinkAndTheLifetimeInSpanish(t *testing.T) {
	raw, err := buildRegistrationMessage(testFrom, testAddress, confirmLink, testNow.Add(model.RegistrationLifetime), testNow, "id123")
	if err != nil {
		t.Fatalf("buildRegistrationMessage() error = %v", err)
	}
	message, body := parseMessage(t, string(raw))

	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subject != "Confirma tu registro" {
		t.Errorf("Subject = %q (%v), want the Spanish subject", subject, err)
	}
	for _, want := range []string{confirmLink, "1440 minutos", "una sola vez", "no se creará ninguna cuenta"} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q:\n%s", want, body)
		}
	}
}

func TestBuildAccountNoticeMessageCarriesNoLinkAndNoSecret(t *testing.T) {
	raw, err := buildAccountNoticeMessage(testFrom, testAddress, testNow, "id123")
	if err != nil {
		t.Fatalf("buildAccountNoticeMessage() error = %v", err)
	}
	message, body := parseMessage(t, string(raw))

	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subject != "Intento de registro con tu correo" {
		t.Errorf("Subject = %q (%v), want the Spanish subject", subject, err)
	}
	if strings.Contains(body, "http") || strings.Contains(body, "#token=") || !strings.Contains(body, "ya tienes una") {
		t.Errorf("body = %q, want a notice without any link", body)
	}
}

func TestBuildRegistrationMessagesRejectHeaderInjection(t *testing.T) {
	injected := "a@example.com\nBcc: evil@example.com"
	if _, err := buildRegistrationMessage(testFrom, injected, confirmLink, testNow, testNow, "id"); err == nil {
		t.Error("buildRegistrationMessage() error = nil, want the line break rejected")
	}
	if _, err := buildAccountNoticeMessage(testFrom, injected, testNow, "id"); err == nil {
		t.Error("buildAccountNoticeMessage() error = nil, want the line break rejected")
	}
}

func TestSendConfirmationReturnsAtOnceAndTheLinkIsDeliveredAfterwards(t *testing.T) {
	server := newFakeServer(t, true)
	server.start()
	var logs syncBuffer
	sender := newRegistrationSender(t, Settings{Host: "127.0.0.1", Port: server.port(), User: "relay", Password: "s3cret", TLS: TLSStartTLS, RootCAs: server.rootCAs}, &logs)

	if err := sender.SendConfirmation(context.Background(), registrationConfirmation(t)); err != nil {
		t.Fatalf("SendConfirmation() error = %v", err)
	}

	got := waitForMails(t, server, 1)[0]
	_, body := parseMessage(t, got.data)
	if !got.encrypted || got.from != testFrom || len(got.to) != 1 || got.to[0] != testAddress || !strings.Contains(body, confirmLink) {
		t.Errorf("encrypted = %v, from = %q, to = %v, body = %q, want the link sent over STARTTLS to the address", got.encrypted, got.from, got.to, body)
	}
	assertNoResetSecretIn(t, logs.String())
}

func TestSendAccountNoticeDeliversTheNoticeToTheOwnerOfTheAddress(t *testing.T) {
	server := newFakeServer(t, false)
	server.start()
	sender := newRegistrationSender(t, Settings{Host: "127.0.0.1", Port: server.port(), TLS: TLSNone}, io.Discard)
	email := registrationConfirmation(t).Email

	if err := sender.SendAccountNotice(context.Background(), email); err != nil {
		t.Fatalf("SendAccountNotice() error = %v", err)
	}

	got := waitForMails(t, server, 1)[0]
	_, body := parseMessage(t, got.data)
	if len(got.to) != 1 || got.to[0] != testAddress || !strings.Contains(body, "ya tienes una") || strings.Contains(body, "#token=") {
		t.Errorf("to = %v, body = %q, want the notice for the address", got.to, body)
	}
}

func TestSendDoesNotWaitForASlowRelayForARegistration(t *testing.T) {
	silent := newFakeServer(t, false)
	silent.silent = true
	silent.start()
	sender := newRegistrationSender(t, Settings{Host: "127.0.0.1", Port: silent.port(), TLS: TLSNone, Timeout: 1500 * time.Millisecond}, io.Discard)

	started := time.Now()
	err := sender.SendConfirmation(context.Background(), registrationConfirmation(t))

	if elapsed := time.Since(started); err != nil || elapsed > 200*time.Millisecond {
		t.Errorf("SendConfirmation() = %v after %v, want a success without waiting for the relay", err, elapsed)
	}
}

func TestAFailedRegistrationDeliveryIsLoggedWithTheClassOnly(t *testing.T) {
	rejecting := newFakeServer(t, false)
	rejecting.rejectTo = true
	rejecting.start()
	var logs syncBuffer
	sender := newRegistrationSender(t, Settings{Host: "127.0.0.1", Port: rejecting.port(), TLS: TLSNone}, &logs)

	if err := sender.SendConfirmation(context.Background(), registrationConfirmation(t)); err != nil {
		t.Fatalf("SendConfirmation() error = %v, want the failure to be the business of the worker", err)
	}

	deadline := time.Now().Add(deliveryGuard)
	for !strings.Contains(logs.String(), "errorClass=rejected") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "errorClass=rejected") {
		t.Errorf("log = %q, want a WARN with errorClass=rejected", logs.String())
	}
	assertNoResetSecretIn(t, logs.String())
}

func TestSendRefusesWhenTheRegistrationQueueIsFullInsteadOfWaiting(t *testing.T) {
	silent := newFakeServer(t, false)
	silent.silent = true
	silent.start()
	sender := newRegistrationSender(t, Settings{Host: "127.0.0.1", Port: silent.port(), TLS: TLSNone, Timeout: 5 * time.Second}, io.Discard)

	var accepted int
	var refusal error
	for accepted = 0; accepted < 3*registrationQueueSize; accepted++ {
		if refusal = sender.SendConfirmation(context.Background(), registrationConfirmation(t)); refusal != nil {
			break
		}
	}

	if !errors.Is(refusal, ErrRegistrationQueueFull) || accepted < registrationQueueSize || accepted > registrationQueueSize+registrationWorkers {
		t.Errorf("accepted = %d, refusal = %v, want ErrRegistrationQueueFull after the queue of %d and the workers are busy", accepted, refusal, registrationQueueSize)
	}
}

func TestSendAfterCloseIsRefusedForARegistration(t *testing.T) {
	sender := newRegistrationSender(t, Settings{Host: "127.0.0.1", Port: 1, TLS: TLSNone}, io.Discard)
	sender.Close()

	err := sender.SendAccountNotice(context.Background(), registrationConfirmation(t).Email)

	if !errors.Is(err, ErrRegistrationSenderClosed) {
		t.Errorf("SendAccountNotice() error = %v, want ErrRegistrationSenderClosed", err)
	}
}

func TestNewSMTPRegistrationSenderRefusesAnUnknownTLSMode(t *testing.T) {
	if _, err := NewSMTPRegistrationSender(Settings{TLS: "tls"}, confirmURL, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("NewSMTPRegistrationSender() error = nil, want the mode refused")
	}
}
