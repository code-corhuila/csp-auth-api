// Package mail is the outbound adapter that sends the service's own messages through an SMTP relay.
package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// How the connection to the relay is secured (ADR-034).
const (
	// TLSStartTLS requires the relay to offer STARTTLS and fails otherwise.
	TLSStartTLS = "starttls"
	// TLSNone sends in clear: only for a local development catcher.
	TLSNone = "none"
)

// Settings of the SMTP relay. Timeout bounds the whole exchange, dial included (Norma 5.3.10).
type Settings struct {
	Host, User, Password, From, TLS string
	Port                            int
	Timeout                         time.Duration
	RootCAs                         *x509.CertPool // trust roots for STARTTLS; nil means the system ones
}

// SMTPVerificationCodeSender implements out.VerificationCodeSender with net/smtp (pattern Strategy,
// ADR-034). The code goes to the relay and nowhere else: it never reaches a log or an error.
type SMTPVerificationCodeSender struct {
	settings Settings
	logger   *slog.Logger
	now      func() time.Time
}

var _ out.VerificationCodeSender = (*SMTPVerificationCodeSender)(nil)

// NewSMTPVerificationCodeSender creates a sender for the relay in settings.
func NewSMTPVerificationCodeSender(settings Settings, logger *slog.Logger) *SMTPVerificationCodeSender {
	return &SMTPVerificationCodeSender{settings: settings, logger: logger, now: time.Now}
}

// deliveryError carries only the class of a failure: the text of an SMTP error can quote the address.
type deliveryError struct{ class string }

func (e *deliveryError) Error() string { return "smtp delivery failed: " + e.class }

// Send delivers the code. A failure is logged as WARN with the user id and the class only.
func (s *SMTPVerificationCodeSender) Send(ctx context.Context, delivery out.VerificationCodeDelivery) error {
	ctx, cancel := context.WithTimeout(ctx, s.settings.Timeout)
	defer cancel()
	stage, err := s.deliver(ctx, delivery)
	if err == nil {
		return nil
	}
	failure := &deliveryError{class: classify(ctx, stage, err)}
	s.logger.WarnContext(ctx, "email verification code not delivered", "userId", delivery.UserID, "errorClass", failure.class)
	return failure
}

func (s *SMTPVerificationCodeSender) deliver(ctx context.Context, delivery out.VerificationCodeDelivery) (stage string, err error) {
	var messageID [16]byte
	_, _ = rand.Read(messageID[:])
	to := delivery.NewEmail.String()
	message, err := buildMessage(s.settings.From, to, delivery.Code.String(), delivery.ExpiresAt, s.now(), hex.EncodeToString(messageID[:]))
	if err != nil {
		return "message", err
	}

	address := net.JoinHostPort(s.settings.Host, strconv.Itoa(s.settings.Port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "connect", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	defer context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })()

	client, err := smtp.NewClient(conn, s.settings.Host)
	if err != nil {
		return "io", err
	}
	defer client.Close()
	if s.settings.TLS == TLSStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return "tls", errors.New("the relay does not offer STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: s.settings.Host, RootCAs: s.settings.RootCAs, MinVersion: tls.VersionTLS12}); err != nil {
			return "tls", err
		}
	}
	if s.settings.User != "" {
		if err := client.Auth(smtp.PlainAuth("", s.settings.User, s.settings.Password, s.settings.Host)); err != nil {
			return "auth", err
		}
	}
	if err := client.Mail(s.settings.From); err != nil {
		return "sender", err
	}
	if err := client.Rcpt(to); err != nil {
		return "recipient", err
	}
	data, err := client.Data()
	if err != nil {
		return "data", err
	}
	if _, err := data.Write(message); err != nil {
		return "data", err
	}
	if err := data.Close(); err != nil {
		return "data", err
	}
	_ = client.Quit()
	return "", nil
}

// classify names the failure without quoting it: canceled, timeout, rejected (the relay answered with
// an error code) or the stage where it happened.
func classify(ctx context.Context, stage string, err error) string {
	var netErr net.Error
	var protocolErr *textproto.Error
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return "canceled"
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.As(err, &protocolErr):
		return "rejected"
	default:
		return stage
	}
}
