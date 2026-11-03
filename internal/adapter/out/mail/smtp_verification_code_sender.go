// Package mail is the outbound adapter that sends the service's own messages through an SMTP relay.
package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
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

// NewSMTPVerificationCodeSender creates a sender for the relay in settings. It refuses a TLS mode that
// is neither TLSStartTLS nor TLSNone, the empty one included: an unknown mode must never send in clear.
func NewSMTPVerificationCodeSender(settings Settings, logger *slog.Logger) (*SMTPVerificationCodeSender, error) {
	if err := checkTLSMode(settings.TLS); err != nil {
		return nil, err
	}
	return &SMTPVerificationCodeSender{settings: settings, logger: logger, now: time.Now}, nil
}

func checkTLSMode(mode string) error {
	if mode != TLSStartTLS && mode != TLSNone {
		return fmt.Errorf("smtp tls mode must be %q or %q", TLSStartTLS, TLSNone)
	}
	return nil
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
	to := delivery.NewEmail.String()
	message, err := buildMessage(s.settings.From, to, delivery.Code.String(), delivery.ExpiresAt, s.now(), newMessageID())
	if err != nil {
		return "message", err
	}
	return transmit(ctx, s.settings, to, message)
}

func newMessageID() string {
	var messageID [16]byte
	_, _ = rand.Read(messageID[:])
	return hex.EncodeToString(messageID[:])
}

// transmit sends message to one recipient through the relay of settings, bounded by ctx. It returns the stage
// where it failed, for classify.
func transmit(ctx context.Context, settings Settings, to string, message []byte) (stage string, err error) {
	address := net.JoinHostPort(settings.Host, strconv.Itoa(settings.Port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "connect", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	defer context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })()

	client, err := smtp.NewClient(conn, settings.Host)
	if err != nil {
		return "io", err
	}
	defer client.Close()
	switch settings.TLS {
	case TLSStartTLS:
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return "tls", errors.New("the relay does not offer STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: settings.Host, RootCAs: settings.RootCAs, MinVersion: tls.VersionTLS12}); err != nil {
			return "tls", err
		}
	case TLSNone: // clear text, only for a local catcher
	default:
		return "tls", errors.New("unknown tls mode")
	}
	if settings.User != "" {
		if err := client.Auth(smtp.PlainAuth("", settings.User, settings.Password, settings.Host)); err != nil {
			return "auth", err
		}
	}
	if err := client.Mail(settings.From); err != nil {
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
