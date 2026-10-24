package mail

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
)

// Bounds of the in-process delivery queue (ADR-050, Norma 5.3.10): at most passwordResetWorkers messages
// are being sent and passwordResetQueueSize wait. A request that finds the queue full is not delivered.
const (
	passwordResetQueueSize = 64
	passwordResetWorkers   = 2
)

var (
	// ErrPasswordResetQueueFull is a delivery refused because the queue is full; the user asks again.
	ErrPasswordResetQueueFull = errors.New("the password reset delivery queue is full")
	// ErrPasswordResetSenderClosed is a delivery refused because the service is stopping.
	ErrPasswordResetSenderClosed = errors.New("the password reset sender is closed")
)

// SMTPPasswordResetSender implements out.PasswordResetSender with net/smtp (pattern Strategy, ADR-050).
// Send only queues the message: workers deliver it afterwards, so the latency or the failure of the relay
// cannot change the answer of the request. The token goes to the relay and nowhere else: it never reaches a
// log or an error, and the queue lives in memory, so messages not yet sent are lost if the process stops.
type SMTPPasswordResetSender struct {
	settings Settings
	resetURL string
	logger   *slog.Logger
	queue    chan out.PasswordResetDelivery
	ctx      context.Context
	stop     context.CancelFunc
	workers  sync.WaitGroup
}

var _ out.PasswordResetSender = (*SMTPPasswordResetSender)(nil)

// NewSMTPPasswordResetSender creates a sender for the relay in settings and starts its workers. The link of a message
// is resetURL followed by #token=<token>, so the token travels in the fragment, which browsers do not send to servers.
// It refuses a TLS mode that is neither TLSStartTLS nor TLSNone, the empty one included.
func NewSMTPPasswordResetSender(settings Settings, resetURL string, logger *slog.Logger) (*SMTPPasswordResetSender, error) {
	if err := checkTLSMode(settings.TLS); err != nil {
		return nil, err
	}
	ctx, stop := context.WithCancel(context.Background())
	s := &SMTPPasswordResetSender{
		settings: settings, resetURL: resetURL, logger: logger,
		queue: make(chan out.PasswordResetDelivery, passwordResetQueueSize), ctx: ctx, stop: stop,
	}
	for range passwordResetWorkers {
		s.workers.Add(1)
		go s.work()
	}
	return s, nil
}

// Send queues the message without waiting for it to be delivered. A full queue is ErrPasswordResetQueueFull.
func (s *SMTPPasswordResetSender) Send(_ context.Context, delivery out.PasswordResetDelivery) error {
	if s.ctx.Err() != nil {
		return ErrPasswordResetSenderClosed
	}
	select {
	case s.queue <- delivery:
		return nil
	default:
		return ErrPasswordResetQueueFull
	}
}

// Close stops the workers, cancelling the delivery in progress, and waits for them. Messages still queued are dropped.
func (s *SMTPPasswordResetSender) Close() {
	s.stop()
	s.workers.Wait()
}

func (s *SMTPPasswordResetSender) work() {
	defer s.workers.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case delivery := <-s.queue:
			s.deliver(delivery)
		}
	}
}

// deliver sends one message. A failure is logged as WARN with the user id and the class only.
func (s *SMTPPasswordResetSender) deliver(delivery out.PasswordResetDelivery) {
	ctx, cancel := context.WithTimeout(s.ctx, s.settings.Timeout)
	defer cancel()
	to := delivery.Email.String()
	link := s.resetURL + "#token=" + delivery.Token.Reveal()
	message, err := buildResetMessage(s.settings.From, to, link, delivery.ExpiresAt, time.Now(), newMessageID())
	stage := "message"
	if err == nil {
		stage, err = transmit(ctx, s.settings, to, message)
	}
	if err != nil {
		s.logger.WarnContext(ctx, "password reset link not delivered", "userId", delivery.UserID, "errorClass", classify(ctx, stage, err))
	}
}
