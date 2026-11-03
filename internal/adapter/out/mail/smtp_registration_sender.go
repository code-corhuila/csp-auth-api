package mail

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
	"github.com/code-corhuila/csp-auth-api/internal/platform/logging"
)

// Bounds of the in-process delivery queue (issue csp-docs#282, Norma 5.3.10): at most registrationWorkers messages are
// being sent and registrationQueueSize wait. A request that finds the queue full is not delivered.
const (
	registrationQueueSize = 64
	registrationWorkers   = 2
)

var (
	// ErrRegistrationQueueFull is a delivery refused because the queue is full; the user asks again.
	ErrRegistrationQueueFull = errors.New("the registration delivery queue is full")
	// ErrRegistrationSenderClosed is a delivery refused because the service is stopping.
	ErrRegistrationSenderClosed = errors.New("the registration sender is closed")
)

// SMTPRegistrationSender implements out.RegistrationSender with net/smtp (pattern Strategy). Like the sender of the
// password reset, Send only queues the message and workers deliver it afterwards, so the latency or the failure of the
// relay cannot change the answer of the request. The token goes to the relay and nowhere else: it never reaches a log or
// an error, and the queue lives in memory, so messages not yet sent are lost if the process stops.
type SMTPRegistrationSender struct {
	settings   Settings
	confirmURL string
	logger     *slog.Logger
	queue      chan queuedRegistration
	ctx        context.Context
	stop       context.CancelFunc
	workers    sync.WaitGroup
}

var _ out.RegistrationSender = (*SMTPRegistrationSender)(nil)

// queuedRegistration is a message waiting for a worker: the notice when notice is set (it has no token), the confirmation
// otherwise. It carries the trace id of the request, so the log line of a failed delivery can be tied to it.
type queuedRegistration struct {
	email     model.Email
	token     model.ResetToken
	expiresAt time.Time
	notice    bool
	traceID   string
}

// NewSMTPRegistrationSender creates a sender for the relay in settings and starts its workers. The link of a
// confirmation is confirmURL followed by #token=<token>, so the token travels in the fragment, which browsers do not send
// to servers. It refuses a TLS mode that is neither TLSStartTLS nor TLSNone.
func NewSMTPRegistrationSender(settings Settings, confirmURL string, logger *slog.Logger) (*SMTPRegistrationSender, error) {
	if err := checkTLSMode(settings.TLS); err != nil {
		return nil, err
	}
	ctx, stop := context.WithCancel(context.Background())
	s := &SMTPRegistrationSender{
		settings: settings, confirmURL: confirmURL, logger: logger,
		queue: make(chan queuedRegistration, registrationQueueSize), ctx: ctx, stop: stop,
	}
	for range registrationWorkers {
		s.workers.Add(1)
		go s.work()
	}
	return s, nil
}

// SendConfirmation queues the message with the link without waiting for it to be delivered.
func (s *SMTPRegistrationSender) SendConfirmation(ctx context.Context, confirmation out.RegistrationConfirmation) error {
	return s.enqueue(queuedRegistration{email: confirmation.Email, token: confirmation.Token, expiresAt: confirmation.ExpiresAt, traceID: logging.TraceIDFrom(ctx)})
}

// SendAccountNotice queues the notice for the owner of the address without waiting for it to be delivered.
func (s *SMTPRegistrationSender) SendAccountNotice(ctx context.Context, email model.Email) error {
	return s.enqueue(queuedRegistration{email: email, notice: true, traceID: logging.TraceIDFrom(ctx)})
}

func (s *SMTPRegistrationSender) enqueue(message queuedRegistration) error {
	if s.ctx.Err() != nil {
		return ErrRegistrationSenderClosed
	}
	select {
	case s.queue <- message:
		return nil
	default:
		return ErrRegistrationQueueFull
	}
}

// Close stops the workers, cancelling the delivery in progress, and waits for them. Messages still queued are dropped.
func (s *SMTPRegistrationSender) Close() {
	s.stop()
	s.workers.Wait()
}

func (s *SMTPRegistrationSender) work() {
	defer s.workers.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case queued := <-s.queue:
			s.deliver(queued)
		}
	}
}

// deliver sends one message. A failure is logged as WARN with the class only: the address is personal data.
func (s *SMTPRegistrationSender) deliver(queued queuedRegistration) {
	ctx, cancel := context.WithTimeout(logging.WithTraceID(s.ctx, queued.traceID), s.settings.Timeout)
	defer cancel()
	to := queued.email.String()
	var message []byte
	var err error
	if queued.notice {
		message, err = buildAccountNoticeMessage(s.settings.From, to, time.Now(), newMessageID())
	} else {
		link := s.confirmURL + "#token=" + queued.token.Reveal()
		message, err = buildRegistrationMessage(s.settings.From, to, link, queued.expiresAt, time.Now(), newMessageID())
	}
	stage := "message"
	if err == nil {
		stage, err = transmit(ctx, s.settings, to, message)
	}
	if err != nil {
		s.logger.WarnContext(ctx, "registration message not delivered", "notice", queued.notice, "errorClass", classify(ctx, stage, err))
	}
}
