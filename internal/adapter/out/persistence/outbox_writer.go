package persistence

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const (
	aggregateType   = "User"
	envelopeVersion = 1
	eventSource     = "auth-service"
)

// OutboxWriter implements out.OutboxWriter over auth.outbox_event (Transactional Outbox, ADR-019).
type OutboxWriter struct {
	pool *pgxpool.Pool
}

var (
	_ out.OutboxWriter           = (*OutboxWriter)(nil)
	_ out.UserRoleOutbox         = (*OutboxWriter)(nil)
	_ out.UserEmailChangedOutbox = (*OutboxWriter)(nil)
)

// NewOutboxWriter creates a writer over pool.
func NewOutboxWriter(pool *pgxpool.Pool) *OutboxWriter {
	return &OutboxWriter{pool: pool}
}

// Append stores the event envelope, in the transaction carried by ctx. The row id is the eventId.
func (w *OutboxWriter) Append(ctx context.Context, event model.UserRegistered) error {
	payload, err := userRegisteredEnvelope(event)
	if err != nil {
		return err
	}
	return w.insert(ctx, event.EventID, event.AggregateID(), event.EventType(), payload)
}

// AppendRoleChanged stores the UserRoleChanged envelope (ADR-031), in the transaction carried by ctx.
func (w *OutboxWriter) AppendRoleChanged(ctx context.Context, event model.UserRoleChanged) error {
	payload, err := userRoleChangedEnvelope(event)
	if err != nil {
		return err
	}
	return w.insert(ctx, event.EventID, event.AggregateID(), event.EventType(), payload)
}

func (w *OutboxWriter) insert(ctx context.Context, eventID, aggregateID, eventType string, payload []byte) error {
	_, err := executorFor(ctx, w.pool).Exec(ctx,
		`INSERT INTO auth.outbox_event (id, aggregate_type, aggregate_id, event_type, payload)
		 VALUES ($1, $2, $3, $4, $5)`,
		eventID, aggregateType, aggregateID, eventType, payload)
	return err
}

// envelope is the message every event shares; P is the payload of the event type.
type envelope[P any] struct {
	EventID     string    `json:"eventId"`
	EventType   string    `json:"eventType"`
	OccurredAt  time.Time `json:"occurredAt"`
	Version     int       `json:"version"`
	Source      string    `json:"source"`
	AggregateID string    `json:"aggregateId"`
	Payload     P         `json:"payload"`
}

type userRegisteredPayload struct {
	UserID string   `json:"userId"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
}

// userRegisteredEnvelope builds the published message (events.md). It carries identity data
// only: never the password, the phone or the address (ADR-024).
func userRegisteredEnvelope(event model.UserRegistered) ([]byte, error) {
	return json.Marshal(envelope[userRegisteredPayload]{
		EventID:     event.EventID,
		EventType:   event.EventType(),
		OccurredAt:  event.OccurredAt.UTC(),
		Version:     envelopeVersion,
		Source:      eventSource,
		AggregateID: event.AggregateID(),
		Payload:     userRegisteredPayload{UserID: event.UserID, Email: event.Email, Roles: event.Roles},
	})
}

type userRoleChangedPayload struct {
	UserID    string `json:"userId"`
	Role      string `json:"role"`
	Enabled   bool   `json:"enabled"`
	ChangedBy string `json:"changedBy"`
}

// userRoleChangedEnvelope builds the published message (events.md): ids and the decision only.
func userRoleChangedEnvelope(event model.UserRoleChanged) ([]byte, error) {
	return json.Marshal(envelope[userRoleChangedPayload]{
		EventID:     event.EventID,
		EventType:   event.EventType(),
		OccurredAt:  event.OccurredAt.UTC(),
		Version:     envelopeVersion,
		Source:      eventSource,
		AggregateID: event.AggregateID(),
		Payload:     userRoleChangedPayload{UserID: event.UserID, Role: event.Role, Enabled: event.Enabled, ChangedBy: event.ChangedBy},
	})
}

// AppendEmailChanged stores the UserEmailChanged envelope (ADR-034), in the transaction carried by ctx.
func (w *OutboxWriter) AppendEmailChanged(ctx context.Context, event model.UserEmailChanged) error {
	payload, err := userEmailChangedEnvelope(event)
	if err != nil {
		return err
	}
	return w.insert(ctx, event.EventID, event.AggregateID(), event.EventType(), payload)
}

type userEmailChangedPayload struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
}

// userEmailChangedEnvelope builds the published message (events.md): the user and the new email
// only, never the verification code and not the old address.
func userEmailChangedEnvelope(event model.UserEmailChanged) ([]byte, error) {
	return json.Marshal(envelope[userEmailChangedPayload]{
		EventID:     event.EventID,
		EventType:   event.EventType(),
		OccurredAt:  event.OccurredAt.UTC(),
		Version:     envelopeVersion,
		Source:      eventSource,
		AggregateID: event.AggregateID(),
		Payload:     userEmailChangedPayload{UserID: event.UserID, Email: event.Email},
	})
}
