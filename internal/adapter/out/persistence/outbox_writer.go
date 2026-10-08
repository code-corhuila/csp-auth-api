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

var _ out.OutboxWriter = (*OutboxWriter)(nil)

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
	_, err = executorFor(ctx, w.pool).Exec(ctx,
		`INSERT INTO auth.outbox_event (id, aggregate_type, aggregate_id, event_type, payload)
		 VALUES ($1, $2, $3, $4, $5)`,
		event.EventID, aggregateType, event.AggregateID(), event.EventType(), payload)
	return err
}

type envelope struct {
	EventID     string                `json:"eventId"`
	EventType   string                `json:"eventType"`
	OccurredAt  time.Time             `json:"occurredAt"`
	Version     int                   `json:"version"`
	Source      string                `json:"source"`
	AggregateID string                `json:"aggregateId"`
	Payload     userRegisteredPayload `json:"payload"`
}

type userRegisteredPayload struct {
	UserID string   `json:"userId"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
}

// userRegisteredEnvelope builds the published message (events.md). It carries identity data
// only: never the password, the phone or the address (ADR-024).
func userRegisteredEnvelope(event model.UserRegistered) ([]byte, error) {
	return json.Marshal(envelope{
		EventID:     event.EventID,
		EventType:   event.EventType(),
		OccurredAt:  event.OccurredAt.UTC(),
		Version:     envelopeVersion,
		Source:      eventSource,
		AggregateID: event.AggregateID(),
		Payload:     userRegisteredPayload{UserID: event.UserID, Email: event.Email, Roles: event.Roles},
	})
}
