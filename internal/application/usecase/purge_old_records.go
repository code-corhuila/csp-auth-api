package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// PurgeOldRecords implements in.PurgeOldRecords (ADR-030).
type PurgeOldRecords struct {
	outbox             out.PurgeableRecords
	refreshTokens      out.PurgeableRecords
	idempotencyKeys    out.PurgeableRecords
	emailVerifications out.PurgeableRecords
	passwordResets     out.PurgeableRecords
	passwordResetKeys  out.PurgeableRecords
	retention          model.RetentionPolicy
	clock              out.Clock
}

var _ in.PurgeOldRecords = (*PurgeOldRecords)(nil)

// NewPurgeOldRecords wires the use case with the six tables it purges and the retention of
// ADR-030.
func NewPurgeOldRecords(outbox, refreshTokens, idempotencyKeys, emailVerifications, passwordResets, passwordResetKeys out.PurgeableRecords, clock out.Clock) *PurgeOldRecords {
	return &PurgeOldRecords{
		outbox:             outbox,
		refreshTokens:      refreshTokens,
		idempotencyKeys:    idempotencyKeys,
		emailVerifications: emailVerifications,
		passwordResets:     passwordResets,
		passwordResetKeys:  passwordResetKeys,
		retention:          model.DefaultRetentionPolicy(),
		clock:              clock,
	}
}

// purgeStep is one table of the purge with the instant before which its rows are old.
type purgeStep struct {
	name    string
	records out.PurgeableRecords
	cutoff  time.Time
}

// Purge deletes old rows in the order outbox events, refresh tokens, idempotency keys, email
// verification requests, password resets, password reset keys, at most
// the batch size in total: each table gets what the previous ones left of the batch. HasMore is
// true while any table still holds a row older than its retention. Repeating the call only finds
// what is left, so it is idempotent.
func (p *PurgeOldRecords) Purge(ctx context.Context, command in.PurgeOldRecordsCommand) (in.PurgeOldRecordsResult, error) {
	batch, err := model.NewPurgeBatchSize(command.BatchSize)
	if err != nil {
		return in.PurgeOldRecordsResult{}, err
	}
	now := p.clock.Now()
	steps := []purgeStep{
		{"outbox events", p.outbox, now.Add(-p.retention.OutboxEvents)},
		{"refresh tokens", p.refreshTokens, now.Add(-p.retention.RefreshTokens)},
		{"idempotency keys", p.idempotencyKeys, now.Add(-p.retention.IdempotencyKeys)},
		{"email verifications", p.emailVerifications, now.Add(-p.retention.EmailVerifications)},
		{"password resets", p.passwordResets, now.Add(-p.retention.PasswordResets)},
		{"password reset keys", p.passwordResetKeys, now.Add(-p.retention.IdempotencyKeys)},
	}

	remaining, processed := int(batch), 0
	for _, step := range steps {
		if remaining == 0 {
			break
		}
		deleted, err := step.records.DeleteOlderThan(ctx, step.cutoff, remaining)
		if err != nil {
			return in.PurgeOldRecordsResult{}, fmt.Errorf("purge %s: %w", step.name, err)
		}
		processed += deleted
		remaining -= deleted
	}

	for _, step := range steps {
		left, err := step.records.ExistOlderThan(ctx, step.cutoff)
		if err != nil {
			return in.PurgeOldRecordsResult{}, fmt.Errorf("look for old %s: %w", step.name, err)
		}
		if left {
			return in.PurgeOldRecordsResult{ProcessedCount: processed, HasMore: true}, nil
		}
	}
	return in.PurgeOldRecordsResult{ProcessedCount: processed}, nil
}
