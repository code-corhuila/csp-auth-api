package in

import "context"

// PurgeOldRecordsCommand carries the most rows one call may delete, in total.
type PurgeOldRecordsCommand struct {
	BatchSize int
}

// PurgeOldRecordsResult is what one call did: the rows deleted in total and whether any row older
// than its retention is left in any table.
type PurgeOldRecordsResult struct {
	ProcessedCount int
	HasMore        bool
}

// PurgeOldRecords is the use case of the maintenance operation (ADR-030): it deletes, in this
// order, old outbox events, old refresh tokens, old idempotency keys, old email verification
// requests, old password resets and old password reset keys. A batch size outside
// 1 to 500 is model.ErrInvalidPurgeBatchSize.
type PurgeOldRecords interface {
	Purge(ctx context.Context, command PurgeOldRecordsCommand) (PurgeOldRecordsResult, error)
}
