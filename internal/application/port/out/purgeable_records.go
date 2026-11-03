package out

import (
	"context"
	"time"
)

// PurgeableRecords is a table whose old rows the purge deletes (ADR-030). There is one
// implementation per table, and each decides what "older than cutoff" means for its rows.
type PurgeableRecords interface {
	// DeleteOlderThan deletes at most limit rows older than cutoff, oldest first, and returns how
	// many it deleted. Called again it finds only what is left.
	DeleteOlderThan(ctx context.Context, cutoff time.Time, limit int) (int, error)
	// ExistOlderThan reports whether any row older than cutoff is left.
	ExistOlderThan(ctx context.Context, cutoff time.Time) (bool, error)
}
