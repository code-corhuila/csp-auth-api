package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// WithPurgeOldRecords publishes the use case at POST /internal/maintenance/purge (ADR-030),
// reserved for the services that authorizer accepts. The gateway does not route it.
func WithPurgeOldRecords(authorizer in.AuthorizeService, useCase in.PurgeOldRecords) Option {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST "+BasePath+"/internal/maintenance/purge", serviceOnly(authorizer, purge(useCase)))
	}
}

// purgeRequest is the MaintenanceRequest schema of the auth-service contract.
type purgeRequest struct {
	BatchSize *int `json:"batchSize"`
}

// purgeResponse is the MaintenanceResult schema of the auth-service contract.
type purgeResponse struct {
	ProcessedCount int  `json:"processedCount"`
	HasMore        bool `json:"hasMore"`
}

func purge(useCase in.PurgeOldRecords) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		traceID := w.Header().Get(headerCorrelationID) // set by serviceOnly, which wraps this handler
		w.Header().Set("Cache-Control", "no-store")

		batchSize := model.DefaultPurgeBatchSize
		if r.ContentLength != 0 {
			body, unreadable := decodeBody[purgeRequest](w, r)
			if len(unreadable) > 0 {
				writeValidation(w, traceID, unreadable)
				return
			}
			if body.BatchSize != nil {
				batchSize = *body.BatchSize
			}
		}

		result, err := useCase.Purge(r.Context(), in.PurgeOldRecordsCommand{BatchSize: batchSize})
		if errors.Is(err, model.ErrInvalidPurgeBatchSize) {
			writeValidation(w, traceID, []fieldError{{Field: "batchSize", Message: err.Error()}})
			return
		}
		if err != nil {
			slog.Error("purge old records failed", "traceId", traceID, "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{
				Error: codeInternal, Message: "an unexpected error occurred", TraceID: traceID,
			})
			return
		}
		writeJSON(w, http.StatusOK, purgeResponse{ProcessedCount: result.ProcessedCount, HasMore: result.HasMore})
	}
}
