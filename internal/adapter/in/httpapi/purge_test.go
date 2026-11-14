package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

const purgePath = BasePath + "/internal/maintenance/purge"

type fakePurge struct {
	result  in.PurgeOldRecordsResult
	err     error
	called  int
	command in.PurgeOldRecordsCommand
}

func (f *fakePurge) Purge(_ context.Context, command in.PurgeOldRecordsCommand) (in.PurgeOldRecordsResult, error) {
	f.called++
	f.command = command
	return f.result, f.err
}

func sendPurge(authorizer *fakeAuthorizer, useCase in.PurgeOldRecords, body, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, purgePath, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.Header.Set("Authorization", "Bearer "+serviceSecret)
	rec := httptest.NewRecorder()
	NewHandler(WithPurgeOldRecords(authorizer, useCase)).ServeHTTP(rec, request)
	return rec
}

func TestPurgeRouteExistsOnlyWhenTheUseCaseIsInjected(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, purgePath, nil))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want the route to be absent", rec.Code)
	}
}

func TestPurgeAnswersTheCountersOfTheUseCase(t *testing.T) {
	useCase := &fakePurge{result: in.PurgeOldRecordsResult{ProcessedCount: 42, HasMore: true}}

	rec := sendPurge(&fakeAuthorizer{}, useCase, `{"batchSize":250}`, "application/json")

	if rec.Code != http.StatusOK || rec.Body.String() != `{"processedCount":42,"hasMore":true}`+"\n" {
		t.Errorf("status = %d, body = %q, want 200 and the counters", rec.Code, rec.Body.String())
	}
	if useCase.command.BatchSize != 250 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Correlation-Id") == "" {
		t.Errorf("command = %+v, headers = %v, want batch 250, no-store and a correlation id", useCase.command, rec.Header())
	}
}

func TestPurgeUsesTheDefaultBatchSizeWhenTheRequestHasNone(t *testing.T) {
	for name, body := range map[string]string{"no body": "", "empty object": "{}", "null batch size": `{"batchSize":null}`} {
		useCase := &fakePurge{}

		rec := sendPurge(&fakeAuthorizer{}, useCase, body, "application/json")

		if rec.Code != http.StatusOK || useCase.command.BatchSize != model.DefaultPurgeBatchSize {
			t.Errorf("%s: status = %d, batch = %d, want 200 and %d", name, rec.Code, useCase.command.BatchSize, model.DefaultPurgeBatchSize)
		}
	}
}

func TestPurgeAcceptsABodylessRequestWithoutContentType(t *testing.T) {
	useCase := &fakePurge{}

	rec := sendPurge(&fakeAuthorizer{}, useCase, "", "")

	if rec.Code != http.StatusOK || useCase.called != 1 {
		t.Errorf("status = %d, calls = %d, want 200 and one call", rec.Code, useCase.called)
	}
}

func TestPurgeAnswers400ForABatchSizeOutsideTheContractRange(t *testing.T) {
	useCase := &fakePurge{err: model.ErrInvalidPurgeBatchSize}

	rec := sendPurge(&fakeAuthorizer{}, useCase, `{"batchSize":501}`, "application/json")

	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, `"error":"VALIDATION_ERROR"`) || !strings.Contains(body, `"field":"batchSize"`) {
		t.Errorf("status = %d, body = %s, want 400 VALIDATION_ERROR naming batchSize", rec.Code, body)
	}
}

func TestPurgeAnswers400ForAnUnreadableBody(t *testing.T) {
	for name, c := range map[string]struct{ body, contentType string }{
		"batch size is a string": {`{"batchSize":"many"}`, "application/json"},
		"not json":               {`batch`, "application/json"},
		"wrong media type":       {`{"batchSize":5}`, "text/plain"},
	} {
		useCase := &fakePurge{}

		rec := sendPurge(&fakeAuthorizer{}, useCase, c.body, c.contentType)

		if rec.Code != http.StatusBadRequest || useCase.called != 0 {
			t.Errorf("%s: status = %d, calls = %d, want 400 and the use case not called", name, rec.Code, useCase.called)
		}
	}
}

func TestPurgeIsProtectedByTheServiceCredential(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want int
	}{"invalid token": {model.ErrServiceTokenInvalid, http.StatusUnauthorized}, "other subject": {model.ErrServiceNotAllowed, http.StatusForbidden}} {
		useCase := &fakePurge{}

		rec := sendPurge(&fakeAuthorizer{err: c.err}, useCase, `{}`, "application/json")

		if rec.Code != c.want || useCase.called != 0 {
			t.Errorf("%s: status = %d, calls = %d, want %d and the use case not called", name, rec.Code, useCase.called, c.want)
		}
	}
}

func TestPurgeAnswersANeutral500AndKeepsTheCauseInTheLog(t *testing.T) {
	useCase := &fakePurge{err: errors.New("connection refused to 10.0.0.5")}

	rec := sendPurge(&fakeAuthorizer{}, useCase, `{}`, "application/json")

	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || !strings.Contains(body, `"error":"INTERNAL_ERROR"`) || strings.Contains(body, "10.0.0.5") {
		t.Errorf("status = %d, body = %s, want a neutral 500", rec.Code, body)
	}
}
