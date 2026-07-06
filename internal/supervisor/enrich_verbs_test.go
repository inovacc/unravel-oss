/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

func TestEnrichVerbs_AllRegistered(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = sv.Stop() }()

	want := []string{
		"enrich.pending",
		"enrich.write",
		"enrich.status",
		"enrich.retry",
		"enrich.record",
		"enrich.human_review",
	}
	for _, v := range want {
		if !sv.HasVerb(v) {
			t.Errorf("supervisor missing verb %q", v)
		}
	}
}

func TestEnrichVerbs_NoDBReturnsUnavailable(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp}) // no DSN ⇒ no pool
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = sv.Stop() }()

	cases := []struct {
		name    string
		handler func(context.Context, json.RawMessage) (any, *ipc.ErrorBody)
		params  any
	}{
		{"pending", sv.enrichPending, EnrichPendingParams{App: "x"}},
		{"write", sv.enrichWrite, EnrichWriteParams{ModuleID: 1, App: "x", ParsedJSON: "{}"}},
		{"status", sv.enrichStatus, EnrichStatusParams{}},
		{"retry", sv.enrichRetry, EnrichRetryParams{RunID: "some-uuid"}},
		{"record-start", sv.enrichRecord, EnrichRecordParams{Action: "start", App: "x"}},
		{"record-attempt", sv.enrichRecord, EnrichRecordParams{Action: "attempt", RunID: "r", ModuleID: 1, Status: "success"}},
		{"human_review-list", sv.enrichHumanReview, EnrichHumanReviewParams{Action: "list"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, eb := tc.handler(context.Background(), mustJSON(t, tc.params))
			if eb == nil {
				t.Fatalf("want ErrorBody, got nil")
			}
			if eb.Code != ipc.CodeUnavailable {
				t.Errorf("got code %d, want %d", eb.Code, ipc.CodeUnavailable)
			}
		})
	}
}

func TestEnrichVerbs_BadParamShape(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})
	defer func() { _ = sv.Stop() }()

	// All no-DB short-circuits run first; verify the verb surface treats
	// no-DB as the more-fundamental error vs the validation errors below.

	// enrich.write with no body → CodeUnavailable wins over CodeInvalidArg
	// because the no-DB check runs first.
	_, eb := sv.enrichWrite(context.Background(), mustJSON(t, EnrichWriteParams{}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Errorf("enrich.write empty no-DB: eb=%v", eb)
	}

	// enrich.retry without run_id likewise.
	_, eb = sv.enrichRetry(context.Background(), mustJSON(t, EnrichRetryParams{}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Errorf("enrich.retry empty no-DB: eb=%v", eb)
	}

	// enrich.record with bogus action likewise.
	_, eb = sv.enrichRecord(context.Background(), mustJSON(t, EnrichRecordParams{Action: "bogus"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Errorf("enrich.record bogus no-DB: eb=%v", eb)
	}
}
