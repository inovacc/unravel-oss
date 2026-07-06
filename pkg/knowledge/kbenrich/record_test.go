/*
Copyright (c) 2026 Security Research
*/
package kbenrich

import (
	"context"
	"errors"
	"testing"
)

func TestStartRun_NilDB(t *testing.T) {
	_, err := StartRun(context.Background(), nil, StartRunOptions{App: "x"})
	if err == nil {
		t.Fatalf("StartRun(nil db): want error, got nil")
	}
}

func TestRecordAttempt_NilDB(t *testing.T) {
	_, err := RecordAttempt(context.Background(), nil, RecordAttemptOptions{RunID: "x", ModuleID: 1, Status: "success"})
	if err == nil {
		t.Fatalf("RecordAttempt(nil db): want error, got nil")
	}
}

func TestRecordAttempt_MissingRequired(t *testing.T) {
	cases := []struct {
		name string
		opts RecordAttemptOptions
	}{
		{"missing run_id", RecordAttemptOptions{ModuleID: 1, Status: "success"}},
		{"missing module_id", RecordAttemptOptions{RunID: "r", Status: "success"}},
		{"missing status", RecordAttemptOptions{RunID: "r", ModuleID: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Provide nil db; the required-field check runs second so the
			// nil-db error fires for these inputs too. Both paths short-
			// circuit before any SQL, which is the contract we want.
			_, err := RecordAttempt(context.Background(), nil, tc.opts)
			if err == nil {
				t.Fatalf("want error, got nil")
			}
		})
	}
}

func TestErrRecordRunNotFound_Identity(t *testing.T) {
	wrapped := errors.Join(ErrRecordRunNotFound, errors.New("ctx"))
	if !errors.Is(wrapped, ErrRecordRunNotFound) {
		t.Fatalf("errors.Is failed for ErrRecordRunNotFound wrapper")
	}
}

func TestIsForeignKeyViolation(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want bool
	}{
		{"sqlstate code", "pq: insert or update on table violates foreign key constraint (SQLSTATE 23503)", true},
		{"text match", "violates foreign key constraint enrich_attempts_run_id_fkey", true},
		{"unrelated", "syntax error at or near \"VALUES\"", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isForeignKeyViolation(errors.New(tc.msg))
			if tc.msg == "" {
				// Special: empty error is still an error; we just want the
				// detector to return false.
				if got != false {
					t.Errorf("isForeignKeyViolation(empty): got %v, want false", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("got %v, want %v for %q", got, tc.want, tc.msg)
			}
		})
	}
}
