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

func TestDriftVerbs_AllRegistered(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = sv.Stop() }()

	want := []string{
		"drift.check",
		"drift.baseline",
		"drift.history",
	}
	for _, v := range want {
		if !sv.HasVerb(v) {
			t.Errorf("supervisor missing verb %q", v)
		}
	}
}

func TestDriftVerbs_NoDBReturnsUnavailable(t *testing.T) {
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
		{"check", sv.driftCheck, DriftCheckParams{App: "x"}},
		{"baseline-set", sv.driftBaseline, DriftBaselineParams{Action: "set", App: "x", RunID: "00000000-0000-0000-0000-000000000001"}},
		{"baseline-clear", sv.driftBaseline, DriftBaselineParams{Action: "clear", App: "x"}},
		{"baseline-show", sv.driftBaseline, DriftBaselineParams{Action: "show", App: "x"}},
		{"history", sv.driftHistory, DriftHistoryParams{App: "x"}},
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

func TestDriftVerbs_BadParamShape(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})
	defer func() { _ = sv.Stop() }()

	// All no-DB short-circuits run first — mirrors the kb.*/enrich.* pattern.
	// drift.check with empty body → CodeUnavailable wins over missing-app.
	_, eb := sv.driftCheck(context.Background(), mustJSON(t, DriftCheckParams{}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Errorf("drift.check empty no-DB: eb=%v", eb)
	}

	// drift.baseline with bogus action → CodeUnavailable wins.
	_, eb = sv.driftBaseline(context.Background(), mustJSON(t, DriftBaselineParams{Action: "bogus", App: "x"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Errorf("drift.baseline bogus no-DB: eb=%v", eb)
	}

	// drift.history with missing app → CodeUnavailable wins.
	_, eb = sv.driftHistory(context.Background(), mustJSON(t, DriftHistoryParams{}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Errorf("drift.history empty no-DB: eb=%v", eb)
	}
}
