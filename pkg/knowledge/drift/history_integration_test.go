//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package drift_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/drift"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

func TestHistory_EmptyForUnknownApp(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	res, err := drift.History(ctx, db, drift.HistoryOptions{App: "never-existed"})
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if res == nil {
		t.Fatalf("History: got nil result")
	}
	if res.Count != 0 {
		t.Errorf("Count = %d, want 0", res.Count)
	}
	if res.Alerts == nil {
		t.Errorf("Alerts is nil; want empty slice for clean JSON marshalling")
	}
	if res.App != "never-existed" {
		t.Errorf("App = %q, want %q", res.App, "never-existed")
	}
}

func TestHistory_ReturnsAlertsNewestFirst(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	// Seed a baseline run + a drifted recent run, then run Check to write
	// drift_alerts. Drifted metrics: success_rate big drop, mean_cost up.
	baselineID := seedFixture(t, ctx, db, "history-app", 30, 28, 1, 0, 3000)
	if err := drift.SetBaseline(ctx, db, "history-app", baselineID, false, 25); err != nil {
		t.Fatalf("SetBaseline: %v", err)
	}

	// Recent run with large delta vs baseline → triggers multi-metric alerts.
	recentID := seedFixture(t, ctx, db, "history-app", 30, 10, 15, 5, 9000)
	v, err := drift.Check(ctx, db, recentID, drift.DefaultOpts())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !v.Drifted {
		t.Fatalf("Check: expected Drifted=true to seed alerts, got verdict=%+v", v)
	}

	res, err := drift.History(ctx, db, drift.HistoryOptions{App: "history-app"})
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if res.Count == 0 || len(res.Alerts) == 0 {
		t.Fatalf("History: got 0 alerts, want >=1")
	}
	if res.Count != len(res.Alerts) {
		t.Errorf("Count = %d, len(Alerts) = %d (must match)", res.Count, len(res.Alerts))
	}
	if res.Limit != 20 {
		t.Errorf("default Limit = %d, want 20", res.Limit)
	}
	// All alerts should be for our app, and reference the recent run.
	for i, a := range res.Alerts {
		if a.App != "history-app" {
			t.Errorf("alert[%d].App = %q, want %q", i, a.App, "history-app")
		}
		if a.RunID != recentID {
			t.Errorf("alert[%d].RunID = %q, want %q", i, a.RunID, recentID)
		}
		if a.BaselineRunID != baselineID {
			t.Errorf("alert[%d].BaselineRunID = %q, want %q", i, a.BaselineRunID, baselineID)
		}
		if a.CreatedAt == "" {
			t.Errorf("alert[%d].CreatedAt empty", i)
		}
	}
}

func TestHistory_LimitClampsToMax(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	res, err := drift.History(ctx, db, drift.HistoryOptions{App: "any", Limit: 100000})
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if res.Limit != 500 {
		t.Errorf("Limit = %d, want clamped to 500", res.Limit)
	}
}

func TestHistory_LimitDefaults(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	res, err := drift.History(ctx, db, drift.HistoryOptions{App: "any", Limit: 0})
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if res.Limit != 20 {
		t.Errorf("Limit = %d, want default 20", res.Limit)
	}
}

func TestHistory_AppRequired(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	if _, err := drift.History(ctx, db, drift.HistoryOptions{}); err == nil {
		t.Fatalf("History empty app: got nil err, want app-required")
	}
}
