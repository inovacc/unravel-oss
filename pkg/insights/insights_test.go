/*
Copyright (c) 2026 Security Research
*/
package insights

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecordRoundtrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("UNRAVEL_INSIGHTS_ROOT", tmp)
	t.Setenv("UNRAVEL_INSIGHTS", "")

	ev := Event{Type: EventCommandInvoked, SessionID: "s1", Payload: map[string]any{"cmd": "unravel doctor"}}
	if err := Record(ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	day := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(tmp, SubdirEvents, day+".jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	line := strings.TrimSpace(string(raw))
	var got Event
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("parse line: %v", err)
	}
	if got.Type != EventCommandInvoked || got.SessionID != "s1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.Payload["cmd"] != "unravel doctor" {
		t.Fatalf("payload lost: %+v", got.Payload)
	}
}

func TestIsDisabled(t *testing.T) {
	for _, v := range []string{"off", "0", "false", "DISABLED"} {
		t.Setenv("UNRAVEL_INSIGHTS", v)
		if !IsDisabled() {
			t.Errorf("expected disabled for %q", v)
		}
	}
	t.Setenv("UNRAVEL_INSIGHTS", "")
	if IsDisabled() {
		t.Errorf("default should be enabled")
	}
}

func TestDisabledSuppressesWrites(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("UNRAVEL_INSIGHTS_ROOT", tmp)
	t.Setenv("UNRAVEL_INSIGHTS", "off")
	if err := Record(Event{Type: EventCommandInvoked}); err != nil {
		t.Fatalf("Record should be silent when disabled: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(tmp, SubdirEvents))
	if len(entries) != 0 {
		t.Errorf("disabled mode should write 0 files, got %d", len(entries))
	}
}

func TestStartGoalIdempotent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("UNRAVEL_INSIGHTS_ROOT", tmp)
	t.Setenv("UNRAVEL_INSIGHTS", "")
	g1, err := StartGoal("enrich teams 25")
	if err != nil {
		t.Fatalf("StartGoal: %v", err)
	}
	g2, err := StartGoal("enrich teams 25")
	if err != nil {
		t.Fatalf("StartGoal idempotent: %v", err)
	}
	if g1.GoalID != g2.GoalID {
		t.Errorf("expected same goal_id, got %s vs %s", g1.GoalID, g2.GoalID)
	}
	if !strings.Contains(g1.GoalID, "enrich-teams-25") {
		t.Errorf("goal id should encode name slug: %s", g1.GoalID)
	}
}

func TestCompleteGoal(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("UNRAVEL_INSIGHTS_ROOT", tmp)
	t.Setenv("UNRAVEL_INSIGHTS", "")
	g, _ := StartGoal("smoke goal")
	if err := CompleteGoal(g.GoalID, OutcomeSuccess); err != nil {
		t.Fatalf("CompleteGoal: %v", err)
	}
	path := filepath.Join(tmp, SubdirGoals, g.GoalID+".json")
	raw, _ := os.ReadFile(path)
	var got Goal
	_ = json.Unmarshal(raw, &got)
	if got.Outcome != OutcomeSuccess {
		t.Errorf("outcome not persisted: %s", got.Outcome)
	}
	if got.CompletedAt == nil {
		t.Errorf("completed_at not set")
	}
}
