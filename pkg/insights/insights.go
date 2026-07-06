/*
Copyright (c) 2026 Security Research
*/

package insights

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EventType enumerates recorded event kinds. See SPEC.
type EventType string

const (
	EventCommandInvoked   EventType = "command_invoked"
	EventMCPToolCall      EventType = "mcp_tool_call"
	EventTaskDispatched   EventType = "task_dispatched"
	EventSubagentReturned EventType = "subagent_returned"
	EventRetry            EventType = "retry"
	EventFailure          EventType = "failure"
	EventGoalStarted      EventType = "goal_started"
	EventGoalCompleted    EventType = "goal_completed"
)

// Event is one record in events/YYYY-MM-DD.jsonl.
type Event struct {
	TS        time.Time      `json:"ts"`
	SessionID string         `json:"session_id"`
	GoalID    string         `json:"goal_id,omitempty"`
	Type      EventType      `json:"event_type"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// Outcome of a goal lifecycle.
type Outcome string

const (
	OutcomeSuccess   Outcome = "success"
	OutcomePartial   Outcome = "partial"
	OutcomeAbandoned Outcome = "abandoned"
)

// Goal envelope persisted at goals/<goal-id>.json.
type Goal struct {
	GoalID      string     `json:"goal_id"`
	Name        string     `json:"name"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Outcome     Outcome    `json:"outcome,omitempty"`
	Jumps       int        `json:"jumps"`
	Friction    int        `json:"friction"`
	EventsSeen  []string   `json:"events_seen,omitempty"`
}

// IsDisabled reports whether insights capture is suppressed via env.
// Default behaviour is enabled; set UNRAVEL_INSIGHTS=off to opt out.
func IsDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("UNRAVEL_INSIGHTS")))
	return v == "off" || v == "0" || v == "false" || v == "disabled"
}

var writeMu sync.Mutex

// Record appends one event to today's events/*.jsonl file. Safe to
// call from multiple goroutines via an internal mutex. Returns nil
// (silent) if insights is disabled.
func Record(ev Event) error {
	if IsDisabled() {
		return nil
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	if ev.Type == "" {
		return errors.New("insights: event_type required")
	}
	dir, err := SubPath(SubdirEvents)
	if err != nil {
		return err
	}
	day := ev.TS.UTC().Format("2006-01-02")
	path := filepath.Join(dir, day+".jsonl")

	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("insights: marshal: %w", err)
	}
	line = append(line, '\n')

	writeMu.Lock()
	defer writeMu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("insights: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("insights: write: %w", err)
	}
	return nil
}

// StartGoal creates (or returns existing) a goal envelope by ID derived
// from name + day. Idempotent: re-calling on the same day returns the
// already-opened goal.
func StartGoal(name string) (Goal, error) {
	if IsDisabled() {
		return Goal{}, nil
	}
	id := stableGoalID(name)
	dir, err := SubPath(SubdirGoals)
	if err != nil {
		return Goal{}, err
	}
	path := filepath.Join(dir, id+".json")
	if existing, err := readGoal(path); err == nil {
		return existing, nil
	}
	g := Goal{
		GoalID:    id,
		Name:      name,
		StartedAt: time.Now().UTC(),
	}
	if err := writeGoal(path, g); err != nil {
		return Goal{}, err
	}
	_ = Record(Event{Type: EventGoalStarted, GoalID: id, Payload: map[string]any{"name": name}})
	return g, nil
}

// CompleteGoal stamps the envelope with completed_at + outcome and
// emits a goal_completed event. Reads existing goal first so
// jump/friction counters from later analysis can persist.
func CompleteGoal(goalID string, outcome Outcome) error {
	if IsDisabled() {
		return nil
	}
	dir, err := SubPath(SubdirGoals)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, goalID+".json")
	g, err := readGoal(path)
	if err != nil {
		return fmt.Errorf("insights: complete missing goal %s: %w", goalID, err)
	}
	now := time.Now().UTC()
	g.CompletedAt = &now
	g.Outcome = outcome
	if err := writeGoal(path, g); err != nil {
		return err
	}
	return Record(Event{Type: EventGoalCompleted, GoalID: goalID, Payload: map[string]any{"outcome": string(outcome)}})
}

// SessionID returns a hex random 16-byte session id, suitable for the
// SessionID field on events recorded from the same process lifetime.
func SessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func stableGoalID(name string) string {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		case r == ' ':
			return '-'
		}
		return -1
	}, name)
	if clean == "" {
		clean = "unnamed"
	}
	return time.Now().UTC().Format("20060102") + "-" + clean
}

func readGoal(path string) (Goal, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Goal{}, err
	}
	var g Goal
	if err := json.Unmarshal(raw, &g); err != nil {
		return Goal{}, fmt.Errorf("insights: parse %s: %w", path, err)
	}
	return g, nil
}

func writeGoal(path string, g Goal) error {
	out, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return fmt.Errorf("insights: write %s: %w", tmp, err)
	}
	return os.Rename(tmp, path)
}
