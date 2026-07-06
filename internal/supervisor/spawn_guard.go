/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// ErrSpawnLoopDetected is returned when the spawn guard refuses to
// start a new daemon process due to too many recent failures.
var ErrSpawnLoopDetected = errors.New("supervisor: spawn-loop detected (3 failures in last 10s)")

// SpawnEvent records one supervisor spawn attempt.
type SpawnEvent struct {
	TS       time.Time `json:"ts"`
	ExitCode int       `json:"exit_code"`
}

// SpawnHistory is a sliding-window of recent SpawnEvents persisted to
// $SocketDir/spawn-history.json.
type SpawnHistory struct {
	mu     sync.Mutex
	path   string
	events []SpawnEvent
	now    func() time.Time
}

// NewSpawnHistory loads any existing history from path; missing file is
// treated as empty.
func NewSpawnHistory(path string) (*SpawnHistory, error) {
	sh := &SpawnHistory{path: path, now: time.Now}
	if data, err := os.ReadFile(path); err == nil {
		if uerr := json.Unmarshal(data, &sh.events); uerr != nil {
			// A corrupt/truncated history (e.g. a crash mid-write) must not be
			// silently swallowed: that would leave the crash-loop guard starting
			// from an empty window precisely when the failures it exists to
			// detect are happening.
			return nil, fmt.Errorf("unmarshal spawn history: %w", uerr)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read spawn history: %w", err)
	}
	return sh, nil
}

// CheckGuard returns ErrSpawnLoopDetected if there are >= 3 failure events
// in the last 10 seconds. Read-only.
func (sh *SpawnHistory) CheckGuard() error {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	cutoff := sh.now().Add(-10 * time.Second)
	failures := 0
	for _, e := range sh.events {
		if e.TS.After(cutoff) && e.ExitCode != 0 {
			failures++
		}
	}
	if failures >= 3 {
		return ErrSpawnLoopDetected
	}
	return nil
}

// Record appends an event and persists. Events older than 60s are pruned.
func (sh *SpawnHistory) Record(exitCode int) error {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	cutoff := sh.now().Add(-60 * time.Second)
	pruned := sh.events[:0]
	for _, e := range sh.events {
		if e.TS.After(cutoff) {
			pruned = append(pruned, e)
		}
	}
	pruned = append(pruned, SpawnEvent{TS: sh.now(), ExitCode: exitCode})
	sh.events = pruned
	data, err := json.MarshalIndent(sh.events, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(sh.path, data, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}
