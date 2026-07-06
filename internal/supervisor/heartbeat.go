/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"time"
)

// heartbeatTimeout — sessions whose LastHeartbeat is older than this
// are reaped.
const heartbeatTimeout = 60 * time.Second

// heartbeatReaper periodically scans the session map and reaps sessions
// whose heartbeat is older than heartbeatTimeout. Called from Start().
func (sv *Supervisor) heartbeatReaper(ctx context.Context) {
	defer sv.wg.Done()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sv.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			sv.reapStaleSessions()
		}
	}
}

func (sv *Supervisor) reapStaleSessions() {
	now := sv.now()
	cutoff := now.Add(-heartbeatTimeout)

	// Collect victims under the read lock, then detach them through the
	// normal detachSession path so workspace ref-counts stay consistent.
	sv.sessionsMu.RLock()
	victims := make([]string, 0)
	for id, s := range sv.sessions {
		if s.LastHeartbeat.Before(cutoff) {
			victims = append(victims, id)
		}
	}
	sv.sessionsMu.RUnlock()

	for _, id := range victims {
		if sv.detachSession(id) {
			sv.cfg.Logger.Info("supervisor: reaped stale session", "session_id", id)
		}
	}
}
