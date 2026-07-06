/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"testing"
	"time"
)

func TestReapStaleSessions(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})

	now := time.Now()
	sv.now = func() time.Time { return now }

	// Inject sessions: one fresh, one stale.
	sv.sessionsMu.Lock()
	sv.sessions["fresh"] = &SessionRecord{
		SessionID: "fresh", LastHeartbeat: now.Add(-30 * time.Second),
	}
	sv.sessions["stale"] = &SessionRecord{
		SessionID: "stale", LastHeartbeat: now.Add(-90 * time.Second),
	}
	sv.sessionsMu.Unlock()

	sv.reapStaleSessions()

	sv.sessionsMu.RLock()
	defer sv.sessionsMu.RUnlock()
	if _, ok := sv.sessions["fresh"]; !ok {
		t.Errorf("fresh session reaped (incorrectly)")
	}
	if _, ok := sv.sessions["stale"]; ok {
		t.Errorf("stale session NOT reaped")
	}
}
