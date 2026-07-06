/*
Copyright (c) 2026 Security Research
*/
package cve

import "sync"

// LatestProber registry. Per-ecosystem packages call RegisterLatestProber in
// their init() to wire concrete implementations. Idempotent: a second
// registration for an already-registered Ecosystem is silently dropped so
// test harnesses that re-init don't panic.

var (
	probersMu sync.RWMutex
	probers   []LatestProber
)

// RegisterLatestProber registers p in the global registry. If an entry for
// p.Ecosystem() is already present, the call is a no-op (idempotent).
func RegisterLatestProber(p LatestProber) {
	if p == nil {
		return
	}
	probersMu.Lock()
	defer probersMu.Unlock()
	for _, existing := range probers {
		if existing.Ecosystem() == p.Ecosystem() {
			return
		}
	}
	probers = append(probers, p)
}

// proberFor returns the registered prober for eco, or nil if none registered.
func proberFor(eco Ecosystem) LatestProber {
	probersMu.RLock()
	defer probersMu.RUnlock()
	for _, p := range probers {
		if p.Ecosystem() == eco {
			return p
		}
	}
	return nil
}
