/*
Copyright (c) 2026 Security Research
*/
package cmd

import "testing"

func TestStale(t *testing.T) {
	const day = 24 * 60 * 60 * 1000
	now := int64(1_000_000_000_000)
	if stale(now-2*day, now, day) != true {
		t.Error("2-day-old should be stale")
	}
	if stale(now-day/2, now, day) != false {
		t.Error("12h-old should be fresh")
	}
	if stale(0, now, day) != true {
		t.Error("never-synced (0) should be stale")
	}
}
