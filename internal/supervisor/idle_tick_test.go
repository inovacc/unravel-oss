/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"testing"
	"time"
)

// TestIdleTickInterval pins the idle-watcher tick cadence and, critically, that
// it never returns a non-positive duration — time.NewTicker panics on <= 0, so
// a tiny or zero IdleTimeout (tests, misconfig) must floor to a safe minimum.
func TestIdleTickInterval(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"normal divides by six", 30 * time.Minute, 5 * time.Minute},
		{"zero floors to minimum", 0, time.Millisecond},
		{"sub-six-ns floors to minimum", 3 * time.Nanosecond, time.Millisecond},
		{"negative floors to minimum", -time.Second, time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := idleTickInterval(tt.timeout)
			if got != tt.want {
				t.Fatalf("idleTickInterval(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
			if got <= 0 {
				t.Fatalf("idleTickInterval(%v) = %v, must be > 0 (time.NewTicker would panic)", tt.timeout, got)
			}
		})
	}
}
