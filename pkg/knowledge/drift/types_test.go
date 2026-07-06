/*
Copyright (c) 2026 Security Research
*/
package drift

import "testing"

func TestDefaultOpts(t *testing.T) {
	o := DefaultOpts()
	if o.ThresholdRelative != 0.20 {
		t.Errorf("ThresholdRelative = %v, want 0.20", o.ThresholdRelative)
	}
	if o.MinRunSize != 25 {
		t.Errorf("MinRunSize = %d, want 25", o.MinRunSize)
	}
	if o.Now == nil {
		t.Errorf("Now func is nil; expected non-nil for testability")
	}
	// Confirm Now is a real, callable time.Now
	got := o.Now()
	if got.IsZero() {
		t.Errorf("o.Now() returned zero time")
	}
}
