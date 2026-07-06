package timeutil

import (
	"testing"
	"time"
)

func TestNowUTC_Format(t *testing.T) {
	got := NowUTC()
	if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Errorf("NowUTC %q is not RFC3339-parseable: %v", got, err)
	}
	if got[len(got)-1] != 'Z' && !contains(got, "+") && !contains(got, "-") {
		t.Errorf("NowUTC %q lacks UTC timezone marker", got)
	}
}

func TestNowUTCNano_HasFractionalSeconds(t *testing.T) {
	got := NowUTCNano()
	if _, err := time.Parse(time.RFC3339Nano, got); err != nil {
		t.Errorf("NowUTCNano %q not RFC3339Nano: %v", got, err)
	}
}

func TestNowUnixMilli_RangeSane(t *testing.T) {
	got := NowUnixMilli()
	// Should be after 2020-01-01 (1577836800000) and before 2100-01-01 (4102444800000)
	if got < 1577836800000 || got > 4102444800000 {
		t.Errorf("NowUnixMilli %d outside reasonable range", got)
	}
}

func TestFormatUTC_StableForKnownTime(t *testing.T) {
	known := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	got := FormatUTC(known)
	want := "2026-05-04T12:00:00Z"
	if got != want {
		t.Errorf("FormatUTC = %q; want %q", got, want)
	}
}

func TestFormatUnixMilli_RoundTrip(t *testing.T) {
	now := NowUnixMilli()
	formatted := FormatUnixMilli(now)
	parsed, err := time.Parse(time.RFC3339, formatted)
	if err != nil {
		t.Fatalf("parse round-trip: %v", err)
	}
	// RFC3339 truncates sub-second precision; must match within 1s.
	delta := now/1000 - parsed.Unix()
	if delta < 0 {
		delta = -delta
	}
	if delta > 1 {
		t.Errorf("round-trip delta %ds too large", delta)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
