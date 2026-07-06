/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"strings"
	"testing"
)

func TestFormatFallbackBanner_None(t *testing.T) {
	banner := FormatFallbackBanner(75, FallbackNone)
	if banner != "" {
		t.Errorf("expected empty banner for FallbackNone, got %q", banner)
	}
}

func TestFormatFallbackBanner_FTS(t *testing.T) {
	banner := FormatFallbackBanner(0, FallbackFTSOverBodies)
	if !strings.Contains(banner, "enrichment coverage 0%") {
		t.Errorf("banner missing coverage: %q", banner)
	}
	if !strings.Contains(banner, "falling back to FTS") {
		t.Errorf("banner missing fallback phrase: %q", banner)
	}
}

func TestFormatFallbackBanner_FTS_PartialCoverage(t *testing.T) {
	banner := FormatFallbackBanner(42, FallbackFTSOverBodies)
	if !strings.Contains(banner, "42%") {
		t.Errorf("banner missing coverage pct: %q", banner)
	}
}

func TestFallbackKindConstants(t *testing.T) {
	if string(FallbackNone) != "none" {
		t.Errorf("FallbackNone = %q, want 'none'", FallbackNone)
	}
	if string(FallbackFTSOverBodies) != "fts_over_bodies" {
		t.Errorf("FallbackFTSOverBodies = %q, want 'fts_over_bodies'", FallbackFTSOverBodies)
	}
}
