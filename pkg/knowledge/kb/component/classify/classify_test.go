/*
Copyright (c) 2026 Security Research
*/

package classify

import (
	"context"
	"strings"
	"testing"
)

// TestRun_EmptyKBID asserts that an empty kb_id is rejected before any DB
// access.
func TestRun_EmptyKBID(t *testing.T) {
	rep, err := Run(context.Background(), nil, "", 0)
	if err == nil {
		t.Fatalf("expected error for empty kb_id, got rep=%+v", rep)
	}
	if !strings.Contains(err.Error(), "kb_id") {
		t.Fatalf("expected error mentioning kb_id, got %v", err)
	}
	if rep != nil {
		t.Fatalf("expected nil report, got %+v", rep)
	}
}

// TestReport_ZeroValue documents the Report shape so future migrations to
// pgx-native types stay source-compatible.
func TestReport_ZeroValue(t *testing.T) {
	r := Report{KBID: "k1", BucketCounts: map[string]int{}}
	if r.KBID != "k1" {
		t.Fatalf("kb_id round-trip failed")
	}
	if r.ModulesClassified != 0 || r.Skipped != 0 {
		t.Fatalf("zero-value counters expected, got classified=%d skipped=%d",
			r.ModulesClassified, r.Skipped)
	}
	if r.BucketCounts == nil {
		t.Fatalf("BucketCounts must be non-nil for the JSON encoder to emit {}")
	}
}
