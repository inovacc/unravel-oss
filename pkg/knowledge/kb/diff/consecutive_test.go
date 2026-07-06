/*
Copyright (c) 2026 Security Research
*/

package diff

import (
	"context"
	"strings"
	"testing"
)

// TestConsecutive_Validation verifies the consecutive-only contract
// (D-30-DIFF-WRITES-ONLY-CONSECUTIVE). Full integration (real PG, real
// app_facts rows) is exercised by Plan 30-03 ingest tests.
func TestConsecutive_Validation(t *testing.T) {
	cases := []struct {
		name             string
		prev, this       int64
		wantErrSubstring string
	}{
		{"gap > 1 rejected", int64(1), int64(3), "thisEpoch==prevEpoch+1"},
		{"reverse rejected", int64(5), int64(4), "thisEpoch==prevEpoch+1"},
		{"equal rejected", int64(2), int64(2), "thisEpoch==prevEpoch+1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// nil tx is safe: validation runs before any DB call.
			_, err := ComputeConsecutive(context.Background(), nil, "kb-x", c.prev, c.this)
			if err == nil {
				t.Fatalf("expected error for prev=%d this=%d", c.prev, c.this)
			}
			if !strings.Contains(err.Error(), c.wantErrSubstring) {
				t.Fatalf("error %q missing substring %q", err.Error(), c.wantErrSubstring)
			}
		})
	}
}
