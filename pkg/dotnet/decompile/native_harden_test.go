/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"strings"
	"testing"
)

// TestSafeExtractModules_RecoversPanic confirms the recover guard converts a
// panic from clr.ExtractModules (here triggered by a nil image, standing in for
// a hostile PE that drives the metadata decoders into a panic) into an error
// instead of crashing the process. Finding #26.
func TestSafeExtractModules_RecoversPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("safeExtractModules let a panic escape: %v", r)
		}
	}()

	_, err := safeExtractModules(nil)
	if err == nil {
		t.Fatalf("expected error from panicking ExtractModules, got nil")
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("expected a recovered-panic error, got %v", err)
	}
}
