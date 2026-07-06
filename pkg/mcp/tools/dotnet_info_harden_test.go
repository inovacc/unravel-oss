/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"strings"
	"testing"
)

// TestSafeExtractModules_RecoversPanic confirms the dotnet_info recover guard
// converts a panic from clr.ExtractModules (triggered here by a nil image,
// standing in for a hostile PE) into an error rather than letting it escape the
// MCP handler goroutine and crash the server process. Finding #26.
func TestSafeExtractModules_RecoversPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("safeExtractModules let a panic escape: %v", r)
		}
	}()

	_, _, _, _, err := safeExtractModules(nil)
	if err == nil {
		t.Fatalf("expected error from panicking ExtractModules, got nil")
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("expected a recovered-panic error, got %v", err)
	}
}
