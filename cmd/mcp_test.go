/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"strings"
	"testing"
)

func TestMcpServe_PrintsNotAutoRegisteredNotice(t *testing.T) {
	// The notice is emitted to stderr before the stdio loop starts.
	// Assert the exact substring is present in the serve command's startup log.
	const want = "not auto-registered"
	if !strings.Contains(mcpServeStartupNotice(), want) {
		t.Fatalf("serve notice missing %q", want)
	}
}
