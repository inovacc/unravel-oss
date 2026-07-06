//go:build !windows

/* Copyright (c) 2026 Security Research */
package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeMockScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write mock script %s: %v", name, err)
	}
	return p
}

func writeMockVersionScript(t *testing.T, dir, name, output string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\necho '%s'\n", output)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock script %s: %v", name, err)
	}
	return p
}
