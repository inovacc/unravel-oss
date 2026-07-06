//go:build windows

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
	p := filepath.Join(dir, name+".bat")
	// Translate common shell commands to batch equivalents
	batch := "@echo off\n"
	switch {
	case body == "exit 0":
		batch += "exit /b 0\n"
	case body == "exit 1":
		batch += "exit /b 1\n"
	case len(body) > 5 && body[:5] == "echo " && !contains(body, ">&2") && !contains(body, "exit"):
		batch += fmt.Sprintf("echo %s\nexit /b 0\n", body[5:])
	default:
		// For complex shell bodies, translate exit codes and stderr redirection
		b := body
		b = replaceAll(b, "exit 0", "exit /b 0")
		b = replaceAll(b, "exit 1", "exit /b 1")
		b = replaceAll(b, "exit 2", "exit /b 2")
		b = replaceAll(b, ">&2", "1>&2")
		b = replaceAll(b, "echo '", "echo ")
		b = replaceAll(b, "' 1>&2", " 1>&2")
		b = replaceAll(b, "; ", "\n")
		batch += b + "\n"
	}
	if err := os.WriteFile(p, []byte(batch), 0o755); err != nil {
		t.Fatalf("write mock script %s: %v", name, err)
	}
	return p
}

func writeMockVersionScript(t *testing.T, dir, name, output string) string {
	t.Helper()
	p := filepath.Join(dir, name+".bat")
	script := fmt.Sprintf("@echo off\necho %s\n", output)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock script %s: %v", name, err)
	}
	return p
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func replaceAll(s, old, new string) string {
	result := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return result + s
		}
		result += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
