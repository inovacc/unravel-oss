//go:build !windows

/* Copyright (c) 2026 Security Research */
package httpshell

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestHandleExec_NonZeroExit(t *testing.T) {
	s := newTestServer(t)

	body := `{"command":"exit 42"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleExec non-zero exit status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp CommandResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("HandleExec response is not valid JSON: %v", err)
	}

	if resp.ExitCode != 42 {
		t.Errorf("HandleExec exit_code = %d, want 42", resp.ExitCode)
	}
}

func TestHandleCD_ForbiddenPath(t *testing.T) {
	s := newTestServer(t)

	body := `{"path":"/etc/passwd"}`
	req := httptest.NewRequest(http.MethodPost, "/cd", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleCD(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("HandleCD forbidden path status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("HandleCD error response is not valid JSON: %v", err)
	}

	if apiErr.Code != "PATH_FORBIDDEN" {
		t.Errorf("HandleCD error code = %q, want %q", apiErr.Code, "PATH_FORBIDDEN")
	}
}

func TestHandleCD_NotADirectory(t *testing.T) {
	s := newTestServer(t)

	// Create a file (not a directory) within an allowed path.
	f, err := os.CreateTemp("/home/dyam", "httpshell-file-*")
	if err != nil {
		t.Fatalf("TestHandleCD_NotADirectory: failed to create temp file: %v", err)
	}

	_ = f.Close()

	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	body := fmt.Sprintf(`{"path":%q}`, f.Name())
	req := httptest.NewRequest(http.MethodPost, "/cd", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleCD(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("HandleCD on file path status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("HandleCD error response is not valid JSON: %v", err)
	}

	if apiErr.Code != "NOT_A_DIRECTORY" {
		t.Errorf("HandleCD error code = %q, want %q", apiErr.Code, "NOT_A_DIRECTORY")
	}
}

func TestExecuteCommand_NonZeroExitCode(t *testing.T) {
	s := newTestServer(t)

	resp := s.ExecuteCommand(CommandRequest{Command: "exit 7"})

	if resp.ExitCode != 7 {
		t.Errorf("ExecuteCommand exit_code = %d, want 7", resp.ExitCode)
	}

	if resp.Error == "" {
		t.Error("ExecuteCommand expected non-empty Error field for failing command")
	}
}

func TestExecuteCommand_WithStderr(t *testing.T) {
	s := newTestServer(t)

	resp := s.ExecuteCommand(CommandRequest{Command: "echo out && echo err >&2"})

	if !strings.Contains(resp.Output, "out") {
		t.Errorf("ExecuteCommand output = %q, expected to contain 'out'", resp.Output)
	}

	if !strings.Contains(resp.Output, "err") {
		t.Errorf("ExecuteCommand output = %q, expected stderr 'err' merged in", resp.Output)
	}
}

// TestExecuteCommand_ServerShellUsed verifies that ExecuteCommand uses the
// server-detected shell (the Shell field has been removed from CommandRequest).
func TestExecuteCommand_ServerShellUsed(t *testing.T) {
	s := newTestServer(t)

	// The server was set up with /bin/sh; echo must still work.
	resp := s.ExecuteCommand(CommandRequest{Command: "echo custom"})

	if !strings.Contains(resp.Output, "custom") {
		t.Errorf("ExecuteCommand output = %q, want it to contain 'custom'", resp.Output)
	}
}

func TestExecuteCommand_Timeout(t *testing.T) {
	s := newTestServer(t)

	resp := s.ExecuteCommand(CommandRequest{
		Command: "sleep 10",
		Timeout: 1,
	})

	if resp.ExitCode != -1 {
		t.Errorf("ExecuteCommand timeout exit_code = %d, want -1", resp.ExitCode)
	}

	if resp.Error != "Command timed out" {
		t.Errorf("ExecuteCommand timeout error = %q, want %q", resp.Error, "Command timed out")
	}
}

func TestExecuteCommand_WithWorkDir(t *testing.T) {
	s := newTestServer(t)

	resp := s.ExecuteCommand(CommandRequest{
		Command: "pwd",
		WorkDir: s.WorkDir,
	})

	if resp.ExitCode != 0 {
		t.Errorf("ExecuteCommand with workdir exit_code = %d, want 0", resp.ExitCode)
	}

	if !strings.Contains(resp.Output, s.WorkDir) {
		t.Errorf("ExecuteCommand pwd output = %q, want it to contain %q", resp.Output, s.WorkDir)
	}
}

func TestExecuteCommand_WithStderrNoNewline(t *testing.T) {
	s := newTestServer(t)

	// printf with no trailing newline on stdout, plus stderr output.
	resp := s.ExecuteCommand(CommandRequest{Command: `printf 'out' && echo err >&2`})

	if !strings.Contains(resp.Output, "out") {
		t.Errorf("ExecuteCommand output = %q, expected 'out'", resp.Output)
	}

	if !strings.Contains(resp.Output, "err") {
		t.Errorf("ExecuteCommand output = %q, expected merged stderr 'err'", resp.Output)
	}
}

func TestDetectShell_ShellsExist(t *testing.T) {
	s := &Server{}
	s.DetectShell()

	// On Linux the shell must be one of the expected paths or the fallback.
	validShells := map[string]bool{
		"/bin/bash": true,
		"/bin/zsh":  true,
		"/bin/sh":   true,
		"sh":        true, // default branch fallback
	}

	if !validShells[s.Shell] {
		t.Errorf("DetectShell() shell = %q, expected one of the known shells", s.Shell)
	}
}
