//go:build windows

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

func TestHandleExec_NonZeroExit_Windows(t *testing.T) {
	s := newTestServer(t)

	body := `{"command":"exit /b 42"}`
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

func TestExecuteCommand_NonZeroExitCode_Windows(t *testing.T) {
	s := newTestServer(t)

	resp := s.ExecuteCommand(CommandRequest{Command: "exit /b 7"})

	if resp.ExitCode != 7 {
		t.Errorf("ExecuteCommand exit_code = %d, want 7", resp.ExitCode)
	}

	if resp.Error == "" {
		t.Error("ExecuteCommand expected non-empty Error field for failing command")
	}
}

func TestDetectShell_ShellsExist_Windows(t *testing.T) {
	s := &Server{}
	s.DetectShell()

	validShells := map[string]bool{
		"powershell.exe": true,
		"cmd.exe":        true,
		"sh":             true,
	}

	if !validShells[s.Shell] {
		t.Errorf("DetectShell() shell = %q, expected one of the known Windows shells", s.Shell)
	}
}

func TestExecuteCommand_WithStderr_Windows(t *testing.T) {
	s := newTestServer(t)

	resp := s.ExecuteCommand(CommandRequest{Command: "echo out & echo err >&2"})

	if !strings.Contains(resp.Output, "out") {
		t.Errorf("ExecuteCommand output = %q, expected to contain 'out'", resp.Output)
	}
}

func TestExecuteCommand_WithWorkDir_Windows(t *testing.T) {
	s := newTestServer(t)

	resp := s.ExecuteCommand(CommandRequest{
		Command: "cd",
		WorkDir: s.WorkDir,
	})

	if resp.ExitCode != 0 {
		t.Errorf("ExecuteCommand with workdir exit_code = %d, want 0", resp.ExitCode)
	}
}

func TestExecuteCommand_Timeout_Windows(t *testing.T) {
	s := newTestServer(t)

	resp := s.ExecuteCommand(CommandRequest{
		Command: "ping -n 10 127.0.0.1",
		Timeout: 1,
	})

	if resp.ExitCode != -1 {
		t.Errorf("ExecuteCommand timeout exit_code = %d, want -1", resp.ExitCode)
	}

	if resp.Error != "Command timed out" {
		t.Errorf("ExecuteCommand timeout error = %q, want %q", resp.Error, "Command timed out")
	}
}

// TestExecuteCommand_ServerShellUsed_Windows verifies that ExecuteCommand uses
// the server-detected shell (the Shell field has been removed from CommandRequest).
func TestExecuteCommand_ServerShellUsed_Windows(t *testing.T) {
	s := newTestServer(t)

	// The server was set up with cmd.exe on Windows; echo must still work.
	resp := s.ExecuteCommand(CommandRequest{Command: "echo custom"})

	if !strings.Contains(resp.Output, "custom") {
		t.Errorf("ExecuteCommand output = %q, want it to contain 'custom'", resp.Output)
	}
}

// TestExecuteCommand_PowershellCommand_Windows verifies that powershell commands
// work when the server has detected powershell as the shell.
func TestExecuteCommand_PowershellCommand_Windows(t *testing.T) {
	s := newTestServer(t)

	// Override server shell to powershell for this test.
	s.Shell = "powershell.exe"
	s.ShellArgs = []string{"-NoLogo", "-NoProfile", "-Command"}

	resp := s.ExecuteCommand(CommandRequest{Command: "Write-Output 'pshello'"})

	if !strings.Contains(resp.Output, "pshello") {
		t.Errorf("ExecuteCommand with powershell output = %q, want 'pshello'", resp.Output)
	}
}

func TestHandleCD_NotADirectory_Windows(t *testing.T) {
	s := newTestServer(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	f, err := os.CreateTemp(home, "httpshell-file-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
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

func TestHandleCD_ForbiddenPath_Windows(t *testing.T) {
	s := newTestServer(t)

	body := `{"path":"C:\\Windows\\System32"}`
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
