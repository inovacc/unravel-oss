package httpshell

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Log writes a timestamped log message
func (s *Server) Log(level, format string, args ...any) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] [%s] %s\n", timestamp, level, msg)
}

// WriteError writes a structured error response
func (s *Server) WriteError(w http.ResponseWriter, status int, code, message, details string) {
	s.Log("ERROR", "%s: %s", code, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIError{Code: code, Message: message, Details: details})
}

// DetectShell detects the system shell
func (s *Server) DetectShell() {
	switch runtime.GOOS {
	case "windows":
		if _, err := exec.LookPath("powershell.exe"); err == nil {
			s.Shell = "powershell.exe"
			s.ShellArgs = []string{"-NoLogo", "-NoProfile", "-Command"}
		} else {
			s.Shell = "cmd.exe"
			s.ShellArgs = []string{"/C"}
		}
	case "darwin", "linux", "freebsd", "openbsd", "netbsd":
		shells := []string{"/bin/bash", "/bin/zsh", "/bin/sh"}
		for _, sh := range shells {
			if _, err := os.Stat(sh); err == nil {
				s.Shell = sh
				s.ShellArgs = []string{"-c"}

				break
			}
		}

		if s.Shell == "" {
			s.Shell = "/bin/sh"
			s.ShellArgs = []string{"-c"}
		}
	default:
		s.Shell = "sh"
		s.ShellArgs = []string{"-c"}
	}
}

// WithMiddleware applies IP check, auth check, and logging
func (s *Server) WithMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAllowedIP(r.RemoteAddr) {
			s.Log("DENY", "%s -> IP not allowed", r.RemoteAddr)
			s.WriteError(w, http.StatusForbidden, "IP_FORBIDDEN", "IP address not allowed", "")

			return
		}

		authID := r.Header.Get("X-Auth-ID")
		if authID == "" {
			s.Log("AUTH", "%s -> Missing auth ID", r.RemoteAddr)
			s.WriteError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication required", "")

			return
		}

		if NormalizeAuthID(authID) != s.AuthID {
			s.Log("AUTH", "%s -> Invalid auth ID", r.RemoteAddr)
			s.WriteError(w, http.StatusUnauthorized, "AUTH_INVALID", "Invalid authentication", "")

			return
		}

		s.Log("CONN", "%s -> %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next(w, r)
	}
}

// HandleInfo handles the root endpoint
func (s *Server) HandleInfo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	hostname, _ := os.Hostname()
	info := ServerInfo{
		Version:  Version,
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
		Shell:    s.Shell,
		WorkDir:  s.WorkDir,
		Uptime:   time.Since(s.StartTime).Round(time.Second).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// HandleHealth handles the health endpoint
func (s *Server) HandleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// HandleExec handles command execution
func (s *Server) HandleExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.WriteError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", "")
		return
	}

	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", err.Error())
		return
	}

	if req.Command == "" {
		s.WriteError(w, http.StatusBadRequest, "INVALID_REQUEST", "Command required", "")
		return
	}

	if allowed, reason := IsCommandAllowed(req.Command); !allowed {
		s.Log("DENY", "Command blocked: %s - %s", req.Command, reason)
		s.WriteError(w, http.StatusForbidden, "COMMAND_FORBIDDEN", "Command not allowed", reason)

		return
	}

	effectiveWorkDir := s.WorkDir
	if req.WorkDir != "" {
		effectiveWorkDir = filepath.Clean(req.WorkDir)
	}

	if !IsAllowedPath(effectiveWorkDir) {
		s.Log("DENY", "WorkDir not allowed: %s", effectiveWorkDir)
		s.WriteError(w, http.StatusForbidden, "PATH_FORBIDDEN", "Working directory not allowed", "Allowed: /home/*, B:\\*, C:\\Users\\*")

		return
	}

	s.Log("EXEC", "%s -> %q (workdir: %s)", r.RemoteAddr, req.Command, effectiveWorkDir)

	startTime := time.Now()
	response := s.ExecuteCommand(req)
	duration := time.Since(startTime)

	s.Log("DONE", "%q exit=%d duration=%s", req.Command, response.ExitCode, duration.Round(time.Millisecond))

	s.Mu.Lock()

	s.CmdHistory = append(s.CmdHistory, response)
	if len(s.CmdHistory) > 1000 {
		s.CmdHistory = s.CmdHistory[1:]
	}

	s.Mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// ExecuteCommand runs a command and returns the response
func (s *Server) ExecuteCommand(req CommandRequest) CommandResponse {
	startTime := time.Now()

	response := CommandResponse{
		Command:   req.Command,
		Timestamp: startTime.Format(time.RFC3339),
		WorkDir:   s.WorkDir,
	}

	workDir := s.WorkDir
	if req.WorkDir != "" {
		workDir = req.WorkDir
	}

	// Security: always use the server-detected shell; never honour a
	// caller-supplied shell path. Accepting an arbitrary binary path from the
	// request body would allow any local process to run an arbitrary executable
	// on the analyst's host regardless of the command allowlist.
	shell := s.Shell
	shellArgs := s.ShellArgs

	args := append(shellArgs, req.Command) //nolint:gocritic // intentional slice growth
	cmd := exec.Command(shell, args...)
	cmd.Dir = workDir

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	timeout := 60 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	done := make(chan error, 1)

	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				response.ExitCode = exitErr.ExitCode()
			} else {
				response.ExitCode = 1
			}

			response.Error = err.Error()
		}
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}

		response.ExitCode = -1
		response.Error = "Command timed out"
	}

	output := stdout.String()
	if stderr.Len() > 0 {
		if output != "" && !strings.HasSuffix(output, "\n") {
			output += "\n"
		}

		output += stderr.String()
	}

	response.Output = output
	response.Duration = time.Since(startTime).Round(time.Millisecond).String()

	return response
}

// HandleHistory handles the history endpoint
func (s *Server) HandleHistory(w http.ResponseWriter, _ *http.Request) {
	s.Mu.Lock()
	history := s.CmdHistory
	s.Mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(history)
}

// HandleCD handles changing the working directory
func (s *Server) HandleCD(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.WriteError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", "")
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", err.Error())
		return
	}

	newPath := req.Path
	if !IsAbsPath(newPath) {
		newPath = JoinPath(s.WorkDir, newPath)
	}

	newPath = filepath.Clean(newPath)

	if !IsAllowedPath(newPath) {
		s.Log("DENY", "Path not allowed: %s", newPath)
		s.WriteError(w, http.StatusForbidden, "PATH_FORBIDDEN", "Access denied", "Allowed: /home/*, B:\\*, C:\\Users\\*")

		return
	}

	info, err := os.Stat(newPath)
	if err != nil {
		s.WriteError(w, http.StatusNotFound, "DIR_NOT_FOUND", "Directory not found", newPath)
		return
	}

	if !info.IsDir() {
		s.WriteError(w, http.StatusBadRequest, "NOT_A_DIRECTORY", "Path is not a directory", newPath)
		return
	}

	s.WorkDir = newPath
	s.Log("INFO", "Working directory changed to: %s", newPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"workdir": newPath})
}
