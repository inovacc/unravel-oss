/* Copyright (c) 2026 Security Research */
package ipc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratePayload(t *testing.T) {
	tests := []struct {
		name      string
		iteration int
		want      any
	}{
		{"iteration 0 returns nil", 0, nil},
		{"iteration 1 returns empty string", 1, ""},
		{"iteration 2 returns empty slice", 2, []any{}},
		{"iteration 3 returns empty map", 3, map[string]any{}},
		{"iteration 4 returns zero", 4, 0},
		{"iteration 28 cycles to nil", 28, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GeneratePayload(tt.iteration)

			switch want := tt.want.(type) {
			case nil:
				if got != nil {
					t.Errorf("GeneratePayload(%d) = %v, want nil", tt.iteration, got)
				}
			case string:
				g, ok := got.(string)
				if !ok || g != want {
					t.Errorf("GeneratePayload(%d) = %v (%T), want %q", tt.iteration, got, got, want)
				}
			case int:
				g, ok := got.(int)
				if !ok || g != want {
					t.Errorf("GeneratePayload(%d) = %v (%T), want %d", tt.iteration, got, got, want)
				}
			case []any:
				g, ok := got.([]any)
				if !ok || len(g) != len(want) {
					t.Errorf("GeneratePayload(%d) = %v (%T), want empty slice", tt.iteration, got, got)
				}
			case map[string]any:
				g, ok := got.(map[string]any)
				if !ok || len(g) != len(want) {
					t.Errorf("GeneratePayload(%d) = %v (%T), want empty map", tt.iteration, got, got)
				}
			}
		})
	}
}

func TestGeneratePayloadCycling(t *testing.T) {
	// There are 28 payload types; verify cycling wraps at 28
	const numPayloads = 28

	for i := range numPayloads {
		// Index 27 generates random bytes each call, skip it
		if i == 27 {
			continue
		}

		a := GeneratePayload(i)
		b := GeneratePayload(i + numPayloads)

		// Both nil
		if a == nil && b == nil {
			continue
		}
		if a == nil || b == nil {
			t.Errorf("iteration %d: cycling mismatch, got %v and %v", i, a, b)
		}
	}
}

func TestExtractStrings(t *testing.T) {
	data := []byte("hello\x00world\x00ab\x00longstring\x00")
	got := extractStrings(data, 4)

	want := []string{"hello", "world", "longstring"}
	if len(got) != len(want) {
		t.Fatalf("extractStrings() returned %d strings, want %d", len(got), len(want))
	}

	for i, s := range want {
		if got[i] != s {
			t.Errorf("extractStrings()[%d] = %q, want %q", i, got[i], s)
		}
	}
}

func TestExtractStrings_MinLen(t *testing.T) {
	data := []byte("ab\x00abcd\x00abcdef\x00")
	got := extractStrings(data, 5)

	if len(got) != 1 || got[0] != "abcdef" {
		t.Errorf("extractStrings(minLen=5) = %v, want [abcdef]", got)
	}
}

func TestIsLikelyCommand(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"set_window_height", true},
		{"openDashboard", true},
		{"plugin:app|show", true},
		{"http://example.com", false},
		{"function", false},
		{"true", false},
		{"123", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isLikelyCommand(tt.s); got != tt.want {
				t.Errorf("isLikelyCommand(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsInterestingResponse(t *testing.T) {
	tests := []struct {
		name   string
		result FuzzResult
		want   bool
	}{
		{"500 error", FuzzResult{StatusCode: 500, Response: "ok"}, true},
		{"403 forbidden", FuzzResult{StatusCode: 403, Response: "ok"}, true},
		{"200 normal", FuzzResult{StatusCode: 200, Response: "ok"}, false},
		{"200 with error", FuzzResult{StatusCode: 200, Response: "Internal error occurred"}, true},
		{"200 with stack trace", FuzzResult{StatusCode: 200, Response: "stack trace at line 5"}, true},
		{"200 with sql", FuzzResult{StatusCode: 200, Response: "SQL syntax error"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInterestingResponse(tt.result); got != tt.want {
				t.Errorf("isInterestingResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscoverCommands_NonexistentFile(t *testing.T) {
	_, err := DiscoverCommands("/nonexistent/binary")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestDiscoverCommands_WithPatterns(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "test-binary")

	content := []byte("padding\x00ipcMain.handle('get-settings')\x00more\x00ipcRenderer.send('toggle-visibility')\x00invoke('open_dashboard')\x00end")
	if err := os.WriteFile(bin, content, 0o644); err != nil {
		t.Fatal(err)
	}

	cmds, err := DiscoverCommands(bin)
	if err != nil {
		t.Fatalf("DiscoverCommands() error: %v", err)
	}

	if len(cmds) == 0 {
		t.Error("DiscoverCommands() found 0 commands, expected some")
	}

	found := make(map[string]bool)
	for _, c := range cmds {
		found[c.Name] = true
	}

	for _, want := range []string{"get-settings", "toggle-visibility"} {
		if !found[want] {
			t.Errorf("expected command %q not found in results", want)
		}
	}
}

func TestAppendIfUnique(t *testing.T) {
	tests := []struct {
		name    string
		initial []CommandInfo
		add     CommandInfo
		wantLen int
	}{
		{
			"empty slice adds element",
			nil,
			CommandInfo{Name: "foo", Source: "test"},
			1,
		},
		{
			"unique name appended",
			[]CommandInfo{{Name: "foo", Source: "test"}},
			CommandInfo{Name: "bar", Source: "test"},
			2,
		},
		{
			"duplicate name rejected",
			[]CommandInfo{{Name: "foo", Source: "test"}},
			CommandInfo{Name: "foo", Source: "other"},
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendIfUnique(tt.initial, tt.add)
			if len(got) != tt.wantLen {
				t.Errorf("appendIfUnique() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"Hello World", "hello", true},
		{"Hello World", "WORLD", true},
		{"Hello", "xyz", false},
		{"", "anything", false},
		{"something", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			if got := containsIgnoreCase(tt.s, tt.substr); got != tt.want {
				t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestCalculateSummary(t *testing.T) {
	results := []FuzzResult{
		{Command: "a", StatusCode: 200, Interesting: false},
		{Command: "b", Error: "connection refused", Interesting: false},
		{Command: "c", Error: "timeout exceeded", Interesting: true},
		{Command: "d", StatusCode: 500, Interesting: true},
	}

	summary := calculateSummary(results)

	if summary.TotalRequests != 4 {
		t.Errorf("TotalRequests = %d, want 4", summary.TotalRequests)
	}
	if summary.SuccessfulCalls != 2 {
		t.Errorf("SuccessfulCalls = %d, want 2", summary.SuccessfulCalls)
	}
	if summary.ErrorResponses != 2 {
		t.Errorf("ErrorResponses = %d, want 2", summary.ErrorResponses)
	}
	if summary.InterestingFinds != 2 {
		t.Errorf("InterestingFinds = %d, want 2", summary.InterestingFinds)
	}
	if summary.TimeoutCount != 1 {
		t.Errorf("TimeoutCount = %d, want 1", summary.TimeoutCount)
	}
}

func TestFuzzCommands_LiveServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	commands := []CommandInfo{
		{Name: "test_cmd", Source: "test"},
		{Name: "other_cmd", Source: "test"},
	}

	config := FuzzerConfig{
		TargetURL:  srv.URL,
		BinaryPath: "test-binary",
		Iterations: 3,
		Timeout:    5 * time.Second,
	}

	report := FuzzCommands(config, commands)

	if len(report.Results) != 6 {
		t.Errorf("expected 6 results (2 cmds * 3 iters), got %d", len(report.Results))
	}

	for _, r := range report.Results {
		if r.Error != "" {
			t.Errorf("unexpected error for %q: %s", r.Command, r.Error)
		}

		var resp map[string]string
		if err := json.Unmarshal([]byte(r.Response), &resp); err != nil {
			t.Errorf("failed to parse response: %v", err)
		}
	}

	if report.Summary.TotalRequests != 6 {
		t.Errorf("summary TotalRequests = %d, want 6", report.Summary.TotalRequests)
	}
}

func TestFuzzCommands_ServerDown(t *testing.T) {
	commands := []CommandInfo{
		{Name: "test_cmd", Source: "test"},
	}

	config := FuzzerConfig{
		TargetURL:  "http://127.0.0.1:1",
		BinaryPath: "test-binary",
		Iterations: 2,
		Timeout:    1 * time.Second,
	}

	report := FuzzCommands(config, commands)

	if len(report.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(report.Results))
	}

	for _, r := range report.Results {
		if r.Error == "" {
			t.Error("expected error for unreachable server, got none")
		}
	}

	if report.Summary.ErrorResponses != 2 {
		t.Errorf("summary ErrorResponses = %d, want 2", report.Summary.ErrorResponses)
	}
}

func TestFuzzCommands_DiscoverOnly(t *testing.T) {
	commands := []CommandInfo{{Name: "cmd1", Source: "test"}}

	config := FuzzerConfig{
		TargetURL:    "http://127.0.0.1:9999",
		BinaryPath:   "test",
		DiscoverOnly: true,
		Iterations:   5,
	}

	report := FuzzCommands(config, commands)

	if len(report.Results) != 0 {
		t.Errorf("DiscoverOnly should produce 0 results, got %d", len(report.Results))
	}
}

func TestGeneratePayload_AllTypes(t *testing.T) {
	const numPayloads = 28

	for i := range numPayloads {
		payload := GeneratePayload(i)
		// iterations 0 returns nil, which is valid
		if i == 0 {
			if payload != nil {
				t.Errorf("GeneratePayload(0) = %v, want nil", payload)
			}
			continue
		}
		if payload == nil {
			t.Errorf("GeneratePayload(%d) unexpectedly nil", i)
		}
	}
}
