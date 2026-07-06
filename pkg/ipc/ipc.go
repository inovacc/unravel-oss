// Package ipc provides IPC channel discovery and fuzzing for Tauri/Electron apps.
// FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.
package ipc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// FuzzResult represents the result of a single fuzz attempt.
type FuzzResult struct {
	Command     string    `json:"command"`
	Payload     any       `json:"payload"`
	Response    string    `json:"response"`
	StatusCode  int       `json:"status_code"`
	Error       string    `json:"error,omitempty"`
	Interesting bool      `json:"interesting"`
	Timestamp   time.Time `json:"timestamp"`
}

// CommandInfo represents a discovered IPC command.
type CommandInfo struct {
	Name       string   `json:"name"`
	Source     string   `json:"source"`
	Parameters []string `json:"parameters,omitempty"`
}

// FuzzReport is the complete fuzzing report.
type FuzzReport struct {
	Target        string        `json:"target"`
	StartTime     time.Time     `json:"start_time"`
	EndTime       time.Time     `json:"end_time"`
	CommandsFound []CommandInfo `json:"commands_found"`
	Results       []FuzzResult  `json:"results"`
	Summary       FuzzSummary   `json:"summary"`
}

// FuzzSummary contains statistics about the fuzzing session.
type FuzzSummary struct {
	TotalRequests    int `json:"total_requests"`
	SuccessfulCalls  int `json:"successful_calls"`
	ErrorResponses   int `json:"error_responses"`
	InterestingFinds int `json:"interesting_finds"`
	TimeoutCount     int `json:"timeout_count"`
}

// FuzzerConfig holds the fuzzer configuration.
type FuzzerConfig struct {
	TargetURL    string
	BinaryPath   string
	OutputDir    string
	Iterations   int
	Timeout      time.Duration
	Verbose      bool
	DiscoverOnly bool
}

// DiscoverCommands performs static analysis to find IPC commands in a binary.
func DiscoverCommands(binaryPath string) ([]CommandInfo, error) {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("reading binary: %w", err)
	}

	strs := extractStrings(data, 4)

	var commands []CommandInfo

	tauriPatterns := []string{
		`#\[tauri::command\]`,
		`invoke\(['"]([^'"]+)['"]\)`,
		`plugin:([a-z_]+)\|([a-z_]+)`,
		`tauri://([a-z_/]+)`,
	}

	electronPatterns := []string{
		`ipcMain\.handle\(['"]([^'"]+)['"]\)`,
		`ipcMain\.on\(['"]([^'"]+)['"]\)`,
		`ipcRenderer\.invoke\(['"]([^'"]+)['"]\)`,
		`ipcRenderer\.send\(['"]([^'"]+)['"]\)`,
	}

	for _, pattern := range tauriPatterns {
		re := regexp.MustCompile(pattern)
		for _, s := range strs {
			if matches := re.FindAllStringSubmatch(s, -1); matches != nil {
				for _, match := range matches {
					cmdName := match[0]
					if len(match) > 1 {
						cmdName = match[1]
						if len(match) > 2 {
							cmdName = fmt.Sprintf("%s|%s", match[1], match[2])
						}
					}

					commands = appendIfUnique(commands, CommandInfo{Name: cmdName, Source: "tauri"})
				}
			}
		}
	}

	for _, pattern := range electronPatterns {
		re := regexp.MustCompile(pattern)
		for _, s := range strs {
			if matches := re.FindAllStringSubmatch(s, -1); matches != nil {
				for _, match := range matches {
					cmdName := match[0]
					if len(match) > 1 {
						cmdName = match[1]
					}

					commands = appendIfUnique(commands, CommandInfo{Name: cmdName, Source: "electron"})
				}
			}
		}
	}

	knownCommands := []string{
		"set_window_height", "open_dashboard", "toggle_dashboard",
		"move_window", "close_overlay_window", "set_always_on_top",
		"check_shortcuts_registered", "get_registered_shortcuts",
		"update_shortcuts", "validate_shortcut_key",
		"set_license_status", "mask_license_key_cmd",
		"set_app_icon_visibility", "exit_app",
		"check_system_audio_access", "get_audio_sample_rate",
		"take-screenshot", "send-message", "toggle-visibility",
		"capture-screen", "start-recording", "stop-recording",
		"get-settings", "set-settings", "copy-to-clipboard",
	}

	for _, s := range strs {
		for _, cmdName := range knownCommands {
			if containsIgnoreCase(s, cmdName) {
				commands = appendIfUnique(commands, CommandInfo{Name: cmdName, Source: "known_pattern"})
			}
		}
	}

	commandPatterns := []string{
		`[a-z]+_[a-z_]+`,
		`[a-z]+[A-Z][a-zA-Z]+`,
		`plugin:[a-z_]+\|[a-z_]+`,
	}

	for _, pattern := range commandPatterns {
		re := regexp.MustCompile(pattern)

		for _, s := range strs {
			if len(s) >= 5 && len(s) <= 50 {
				if matches := re.FindAllString(s, -1); matches != nil {
					for _, match := range matches {
						if isLikelyCommand(match) {
							commands = appendIfUnique(commands, CommandInfo{Name: match, Source: "pattern_match"})
						}
					}
				}
			}
		}
	}

	return commands, nil
}

// FuzzCommands performs live fuzzing against discovered commands.
func FuzzCommands(config FuzzerConfig, commands []CommandInfo) *FuzzReport {
	report := &FuzzReport{
		Target:        config.BinaryPath,
		StartTime:     time.Now(),
		CommandsFound: commands,
		Results:       []FuzzResult{},
	}

	if config.TargetURL == "" || config.DiscoverOnly {
		report.EndTime = time.Now()
		report.Summary = calculateSummary(report.Results)

		return report
	}

	client := &http.Client{Timeout: config.Timeout}

	for _, cmd := range commands {
		for i := 0; i < config.Iterations; i++ {
			payload := GeneratePayload(i)
			result := fuzzCommand(client, config.TargetURL, cmd.Name, payload)
			report.Results = append(report.Results, result)
		}
	}

	report.EndTime = time.Now()
	report.Summary = calculateSummary(report.Results)

	return report
}

// GeneratePayload creates a fuzz payload for the given iteration.
func GeneratePayload(iteration int) any {
	payloadTypes := []func() any{
		func() any { return nil },
		func() any { return "" },
		func() any { return []any{} },
		func() any { return map[string]any{} },
		func() any { return 0 },
		func() any { return -1 },
		func() any { return 999999999 },
		func() any { return 1.5 },
		func() any { return true },
		func() any { return false },
		func() any { return "test" },
		func() any { return strings.Repeat("A", 1000) },
		func() any { return strings.Repeat("A", 10000) },
		func() any { return "{{template}}" },
		func() any { return "${env.PATH}" },
		func() any { return "../../../etc/passwd" },
		func() any { return "..\\..\\..\\windows\\system32\\config\\sam" },
		func() any { return "; echo test" },
		func() any { return "| echo test" },
		func() any { return "$(echo test)" },
		func() any { return "' OR '1'='1" },
		func() any { return "<script>alert(1)</script>" },
		func() any { return "%s%s%s%s%s" },
		func() any { return "%n%n%n%n" },
		func() any {
			return map[string]any{
				"__proto__": map[string]any{"polluted": true},
			}
		},
		func() any { return "\x00\x00\x00\x00" },
		func() any { return "test\u0000hidden" },
		func() any {
			b := make([]byte, 100)
			_, _ = rand.Read(b) //nolint:gosec // G404 -- generates random junk bytes for a fuzz-payload test harness; not security-sensitive

			return string(b)
		},
	}

	return payloadTypes[iteration%len(payloadTypes)]()
}

func fuzzCommand(client *http.Client, targetURL, command string, payload any) FuzzResult {
	result := FuzzResult{
		Command:   command,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	body := map[string]any{"cmd": command, "args": payload}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		result.Error = err.Error()
		return result
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		if strings.Contains(err.Error(), "timeout") {
			result.Interesting = true
		}

		return result
	}

	defer func() { _ = resp.Body.Close() }()

	result.StatusCode = resp.StatusCode
	respBody, _ := io.ReadAll(resp.Body)
	result.Response = string(respBody)
	result.Interesting = isInterestingResponse(result)

	return result
}

func extractStrings(data []byte, minLen int) []string {
	var (
		result  []string
		current bytes.Buffer
	)

	for _, b := range data {
		if b >= 32 && b < 127 {
			current.WriteByte(b)
		} else {
			if current.Len() >= minLen {
				result = append(result, current.String())
			}

			current.Reset()
		}
	}

	if current.Len() >= minLen {
		result = append(result, current.String())
	}

	return result
}

func isLikelyCommand(s string) bool {
	falsePositives := []string{
		"http", "https", "file", "data", "blob",
		"true", "false", "null", "undefined",
		"function", "return", "const", "let", "var",
		"import", "export", "require", "module",
	}

	lower := strings.ToLower(s)
	for _, fp := range falsePositives {
		if lower == fp || strings.HasPrefix(lower, fp) {
			return false
		}
	}

	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(s)
	if !hasLetter {
		return false
	}

	return regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_\-:|\/.]+$`).MatchString(s)
}

func isInterestingResponse(result FuzzResult) bool {
	interestingCodes := []int{500, 502, 503, 400, 401, 403, 405}
	if slices.Contains(interestingCodes, result.StatusCode) {
		return true
	}

	interestingPatterns := []string{
		"error", "exception", "stack trace", "panic",
		"undefined", "null pointer", "segfault",
		"access denied", "permission", "unauthorized",
		"sql", "query", "database",
		"file not found", "path", "directory",
		"command", "shell", "exec",
	}

	lower := strings.ToLower(result.Response)
	for _, pattern := range interestingPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

func appendIfUnique(commands []CommandInfo, cmd CommandInfo) []CommandInfo {
	for _, existing := range commands {
		if existing.Name == cmd.Name {
			return commands
		}
	}

	return append(commands, cmd)
}

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func calculateSummary(results []FuzzResult) FuzzSummary {
	summary := FuzzSummary{TotalRequests: len(results)}
	for _, r := range results {
		if r.Error == "" {
			summary.SuccessfulCalls++
		} else {
			summary.ErrorResponses++
			if strings.Contains(r.Error, "timeout") {
				summary.TimeoutCount++
			}
		}

		if r.Interesting {
			summary.InterestingFinds++
		}
	}

	return summary
}
