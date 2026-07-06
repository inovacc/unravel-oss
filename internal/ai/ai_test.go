/* Copyright (c) 2026 Security Research */
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

// mockMCPClient lets tests inject a Summarize body / error.
type mockMCPClient struct {
	body []byte
	err  error
}

func (m mockMCPClient) Summarize(_ context.Context, _ string) ([]byte, error) {
	return m.body, m.err
}

// withMockMCP installs the mock for the duration of a test, then resets.
func withMockMCP(t *testing.T, c MCPClient) {
	t.Helper()
	SetMCPClient(c)
	t.Cleanup(func() { SetMCPClient(nil) })
}

// ---------------------------------------------------------------------------
// client.go — NewClient & options
// ---------------------------------------------------------------------------

func TestNewClient_Defaults(t *testing.T) {
	c, err := NewClient()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("Client should not be nil")
	}
	if c.model == "" {
		t.Error("default model should be set")
	}
}

func TestWithModel_Sets(t *testing.T) {
	c, err := NewClient(WithModel("claude-3-haiku"))
	if err != nil {
		t.Fatal(err)
	}
	if c.model != "claude-3-haiku" {
		t.Errorf("model = %q, want %q", c.model, "claude-3-haiku")
	}
}

func TestWithBaseURL_NoOp(t *testing.T) {
	// Must not error and must not enable any HTTP path.
	c, err := NewClient(WithBaseURL("http://anything"))
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("client should not be nil")
	}
}

func TestWithSessionKey_NoOp(t *testing.T) {
	c, err := NewClient(WithSessionKey("anything"))
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("client should not be nil")
	}
}

// ---------------------------------------------------------------------------
// client.go — Analyze (delegates to mock MCPClient)
// ---------------------------------------------------------------------------

func TestClient_DelegatesToMCPClient(t *testing.T) {
	withMockMCP(t, mockMCPClient{body: []byte("mock content from MCP host")})

	c, _ := NewClient()
	resp, err := c.Analyze(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "mock content from MCP host" {
		t.Errorf("Content = %q, want %q", resp.Content, "mock content from MCP host")
	}
}

func TestClient_NilResolver_GracefulDegrade(t *testing.T) {
	// Ensure we start from the default (no-MCP) resolver state.
	SetMCPClient(nil)
	t.Cleanup(func() { SetMCPClient(nil) })

	c, _ := NewClient()
	_, err := c.Analyze(context.Background(), "system", "user")
	if err == nil {
		t.Fatal("expected error when no MCP client wired")
	}
	if !strings.Contains(err.Error(), "no MCP client wired") {
		t.Errorf("error = %v, want to contain 'no MCP client wired'", err)
	}
}

func TestClient_AnalyzeStream_SingleChunk(t *testing.T) {
	withMockMCP(t, mockMCPClient{body: []byte("Hello, world!")})

	c, _ := NewClient()

	var received []string
	resp, err := c.AnalyzeStream(context.Background(), "sys", "user", func(chunk string) {
		received = append(received, chunk)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "Hello, world!" {
		t.Errorf("Content = %q, want %q", resp.Content, "Hello, world!")
	}
	if len(received) != 1 {
		t.Errorf("callback chunk count = %d, want 1", len(received))
	}
	if len(received) > 0 && received[0] != "Hello, world!" {
		t.Errorf("first chunk = %q, want full content", received[0])
	}
}

func TestClient_AnalyzeStream_NilCallbackOK(t *testing.T) {
	withMockMCP(t, mockMCPClient{body: []byte("data")})

	c, _ := NewClient()
	resp, err := c.AnalyzeStream(context.Background(), "sys", "user", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "data" {
		t.Errorf("Content = %q, want %q", resp.Content, "data")
	}
}

func TestClient_AnalyzeStream_PropagatesError(t *testing.T) {
	withMockMCP(t, mockMCPClient{err: errors.New("upstream boom")})

	c, _ := NewClient()
	_, err := c.AnalyzeStream(context.Background(), "sys", "user", nil)
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if !strings.Contains(err.Error(), "upstream boom") {
		t.Errorf("error = %v, want to contain 'upstream boom'", err)
	}
}

func TestSetMCPClient_NilResetsToDefault(t *testing.T) {
	// Inject a working mock, then reset.
	SetMCPClient(mockMCPClient{body: []byte("alive")})
	SetMCPClient(nil)
	t.Cleanup(func() { SetMCPClient(nil) })

	c, _ := NewClient()
	_, err := c.Analyze(context.Background(), "s", "u")
	if err == nil {
		t.Fatal("expected error after reset to nil resolver")
	}
	if !strings.Contains(err.Error(), "no MCP client wired") {
		t.Errorf("error = %v, want to contain 'no MCP client wired'", err)
	}
}

// ---------------------------------------------------------------------------
// analysis.go — AnalyzeAndroid passthrough using mock MCP
// ---------------------------------------------------------------------------

func TestAnalyzeAndroid_PassesThrough(t *testing.T) {
	withMockMCP(t, mockMCPClient{
		body: []byte("## Security Findings\ncritical vuln\n\n## Risk Assessment\nHIGH"),
	})

	c, _ := NewClient()
	result, err := AnalyzeAndroid(context.Background(), c, "system prompt", "data summary")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.SecurityFindings, "critical vuln") {
		t.Errorf("SecurityFindings = %q, want to contain 'critical vuln'", result.SecurityFindings)
	}
	if !strings.Contains(result.RiskAssessment, "HIGH") {
		t.Errorf("RiskAssessment = %q, want to contain 'HIGH'", result.RiskAssessment)
	}
	if result.Duration < 0 {
		t.Error("Duration should be non-negative")
	}
}

func TestAnalyzeAndroid_Error(t *testing.T) {
	withMockMCP(t, mockMCPClient{err: errors.New("server error")})

	c, _ := NewClient()
	_, err := AnalyzeAndroid(context.Background(), c, "sys", "data")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "AI analysis") {
		t.Errorf("error = %v, want to contain 'AI analysis'", err)
	}
}

func TestAnalyzeAndroidStream_PassesThrough(t *testing.T) {
	withMockMCP(t, mockMCPClient{
		body: []byte("## Security Findings\nrce found\n\n## Risk Assessment\nCRITICAL"),
	})

	c, _ := NewClient()
	var chunks []string
	result, err := AnalyzeAndroidStream(context.Background(), c, "sys", "data", func(chunk string) {
		chunks = append(chunks, chunk)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.SecurityFindings, "rce found") {
		t.Errorf("SecurityFindings = %q, want to contain 'rce found'", result.SecurityFindings)
	}
	if !strings.Contains(result.RiskAssessment, "CRITICAL") {
		t.Errorf("RiskAssessment = %q, want to contain 'CRITICAL'", result.RiskAssessment)
	}
	if len(chunks) == 0 {
		t.Error("callback should have been invoked at least once")
	}
}

func TestAnalyzeAndroidStream_Error(t *testing.T) {
	withMockMCP(t, mockMCPClient{err: errors.New("boom")})

	c, _ := NewClient()
	_, err := AnalyzeAndroidStream(context.Background(), c, "sys", "data", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "AI analysis") {
		t.Errorf("error = %v, want to contain 'AI analysis'", err)
	}
}

// ---------------------------------------------------------------------------
// analysis.go — parseAnalysisResponse (pure function, unchanged behavior)
// ---------------------------------------------------------------------------

func TestParseAnalysisResponse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, r *AnalysisResult)
	}{
		{
			name: "parses h1 and h2 markdown sections",
			input: `# Manifest Analysis
manifest content here

## Security Findings
vuln1 found

## Network Surface
api.example.com

## Secret Exposure
API_KEY=leaked

## Obfuscation Analysis
ProGuard detected

## Risk Assessment
HIGH risk
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.Manifest, "manifest content") {
					t.Errorf("Manifest missing content: %q", r.Manifest)
				}
				if !strings.Contains(r.SecurityFindings, "vuln1") {
					t.Errorf("SecurityFindings missing: %q", r.SecurityFindings)
				}
				if !strings.Contains(r.NetworkSurface, "api.example.com") {
					t.Errorf("NetworkSurface missing: %q", r.NetworkSurface)
				}
				if !strings.Contains(r.SecretsExposed, "API_KEY") {
					t.Errorf("SecretsExposed missing: %q", r.SecretsExposed)
				}
				if !strings.Contains(r.Obfuscation, "ProGuard") {
					t.Errorf("Obfuscation missing: %q", r.Obfuscation)
				}
				if !strings.Contains(r.RiskAssessment, "HIGH") {
					t.Errorf("RiskAssessment missing: %q", r.RiskAssessment)
				}
			},
		},
		{
			name: "parses h3 markdown sections",
			input: `### Security Findings
sql injection

### Risk Assessment
CRITICAL
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "sql injection") {
					t.Errorf("SecurityFindings missing h3 content: %q", r.SecurityFindings)
				}
				if !strings.Contains(r.RiskAssessment, "CRITICAL") {
					t.Errorf("RiskAssessment missing h3 content: %q", r.RiskAssessment)
				}
			},
		},
		{
			name: "parses numbered section headers",
			input: `1. Security Analysis
heap overflow found

2. Risk Assessment
HIGH severity
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "heap overflow") {
					t.Errorf("SecurityFindings missing numbered section: %q", r.SecurityFindings)
				}
				if !strings.Contains(r.RiskAssessment, "HIGH severity") {
					t.Errorf("RiskAssessment missing numbered section: %q", r.RiskAssessment)
				}
			},
		},
		{
			name: "parses bold-numbered section headers",
			input: `**1. Security Analysis**
xss detected

**2. Obfuscation Analysis**
DexGuard present
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "xss detected") {
					t.Errorf("SecurityFindings missing bold-numbered section: %q", r.SecurityFindings)
				}
				if !strings.Contains(r.Obfuscation, "DexGuard") {
					t.Errorf("Obfuscation missing bold-numbered section: %q", r.Obfuscation)
				}
			},
		},
		{
			name: "parses lowercase XML tags",
			input: `<security>
sql injection
</security>
<risk>
HIGH
</risk>`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "sql injection") {
					t.Errorf("SecurityFindings missing XML content: %q", r.SecurityFindings)
				}
				if !strings.Contains(r.RiskAssessment, "HIGH") {
					t.Errorf("RiskAssessment missing XML content: %q", r.RiskAssessment)
				}
			},
		},
		{
			name: "case-insensitive XML tags: UPPERCASE",
			input: `<SECURITY>
buffer overflow
</SECURITY>`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "buffer overflow") {
					t.Errorf("SecurityFindings missing uppercase XML: %q", r.SecurityFindings)
				}
			},
		},
		{
			name: "case-insensitive XML tags: MixedCase",
			input: `<Security>
path traversal
</Security>`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "path traversal") {
					t.Errorf("SecurityFindings missing mixed-case XML: %q", r.SecurityFindings)
				}
			},
		},
		{
			name: "XML takes priority over markdown headers when both present",
			input: `<security>
from xml tag
</security>

## Security Findings
from markdown header
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "from xml tag") {
					t.Errorf("SecurityFindings should contain XML content: %q", r.SecurityFindings)
				}
				if strings.Contains(r.SecurityFindings, "from markdown header") {
					t.Errorf("SecurityFindings should not contain markdown content when XML took priority: %q", r.SecurityFindings)
				}
			},
		},
		{
			name: "strips leading dash bullets from content lines",
			input: `## Security Findings
- sql injection
- buffer overflow
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if strings.Contains(r.SecurityFindings, "- sql") {
					t.Errorf("SecurityFindings still contains bullet prefix: %q", r.SecurityFindings)
				}
				if !strings.Contains(r.SecurityFindings, "sql injection") {
					t.Errorf("SecurityFindings missing content after bullet strip: %q", r.SecurityFindings)
				}
			},
		},
		{
			name: "strips leading asterisk bullets from content lines",
			input: `## Security Findings
* xss
* csrf
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if strings.Contains(r.SecurityFindings, "* xss") {
					t.Errorf("SecurityFindings still contains asterisk bullet: %q", r.SecurityFindings)
				}
				if !strings.Contains(r.SecurityFindings, "xss") {
					t.Errorf("SecurityFindings missing content after bullet strip: %q", r.SecurityFindings)
				}
			},
		},
		{
			name: "XML content also strips bullets",
			input: `<security>
- rce vulnerability
* path traversal
</security>`,
			check: func(t *testing.T, r *AnalysisResult) {
				if strings.Contains(r.SecurityFindings, "- rce") {
					t.Errorf("XML security content still has dash bullet: %q", r.SecurityFindings)
				}
				if !strings.Contains(r.SecurityFindings, "rce vulnerability") {
					t.Errorf("XML security content missing after bullet strip: %q", r.SecurityFindings)
				}
			},
		},
		{
			name:  "no sections falls back to SecurityFindings",
			input: "just plain text without headers",
			check: func(t *testing.T, r *AnalysisResult) {
				if r.SecurityFindings != "just plain text without headers" {
					t.Errorf("expected fallback to SecurityFindings, got %q", r.SecurityFindings)
				}
			},
		},
		{
			name:  "empty input produces empty result",
			input: "",
			check: func(t *testing.T, r *AnalysisResult) {
				if r.SecurityFindings != "" {
					t.Errorf("expected empty SecurityFindings for empty input, got %q", r.SecurityFindings)
				}
			},
		},
		{
			name: "code architecture alias",
			input: `## Code Architecture
layered architecture
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.CodeArchitecture, "layered") {
					t.Errorf("CodeArchitecture missing: %q", r.CodeArchitecture)
				}
			},
		},
		{
			name: "credential alias maps to secrets",
			input: `## Credential Leaks
password=abc
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecretsExposed, "password=abc") {
					t.Errorf("SecretsExposed missing credential alias: %q", r.SecretsExposed)
				}
			},
		},
		{
			name: "protection alias maps to obfuscation",
			input: `## Protection Mechanisms
packer detected
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.Obfuscation, "packer") {
					t.Errorf("Obfuscation missing protection alias: %q", r.Obfuscation)
				}
			},
		},
		{
			name: "api alias maps to network",
			input: `## API Endpoints
/v1/users
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.NetworkSurface, "/v1/users") {
					t.Errorf("NetworkSurface missing api alias: %q", r.NetworkSurface)
				}
			},
		},
		{
			name: "unknown XML tags are ignored",
			input: `<unknown_tag>ignored content</unknown_tag>
<security>real finding</security>`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "real finding") {
					t.Errorf("SecurityFindings missing: %q", r.SecurityFindings)
				}
			},
		},
		{
			name:  "XML tag without closing bracket is skipped gracefully",
			input: `<security real finding`,
			check: func(t *testing.T, r *AnalysisResult) {
				_ = r
			},
		},
		{
			name: "unclosed XML tag falls back to markdown parsing",
			input: `## Security Findings
unclosed xml below
<security>no closing tag here`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "unclosed xml below") {
					t.Errorf("SecurityFindings should contain markdown content: %q", r.SecurityFindings)
				}
			},
		},
		{
			name: "markdown section with only whitespace content is not flushed",
			input: `## Security Findings

## Risk Assessment
critical
`,
			check: func(t *testing.T, r *AnalysisResult) {
				if r.SecurityFindings != "" {
					t.Errorf("SecurityFindings should be empty for whitespace-only section: %q", r.SecurityFindings)
				}
				if !strings.Contains(r.RiskAssessment, "critical") {
					t.Errorf("RiskAssessment missing: %q", r.RiskAssessment)
				}
			},
		},
		{
			name: "XML tag with space in tag name is treated as HTML and skipped",
			input: `<br class="x">noise</br>
<security>real</security>`,
			check: func(t *testing.T, r *AnalysisResult) {
				if !strings.Contains(r.SecurityFindings, "real") {
					t.Errorf("SecurityFindings missing after HTML tag skip: %q", r.SecurityFindings)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := parseAnalysisResponse(tt.input)
			tt.check(t, r)
		})
	}
}

// ---------------------------------------------------------------------------
// analysis.go — trimSlice, MarshalDissectForAI, BuildDataSummary (pure)
// ---------------------------------------------------------------------------

func TestTrimSlice(t *testing.T) {
	tests := []struct {
		name    string
		m       map[string]any
		key     string
		maxLen  int
		wantLen int
	}{
		{
			name:    "trims long slice",
			m:       map[string]any{"items": []any{1, 2, 3, 4, 5}},
			key:     "items",
			maxLen:  3,
			wantLen: 3,
		},
		{
			name:    "no-op for short slice",
			m:       map[string]any{"items": []any{1, 2}},
			key:     "items",
			maxLen:  5,
			wantLen: 2,
		},
		{
			name:    "missing key is no-op",
			m:       map[string]any{"other": "val"},
			key:     "items",
			maxLen:  3,
			wantLen: -1,
		},
		{
			name:    "non-slice value is no-op",
			m:       map[string]any{"items": "not a slice"},
			key:     "items",
			maxLen:  3,
			wantLen: -1,
		},
		{
			name:    "exact length is no-op",
			m:       map[string]any{"items": []any{1, 2, 3}},
			key:     "items",
			maxLen:  3,
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trimSlice(tt.m, tt.key, tt.maxLen)
			arr, ok := tt.m[tt.key].([]any)
			if tt.wantLen == -1 {
				return
			}
			if !ok {
				t.Fatal("expected []any after trimSlice")
			}
			if len(arr) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(arr), tt.wantLen)
			}
		})
	}
}

func TestMarshalDissectForAI_Trimming(t *testing.T) {
	bigClasses := make([]any, 600)
	for i := range bigClasses {
		bigClasses[i] = fmt.Sprintf("class_%d", i)
	}

	input := map[string]any{
		"app_name":  "test",
		"ai_prompt": "remove me",
		"analyses":  "remove me too",
		"dex_analysis": map[string]any{
			"dex_files": []any{
				map[string]any{
					"strings": []any{"a", "b"},
					"types":   []any{"t1"},
					"fields":  []any{"f1"},
					"classes": bigClasses,
					"methods": []any{"m1"},
				},
			},
			"high_entropy_strings": []any{"s1"},
		},
		"network_analysis": map[string]any{
			"endpoints": make([]any, 300),
			"domains":   []any{"example.com"},
		},
		"secrets": map[string]any{
			"findings": make([]any, 250),
		},
		"resource_analysis": map[string]any{
			"assets": make([]any, 150),
			"string_pool": map[string]any{
				"sample_strings": make([]any, 50),
			},
		},
	}

	data, err := MarshalDissectForAI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"ai_prompt", "analyses"} {
		if _, ok := m[key]; ok {
			t.Errorf("field %q should have been stripped", key)
		}
	}

	dex := m["dex_analysis"].(map[string]any)
	files := dex["dex_files"].([]any)
	df := files[0].(map[string]any)
	for _, key := range []string{"strings", "types", "fields"} {
		if _, ok := df[key]; ok {
			t.Errorf("dex field %q should have been deleted", key)
		}
	}
	classes := df["classes"].([]any)
	if len(classes) != 500 {
		t.Errorf("classes len = %d, want 500", len(classes))
	}

	net := m["network_analysis"].(map[string]any)
	endpoints := net["endpoints"].([]any)
	if len(endpoints) != 200 {
		t.Errorf("endpoints len = %d, want 200", len(endpoints))
	}

	secrets := m["secrets"].(map[string]any)
	findings := secrets["findings"].([]any)
	if len(findings) != 200 {
		t.Errorf("findings len = %d, want 200", len(findings))
	}

	res := m["resource_analysis"].(map[string]any)
	assets := res["assets"].([]any)
	if len(assets) != 100 {
		t.Errorf("assets len = %d, want 100", len(assets))
	}
	sp := res["string_pool"].(map[string]any)
	ss := sp["sample_strings"].([]any)
	if len(ss) != 20 {
		t.Errorf("sample_strings len = %d, want 20", len(ss))
	}
}

func TestMarshalDissectForAI_NonMapFallback(t *testing.T) {
	input := []string{"a", "b"}
	data, err := MarshalDissectForAI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), `"a"`) {
		t.Errorf("expected array JSON, got %s", data)
	}
}

func TestMarshalDissectForAI(t *testing.T) {
	tests := []struct {
		name      string
		input     any
		wantErr   bool
		wantField string
		denyField string
	}{
		{
			name: "strips ai_prompt field",
			input: map[string]any{
				"app_name":  "test",
				"ai_prompt": "should be removed",
				"version":   "1.0",
			},
			wantField: "app_name",
			denyField: "ai_prompt",
		},
		{
			name: "preserves other fields",
			input: map[string]any{
				"findings": []string{"vuln1", "vuln2"},
			},
			wantField: "findings",
		},
		{
			name:    "unmarshalable input returns error",
			input:   make(chan int),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MarshalDissectForAI(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("MarshalDissectForAI() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalDissectForAI() unexpected error: %v", err)
			}

			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("failed to unmarshal result: %v", err)
			}

			if tt.wantField != "" {
				if _, ok := m[tt.wantField]; !ok {
					t.Errorf("expected field %q not found in output", tt.wantField)
				}
			}

			if tt.denyField != "" {
				if _, ok := m[tt.denyField]; ok {
					t.Errorf("field %q should have been stripped but was present", tt.denyField)
				}
			}
		})
	}
}

func TestBuildDataSummary(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		contains []string
	}{
		{
			name:  "wraps JSON in markdown code block",
			input: []byte(`{"app":"test","version":"1.0"}`),
			contains: []string{
				"# Android APK Analysis Data",
				"```json",
				`{"app":"test","version":"1.0"}`,
				"```",
			},
		},
		{
			name:  "empty JSON object",
			input: []byte(`{}`),
			contains: []string{
				"```json",
				"{}",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildDataSummary(tt.input)
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("BuildDataSummary() missing expected substring %q\ngot: %s", want, got)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// env.go — LoadEnv (preserved from previous tests)
// ---------------------------------------------------------------------------

func TestLoadEnv(t *testing.T) {
	tests := []struct {
		name    string
		content string
		preSet  map[string]string
		want    map[string]string
	}{
		{
			name:    "basic key=value",
			content: "FOO_TEST_AI=bar\nBAZ_TEST_AI=qux\n",
			want:    map[string]string{"FOO_TEST_AI": "bar", "BAZ_TEST_AI": "qux"},
		},
		{
			name:    "skips comments and blank lines",
			content: "# comment\n\n  \nKEY_TEST_AI=val\n",
			want:    map[string]string{"KEY_TEST_AI": "val"},
		},
		{
			name:    "does not override existing env vars",
			content: "EXISTING_TEST_AI=new",
			preSet:  map[string]string{"EXISTING_TEST_AI": "old"},
			want:    map[string]string{"EXISTING_TEST_AI": "old"},
		},
		{
			name:    "skips lines without equals",
			content: "NOEQUALS\nGOOD_TEST_AI=yes\n",
			want:    map[string]string{"GOOD_TEST_AI": "yes"},
		},
		{
			name:    "trims whitespace around key and value",
			content: "  SPACED_TEST_AI  =  value  \n",
			want:    map[string]string{"SPACED_TEST_AI": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allKeys := make([]string, 0)
			for k := range tt.want {
				allKeys = append(allKeys, k)
			}
			for k := range tt.preSet {
				allKeys = append(allKeys, k)
			}
			t.Cleanup(func() {
				for _, k := range allKeys {
					_ = os.Unsetenv(k)
				}
			})

			for _, k := range allKeys {
				_ = os.Unsetenv(k)
			}
			for k, v := range tt.preSet {
				_ = os.Setenv(k, v)
			}

			dir := t.TempDir()
			path := filepath.Join(dir, ".env")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}

			LoadEnv(path)

			for k, want := range tt.want {
				got := os.Getenv(k)
				if got != want {
					t.Errorf("env %q = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestLoadEnv_MissingFile(t *testing.T) {
	LoadEnv("/nonexistent/path/.env")
}
