package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePipeline(t *testing.T, dir string, report *PipelineReport) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "pipeline.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDashboard_Empty(t *testing.T) {
	dir := t.TempDir()

	d, err := LoadDashboard(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(d.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(d.Entries))
	}
}

func TestLoadDashboard_SingleRun(t *testing.T) {
	dir := t.TempDir()

	writePipeline(t, filepath.Join(dir, "run-001"), &PipelineReport{
		ID:              "run-001",
		ScenarioName:    "calculator",
		TotalDurationMS: 5000,
		Tokens: TokenMetrics{
			TotalInputTokens:  1000,
			TotalOutputTokens: 500,
			TotalTokens:       1500,
			APICalls:          2,
			Calls: []APICallUsage{
				{File: "a.java", Stage: "codegen", InputTokens: 500, OutputTokens: 250, TotalTokens: 750, StopReason: "end_turn"},
				{File: "a.java", Stage: "ast_rewrite", InputTokens: 500, OutputTokens: 250, TotalTokens: 750, StopReason: "max_tokens"},
			},
		},
	})

	d, err := LoadDashboard(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(d.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(d.Entries))
	}

	e := d.Entries[0]
	if e.ScenarioName != "calculator" {
		t.Errorf("scenario = %q, want %q", e.ScenarioName, "calculator")
	}

	if e.APICalls != 2 {
		t.Errorf("api_calls = %d, want 2", e.APICalls)
	}

	if e.InputTokens != 1000 {
		t.Errorf("input_tokens = %d, want 1000", e.InputTokens)
	}

	if e.Truncated != 1 {
		t.Errorf("truncated = %d, want 1", e.Truncated)
	}
}

func TestLoadDashboard_MultipleRuns(t *testing.T) {
	dir := t.TempDir()

	writePipeline(t, filepath.Join(dir, "aaa"), &PipelineReport{
		ID:           "aaa",
		ScenarioName: "first",
		Tokens:       TokenMetrics{APICalls: 1, TotalInputTokens: 100, TotalOutputTokens: 50, TotalTokens: 150},
	})

	writePipeline(t, filepath.Join(dir, "bbb"), &PipelineReport{
		ID:           "bbb",
		ScenarioName: "second",
		Tokens:       TokenMetrics{APICalls: 3, TotalInputTokens: 300, TotalOutputTokens: 150, TotalTokens: 450},
	})

	d, err := LoadDashboard(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(d.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(d.Entries))
	}

	// Should be sorted by ID
	if d.Entries[0].ID != "aaa" {
		t.Errorf("first entry ID = %q, want %q", d.Entries[0].ID, "aaa")
	}
}

func TestLoadDashboard_SkipsInvalidJSON(t *testing.T) {
	dir := t.TempDir()

	// Valid entry
	writePipeline(t, filepath.Join(dir, "good"), &PipelineReport{
		ID:           "good",
		ScenarioName: "valid",
		Tokens:       TokenMetrics{APICalls: 1},
	})

	// Invalid JSON
	badDir := filepath.Join(dir, "bad")
	if err := os.MkdirAll(badDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(badDir, "pipeline.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := LoadDashboard(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(d.Entries) != 1 {
		t.Errorf("expected 1 entry (skipping invalid), got %d", len(d.Entries))
	}
}

func TestDashboard_PrintTable(t *testing.T) {
	d := &Dashboard{
		Entries: []DashboardEntry{
			{
				ID:           "001",
				ScenarioName: "calculator",
				APICalls:     2,
				InputTokens:  12162,
				OutputTokens: 8429,
				TotalTokens:  20591,
				Truncated:    0,
			},
			{
				ID:           "002",
				ScenarioName: "spring",
				APICalls:     2,
				InputTokens:  80610,
				OutputTokens: 16384,
				TotalTokens:  96994,
				Truncated:    2,
			},
		},
	}

	var buf bytes.Buffer
	d.PrintTable(&buf)
	output := buf.String()

	if !strings.Contains(output, "Token Usage Dashboard") {
		t.Error("missing header")
	}

	if !strings.Contains(output, "calculator") {
		t.Error("missing calculator entry")
	}

	if !strings.Contains(output, "spring") {
		t.Error("missing spring entry")
	}

	if !strings.Contains(output, "TOTAL") {
		t.Error("missing TOTAL row")
	}

	if !strings.Contains(output, "Estimated cost") {
		t.Error("missing cost estimate")
	}
}

func TestDashboard_PrintTable_Empty(t *testing.T) {
	d := &Dashboard{}

	var buf bytes.Buffer
	d.PrintTable(&buf)

	if !strings.Contains(buf.String(), "No audit runs found") {
		t.Error("expected empty message")
	}
}

func TestDashboard_PrintJSON(t *testing.T) {
	d := &Dashboard{
		Entries: []DashboardEntry{
			{ID: "001", ScenarioName: "test", APICalls: 1},
		},
	}

	var buf bytes.Buffer
	if err := d.PrintJSON(&buf); err != nil {
		t.Fatalf("PrintJSON error: %v", err)
	}

	var parsed Dashboard
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(parsed.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(parsed.Entries))
	}
}

func TestFmtInt(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{100, "100"},
		{1000, "1,000"},
		{12162, "12,162"},
		{1000000, "1,000,000"},
	}

	for _, tt := range tests {
		got := fmtInt(tt.input)
		if got != tt.want {
			t.Errorf("fmtInt(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
