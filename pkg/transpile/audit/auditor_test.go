package audit

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/transpile/archive"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func TestAuditorDirectoryStructure(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "test_scenario", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Verify base dir was created
	if _, err := os.Stat(a.BaseDir()); os.IsNotExist(err) {
		t.Fatalf("base dir not created: %s", a.BaseDir())
	}

	// Write to various stage directories
	if err := a.WriteJSON(DirInput, "test.json", map[string]string{"key": "value"}); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	if err := a.WriteText(DirMetadata, "test.txt", "hello world"); err != nil {
		t.Fatalf("WriteText error: %v", err)
	}

	// Verify directories exist
	for _, dir := range []string{DirInput, DirMetadata} {
		path := filepath.Join(a.BaseDir(), dir)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("directory not created: %s", path)
		}
	}

	// Verify file contents
	data, err := os.ReadFile(filepath.Join(a.BaseDir(), DirInput, "test.json"))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if m["key"] != "value" {
		t.Errorf("expected key=value, got key=%s", m["key"])
	}

	text, err := os.ReadFile(filepath.Join(a.BaseDir(), DirMetadata, "test.txt"))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	if string(text) != "hello world" {
		t.Errorf("expected 'hello world', got %q", string(text))
	}
}

func TestAuditorPipelineReport(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "pipeline_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	a.SetInputPath("/path/to/test.jar")
	a.SetArchiveType("JAR")
	a.SetTotalJavaFiles(5)

	// Record some stages
	stage := a.StartStage("input")
	stage.Done("ok", "", 1)

	stage = a.StartStage("extraction")
	stage.Done("ok", "", 10)

	stage = a.StartStage("parsing")
	stage.Done("warn", "2 parse errors", 3)

	a.AddError("test error 1")
	a.IncrGoFiles()
	a.IncrGoFiles()

	if err := a.Finalize(); err != nil {
		t.Fatalf("Finalize() error: %v", err)
	}

	// Read and verify pipeline.json
	data, err := os.ReadFile(filepath.Join(a.BaseDir(), "pipeline.json"))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var report PipelineReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if report.InputPath != "/path/to/test.jar" {
		t.Errorf("expected InputPath=/path/to/test.jar, got %s", report.InputPath)
	}

	if report.ArchiveType != "JAR" {
		t.Errorf("expected ArchiveType=JAR, got %s", report.ArchiveType)
	}

	if report.TotalJavaFiles != 5 {
		t.Errorf("expected TotalJavaFiles=5, got %d", report.TotalJavaFiles)
	}

	if report.TotalGoFiles != 2 {
		t.Errorf("expected TotalGoFiles=2, got %d", report.TotalGoFiles)
	}

	if len(report.Stages) != 3 {
		t.Fatalf("expected 3 stages, got %d", len(report.Stages))
	}

	if report.Stages[0].Name != "input" {
		t.Errorf("expected stage[0].Name=input, got %s", report.Stages[0].Name)
	}

	if report.Stages[0].Status != "ok" {
		t.Errorf("expected stage[0].Status=ok, got %s", report.Stages[0].Status)
	}

	if report.Stages[2].Status != "warn" {
		t.Errorf("expected stage[2].Status=warn, got %s", report.Stages[2].Status)
	}

	if report.Stages[2].Message != "2 parse errors" {
		t.Errorf("expected stage[2].Message='2 parse errors', got %q", report.Stages[2].Message)
	}

	if len(report.Errors) != 1 || report.Errors[0] != "test error 1" {
		t.Errorf("expected 1 error 'test error 1', got %v", report.Errors)
	}

	if report.TotalDurationMS < 0 {
		t.Errorf("expected non-negative TotalDurationMS, got %d", report.TotalDurationMS)
	}

	if report.StartTime == "" || report.EndTime == "" {
		t.Error("expected non-empty StartTime and EndTime")
	}
}

func TestAuditorStageTimer(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "timer_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	stage := a.StartStage("test_stage")
	stage.Done("ok", "all good", 42)

	report := a.Report()
	if len(report.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(report.Stages))
	}

	s := report.Stages[0]
	if s.Name != "test_stage" {
		t.Errorf("expected Name=test_stage, got %s", s.Name)
	}

	if s.Status != "ok" {
		t.Errorf("expected Status=ok, got %s", s.Status)
	}

	if s.Message != "all good" {
		t.Errorf("expected Message='all good', got %q", s.Message)
	}

	if s.Files != 42 {
		t.Errorf("expected Files=42, got %d", s.Files)
	}

	if s.DurationMS < 0 {
		t.Errorf("expected non-negative DurationMS, got %d", s.DurationMS)
	}
}

func TestAuditorCopyFile(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	// Create a source file
	srcFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(srcFile, []byte("file content"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	a, err := New(tmpDir, "copy_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := a.CopyFile(DirInput, "copied.txt", srcFile); err != nil {
		t.Fatalf("CopyFile error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(a.BaseDir(), DirInput, "copied.txt"))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	if string(data) != "file content" {
		t.Errorf("expected 'file content', got %q", string(data))
	}
}

func TestRecordParsedAST(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "ast_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	module := map[string]any{
		"filename": "Calculator.java",
		"classes":  []string{"Calculator"},
	}

	if err := a.RecordParsedAST("Calculator.java", module); err != nil {
		t.Fatalf("RecordParsedAST error: %v", err)
	}

	// Verify the file was created
	astPath := filepath.Join(a.BaseDir(), DirParsing, "Calculator", "ast.json")
	if _, err := os.Stat(astPath); os.IsNotExist(err) {
		t.Fatalf("ast.json not created at %s", astPath)
	}
}

func TestRecordRewritePrompts(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "rewrite_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := a.RecordRewritePrompts("MyClass.java", "system prompt", "user prompt"); err != nil {
		t.Fatalf("RecordRewritePrompts error: %v", err)
	}

	sysPath := filepath.Join(a.BaseDir(), DirASTRewrite, "MyClass", "rewrite_system_prompt.txt")

	data, err := os.ReadFile(sysPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	if string(data) != "system prompt" {
		t.Errorf("expected 'system prompt', got %q", string(data))
	}
}

func TestRecordCodegenOutput(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "codegen_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := a.RecordCodegenOutput("Foo.java", "package main\n", "package main\n"); err != nil {
		t.Fatalf("RecordCodegenOutput error: %v", err)
	}

	rawPath := filepath.Join(a.BaseDir(), DirCodegen, "Foo", "output_raw.go")

	data, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	if string(data) != "package main\n" {
		t.Errorf("expected 'package main\\n', got %q", string(data))
	}
}

func TestRecordExtraction(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "extract_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	info := &archive.ArchiveInfo{
		ExtractDir: "/tmp/test",
		JavaFiles:  []string{"com/example/Main.java", "com/example/Util.java"},
		ClassFiles: []string{"com/example/Helper.class"},
		NestedJARs: []string{"lib/dep.jar"},
	}

	if err := a.RecordExtraction(info); err != nil {
		t.Fatalf("RecordExtraction error: %v", err)
	}

	listingPath := filepath.Join(a.BaseDir(), DirExtraction, "file_listing.json")

	data, err := os.ReadFile(listingPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var listing map[string]any
	if err := json.Unmarshal(data, &listing); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if listing["java_files"].(float64) != 2 {
		t.Errorf("expected java_files=2, got %v", listing["java_files"])
	}
}

func TestRecordPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "pattern_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	report := &archive.PatternReport{
		HasServlets: true,
		HasEJB:      true,
		EJBTypes:    []string{"@Stateless"},
	}

	if err := a.RecordPatterns(report); err != nil {
		t.Fatalf("RecordPatterns error: %v", err)
	}

	patternPath := filepath.Join(a.BaseDir(), DirPatterns, "pattern_report.json")

	data, err := os.ReadFile(patternPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var parsed archive.PatternReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if !parsed.HasServlets {
		t.Error("expected HasServlets=true")
	}

	if !parsed.HasEJB {
		t.Error("expected HasEJB=true")
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Calculator.java", "Calculator"},
		{"MyClass.java", "MyClass"},
		{"com.example.Main.java", "com_example_Main"},
		{"", "unknown"},
		{"hello world.java", "hello_world"},
		{"Test-Case.java", "Test-Case"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestRecordPatternsNil(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "nil_pattern_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := a.RecordPatterns(nil); err != nil {
		t.Fatalf("RecordPatterns(nil) error: %v", err)
	}

	// Verify no file was created
	patternPath := filepath.Join(a.BaseDir(), DirPatterns, "pattern_report.json")
	if _, err := os.Stat(patternPath); !os.IsNotExist(err) {
		t.Error("expected no pattern_report.json for nil report")
	}
}

func TestAuditDirUsesUUIDv7(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "uuid_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Directory name should be a valid UUID v7 (hex-dash format)
	dirName := filepath.Base(a.BaseDir())

	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRe.MatchString(dirName) {
		t.Errorf("expected UUID v7 directory name, got %q", dirName)
	}

	// Pipeline report should have the ID field set
	report := a.Report()
	if report.ID == "" {
		t.Error("expected non-empty report ID")
	}

	if report.ID != dirName {
		t.Errorf("expected report.ID=%q to match dir name=%q", report.ID, dirName)
	}
}

func TestGenerateUUIDv7Format(t *testing.T) {
	// Generate multiple UUIDs and verify format + version bits
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	seen := make(map[string]struct{})

	for range 100 {
		id, err := generateUUIDv7()
		if err != nil {
			t.Fatalf("generateUUIDv7() error: %v", err)
		}

		if !uuidRe.MatchString(id) {
			t.Errorf("invalid UUID v7 format: %q", id)
		}

		// Check uniqueness
		if _, ok := seen[id]; ok {
			t.Errorf("duplicate UUID generated: %s", id)
		}

		seen[id] = struct{}{}
	}
}

func TestPipelineReportContainsID(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "id_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	a.SetInputPath("/test/input.jar")

	if err := a.Finalize(); err != nil {
		t.Fatalf("Finalize() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(a.BaseDir(), "pipeline.json"))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var report PipelineReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if report.ID == "" {
		t.Error("expected non-empty ID in pipeline.json")
	}

	// Verify the version nibble is 7
	if len(report.ID) >= 19 && report.ID[14] != '7' {
		t.Errorf("expected UUID v7 version nibble '7', got '%c'", report.ID[14])
	}
}

func TestTokenMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "token_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Record multiple API calls
	a.RecordTokenUsage("Calculator.java", "ast_rewrite", 1500, 2000, "end_turn")
	a.RecordTokenUsage("Calculator.java", "codegen", 3000, 1800, "end_turn")
	a.RecordTokenUsage("Util.java", "ast_rewrite", 800, 1200, "end_turn")
	a.RecordTokenUsage("Util.java", "codegen", 2500, 1500, "max_tokens")

	if err := a.Finalize(); err != nil {
		t.Fatalf("Finalize() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(a.BaseDir(), "pipeline.json"))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var report PipelineReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	tokens := report.Tokens

	// Verify totals
	if tokens.TotalInputTokens != 7800 {
		t.Errorf("expected TotalInputTokens=7800, got %d", tokens.TotalInputTokens)
	}

	if tokens.TotalOutputTokens != 6500 {
		t.Errorf("expected TotalOutputTokens=6500, got %d", tokens.TotalOutputTokens)
	}

	if tokens.TotalTokens != 14300 {
		t.Errorf("expected TotalTokens=14300, got %d", tokens.TotalTokens)
	}

	if tokens.APICalls != 4 {
		t.Errorf("expected APICalls=4, got %d", tokens.APICalls)
	}

	// Verify individual calls
	if len(tokens.Calls) != 4 {
		t.Fatalf("expected 4 calls, got %d", len(tokens.Calls))
	}

	// First call
	c := tokens.Calls[0]
	if c.File != "Calculator.java" || c.Stage != "ast_rewrite" {
		t.Errorf("call[0]: expected Calculator.java/ast_rewrite, got %s/%s", c.File, c.Stage)
	}

	if c.InputTokens != 1500 || c.OutputTokens != 2000 {
		t.Errorf("call[0]: expected 1500/2000, got %d/%d", c.InputTokens, c.OutputTokens)
	}

	if c.TotalTokens != 3500 {
		t.Errorf("call[0]: expected TotalTokens=3500, got %d", c.TotalTokens)
	}

	if c.StopReason != "end_turn" {
		t.Errorf("call[0]: expected StopReason=end_turn, got %s", c.StopReason)
	}

	// Last call should have max_tokens stop reason
	last := tokens.Calls[3]
	if last.StopReason != "max_tokens" {
		t.Errorf("call[3]: expected StopReason=max_tokens, got %s", last.StopReason)
	}
}

func TestTokenMetricsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	a, err := New(tmpDir, "empty_token_test", logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := a.Finalize(); err != nil {
		t.Fatalf("Finalize() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(a.BaseDir(), "pipeline.json"))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var report PipelineReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if report.Tokens.TotalTokens != 0 {
		t.Errorf("expected TotalTokens=0, got %d", report.Tokens.TotalTokens)
	}

	if report.Tokens.APICalls != 0 {
		t.Errorf("expected APICalls=0, got %d", report.Tokens.APICalls)
	}

	if len(report.Tokens.Calls) != 0 {
		t.Errorf("expected 0 calls, got %d", len(report.Tokens.Calls))
	}
}

// TestRecordLoopIteration_Appends asserts N calls append N records in order.
func TestRecordLoopIteration_Appends(t *testing.T) {
	a, err := New(t.TempDir(), "loop_iter_test", testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	records := []LoopIterationRecord{
		{UnitID: "u1", Iteration: 1, PassingCount: 0, TotalCount: 3, GoTreeHash: "h1", Status: "running", Timestamp: "2026-01-01T00:00:00Z"},
		{UnitID: "u1", Iteration: 2, PassingCount: 1, TotalCount: 3, GoTreeHash: "h2", Status: "running", Timestamp: "2026-01-01T00:00:01Z"},
		{UnitID: "u1", Iteration: 3, PassingCount: 3, TotalCount: 3, GoTreeHash: "h3", Status: "done", Timestamp: "2026-01-01T00:00:02Z"},
	}

	for _, r := range records {
		a.RecordLoopIteration(r)
	}

	got := a.Report().LoopIterations
	if len(got) != len(records) {
		t.Fatalf("LoopIterations len = %d, want %d", len(got), len(records))
	}

	for i, r := range records {
		if got[i] != r {
			t.Fatalf("record[%d] = %+v, want %+v", i, got[i], r)
		}
	}
}

// TestRecordLoopIteration_TimestampDefaulted asserts an empty timestamp is
// filled with an RFC3339Nano-parseable value.
func TestRecordLoopIteration_TimestampDefaulted(t *testing.T) {
	a, err := New(t.TempDir(), "loop_ts_test", testLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	a.RecordLoopIteration(LoopIterationRecord{UnitID: "u1", Iteration: 1})

	got := a.Report().LoopIterations
	if len(got) != 1 {
		t.Fatalf("LoopIterations len = %d, want 1", len(got))
	}

	if got[0].Timestamp == "" {
		t.Fatalf("timestamp not defaulted")
	}

	if _, err := time.Parse(time.RFC3339Nano, got[0].Timestamp); err != nil {
		t.Fatalf("defaulted timestamp %q not RFC3339Nano: %v", got[0].Timestamp, err)
	}
}

// TestNewID_UniqueNonEmpty asserts NewID returns non-empty distinct IDs.
func TestNewID_UniqueNonEmpty(t *testing.T) {
	id1, err := NewID()
	if err != nil {
		t.Fatalf("NewID first: %v", err)
	}

	id2, err := NewID()
	if err != nil {
		t.Fatalf("NewID second: %v", err)
	}

	if id1 == "" || id2 == "" {
		t.Fatalf("NewID returned empty: %q %q", id1, id2)
	}

	if id1 == id2 {
		t.Fatalf("NewID returned identical IDs: %q", id1)
	}
}
