// Package audit provides a structured audit trail for the full Java conversion pipeline.
// It records all intermediate artifacts from each pipeline stage into a numbered directory structure.
package audit

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// StageInfo records timing and status for a single pipeline stage.
type StageInfo struct {
	Name       string `json:"name"`
	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time"`
	DurationMS int64  `json:"duration_ms"`
	Status     string `json:"status"` // "ok", "warn", "error", "skipped"
	Message    string `json:"message,omitempty"`
	Files      int    `json:"files,omitempty"`
}

// TokenMetrics tracks token usage across all API calls in the pipeline.
type TokenMetrics struct {
	TotalInputTokens  int            `json:"total_input_tokens"`
	TotalOutputTokens int            `json:"total_output_tokens"`
	TotalTokens       int            `json:"total_tokens"`
	APICalls          int            `json:"api_calls"`
	Calls             []APICallUsage `json:"calls,omitempty"`
}

// APICallUsage records token usage for a single API call.
type APICallUsage struct {
	File         string `json:"file"`
	Stage        string `json:"stage"` // "ast_rewrite" or "codegen"
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	TotalTokens  int    `json:"total_tokens"`
	StopReason   string `json:"stop_reason,omitempty"`
}

// PipelineReport is the top-level report written to pipeline.json.
type PipelineReport struct {
	ID              string                `json:"id"`
	ScenarioName    string                `json:"scenario_name,omitempty"`
	InputPath       string                `json:"input_path"`
	ArchiveType     string                `json:"archive_type,omitempty"`
	AuditDir        string                `json:"audit_dir"`
	StartTime       string                `json:"start_time"`
	EndTime         string                `json:"end_time"`
	TotalDurationMS int64                 `json:"total_duration_ms"`
	Stages          []StageInfo           `json:"stages"`
	Tokens          TokenMetrics          `json:"tokens"`
	TotalJavaFiles  int                   `json:"total_java_files"`
	TotalGoFiles    int                   `json:"total_go_files"`
	Errors          []string              `json:"errors,omitempty"`
	LoopIterations  []LoopIterationRecord `json:"loop_iterations,omitempty"`
}

// LoopIterationRecord is one per-iteration audit entry for the verify-correct
// loop (D-03). It is appended additively; existing PipelineReport consumers are
// unaffected because LoopIterations is omitempty when no iterations recorded.
type LoopIterationRecord struct {
	UnitID       string `json:"unit_id"`
	Iteration    int    `json:"iteration"`
	PassingCount int    `json:"passing_count"`
	TotalCount   int    `json:"total_count"`
	GoTreeHash   string `json:"go_tree_hash"`
	Status       string `json:"status"`
	Timestamp    string `json:"timestamp"`
}

// StageTimer tracks the timing of a single stage.
type StageTimer struct {
	auditor   *Auditor
	name      string
	startTime time.Time
}

// Done marks the stage as complete with the given status.
func (st *StageTimer) Done(status, message string, files int) {
	end := time.Now()

	st.auditor.mu.Lock()
	defer st.auditor.mu.Unlock()

	st.auditor.report.Stages = append(st.auditor.report.Stages, StageInfo{
		Name:       st.name,
		StartTime:  st.startTime.Format(time.RFC3339Nano),
		EndTime:    end.Format(time.RFC3339Nano),
		DurationMS: end.Sub(st.startTime).Milliseconds(),
		Status:     status,
		Message:    message,
		Files:      files,
	})
}

// Auditor manages the audit directory structure and records pipeline artifacts.
type Auditor struct {
	baseDir   string
	report    *PipelineReport
	logger    *slog.Logger
	startTime time.Time
	mu        sync.Mutex
}

// New creates a new Auditor rooted at outputDir/<uuid_v7>/. The UUID v7 is
// time-ordered (RFC 9562) so audit directories sort chronologically.
func New(outputDir, scenarioName string, logger *slog.Logger) (*Auditor, error) {
	id, err := generateUUIDv7()
	if err != nil {
		return nil, fmt.Errorf("generate audit ID: %w", err)
	}

	baseDir := filepath.Join(outputDir, id)

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}

	now := time.Now()

	return &Auditor{
		baseDir:   baseDir,
		startTime: now,
		logger:    logger,
		report: &PipelineReport{
			ID:           id,
			ScenarioName: scenarioName,
			AuditDir:     baseDir,
			StartTime:    now.Format(time.RFC3339Nano),
		},
	}, nil
}

// BaseDir returns the root audit directory path.
func (a *Auditor) BaseDir() string {
	return a.baseDir
}

// Report returns the current pipeline report for reading.
func (a *Auditor) Report() *PipelineReport {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.report
}

// SetInputPath sets the input path in the pipeline report.
func (a *Auditor) SetInputPath(path string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.report.InputPath = path
}

// SetArchiveType sets the archive type in the pipeline report.
func (a *Auditor) SetArchiveType(archiveType string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.report.ArchiveType = archiveType
}

// IncrGoFiles increments the total Go files counter.
func (a *Auditor) IncrGoFiles() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.report.TotalGoFiles++
}

// SetTotalJavaFiles sets the total Java files count.
func (a *Auditor) SetTotalJavaFiles(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.report.TotalJavaFiles = n
}

// AddError appends an error message to the pipeline report.
func (a *Auditor) AddError(msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.report.Errors = append(a.report.Errors, msg)
}

// RecordTokenUsage records token usage from a single API call.
func (a *Auditor) RecordTokenUsage(file, stage string, inputTokens, outputTokens int, stopReason string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	total := inputTokens + outputTokens

	a.report.Tokens.TotalInputTokens += inputTokens
	a.report.Tokens.TotalOutputTokens += outputTokens
	a.report.Tokens.TotalTokens += total
	a.report.Tokens.APICalls++

	a.report.Tokens.Calls = append(a.report.Tokens.Calls, APICallUsage{
		File:         file,
		Stage:        stage,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		TotalTokens:  total,
		StopReason:   stopReason,
	})

	a.logger.Info("audit: token usage",
		"file", file,
		"stage", stage,
		"input_tokens", inputTokens,
		"output_tokens", outputTokens,
	)
}

// RecordLoopIteration appends one per-iteration loop record to the report
// (D-03/SC3). It is additive and mirrors RecordTokenUsage's lock+append
// pattern. An empty Timestamp is defaulted to the current UTC RFC3339Nano time.
func (a *Auditor) RecordLoopIteration(r LoopIterationRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if r.Timestamp == "" {
		r.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	a.report.LoopIterations = append(a.report.LoopIterations, r)

	a.logger.Info("audit: loop iteration",
		"unit", r.UnitID,
		"iteration", r.Iteration,
		"passing", r.PassingCount,
		"total", r.TotalCount,
	)
}

// StartStage begins timing a new pipeline stage.
func (a *Auditor) StartStage(name string) *StageTimer {
	a.logger.Info("audit: starting stage", "stage", name)

	return &StageTimer{
		auditor:   a,
		name:      name,
		startTime: time.Now(),
	}
}

// WriteJSON marshals v as indented JSON and writes it to subdir/filename.
func (a *Auditor) WriteJSON(subdir, filename string, v any) error {
	dir := filepath.Join(a.baseDir, subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON for %s/%s: %w", subdir, filename, err)
	}

	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

// WriteText writes text content to subdir/filename.
func (a *Auditor) WriteText(subdir, filename, content string) error {
	dir := filepath.Join(a.baseDir, subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

// CopyFile copies srcPath into subdir/filename within the audit directory.
func (a *Auditor) CopyFile(subdir, filename, srcPath string) error {
	dir := filepath.Join(a.baseDir, subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source %s: %w", srcPath, err)
	}

	defer func() { _ = src.Close() }()

	dstPath := filepath.Join(dir, filename)

	dst, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create destination %s: %w", dstPath, err)
	}

	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy file: %w", err)
	}

	return nil
}

// Finalize writes the pipeline.json summary report.
func (a *Auditor) Finalize() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	a.report.EndTime = now.Format(time.RFC3339Nano)
	a.report.TotalDurationMS = now.Sub(a.startTime).Milliseconds()

	data, err := json.MarshalIndent(a.report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pipeline report: %w", err)
	}

	path := filepath.Join(a.baseDir, "pipeline.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write pipeline.json: %w", err)
	}

	a.logger.Info("audit: pipeline report written", "path", path)

	return nil
}

// NewID returns a stable, time-ordered run-id (UUID v7) reusing the same
// generator as audit directory IDs. Exported for run-id reuse across D-01/D-03
// (A4) so callers do not duplicate the UUID v7 implementation.
func NewID() (string, error) {
	return generateUUIDv7()
}

// generateUUIDv7 generates a time-ordered UUID v7 (RFC 9562).
// First 48 bits are the Unix millisecond timestamp, remaining bits are random.
// This matches the omni pkg/idgen implementation.
func generateUUIDv7() (string, error) {
	uuid := make([]byte, 16)
	now := time.Now().UnixMilli()

	uuid[0] = byte(now >> 40)
	uuid[1] = byte(now >> 32)
	uuid[2] = byte(now >> 24)
	uuid[3] = byte(now >> 16)
	uuid[4] = byte(now >> 8)
	uuid[5] = byte(now)

	if _, err := rand.Read(uuid[6:]); err != nil {
		return "", err
	}

	uuid[6] = (uuid[6] & 0x0f) | 0x70 // Version 7
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant RFC 4122

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

// sanitizeFilename creates a safe filename from a Java source path.
func sanitizeFilename(filename string) string {
	name := filepath.Base(filename)
	name = strings.TrimSuffix(name, filepath.Ext(name))
	// Replace any non-alphanumeric characters with underscores
	var sb strings.Builder

	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}

	result := sb.String()
	if result == "" {
		result = "unknown"
	}

	return result
}
