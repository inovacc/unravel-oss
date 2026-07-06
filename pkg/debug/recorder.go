/*
Copyright (c) 2026 Security Research
*/
package debug

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// unsafeChars matches characters not safe for directory/file names.
var unsafeChars = regexp.MustCompile(`[/\\:*?"<>|]`)

// Recorder manages a debug session directory and writes artifacts into it.
type Recorder struct {
	baseDir string
	logger  *slog.Logger
	enabled bool
}

// NopRecorder returns a disabled recorder. All methods are no-ops.
func NopRecorder() *Recorder {
	return &Recorder{enabled: false}
}

// New creates a new debug recorder under rootDir/debug/YYYY-MM-DD_HH-MM-SS/.
func New(rootDir string, logger *slog.Logger) (*Recorder, error) {
	ts := time.Now().Format("2006-01-02_15-04-05")
	dir := filepath.Join(rootDir, "debug", ts)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create debug directory: %w", err)
	}

	logger.Info("debug mode enabled", "dir", dir)

	return &Recorder{
		baseDir: dir,
		logger:  logger,
		enabled: true,
	}, nil
}

// Enabled reports whether debug recording is active.
func (r *Recorder) Enabled() bool {
	return r.enabled
}

// BaseDir returns the session debug directory path.
func (r *Recorder) BaseDir() string {
	return r.baseDir
}

// StepRecorder creates a per-analysis-step recorder under a sanitized subdirectory.
func (r *Recorder) StepRecorder(name string) *StepRecorder {
	if !r.enabled {
		return &StepRecorder{recorder: r}
	}

	safeName := sanitizeName(name)
	dir := filepath.Join(r.baseDir, safeName)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.logger.Warn("failed to create step debug dir", "dir", dir, "error", err)
	}

	return &StepRecorder{
		recorder: r,
		dir:      dir,
		meta:     &StepMetadata{StepName: name},
	}
}

// WriteJSON writes a JSON file at the session level.
func (r *Recorder) WriteJSON(name string, v any) error {
	if !r.enabled {
		return nil
	}

	path := filepath.Join(r.baseDir, name)

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}

	return nil
}

// WriteText writes a text file at the session level.
func (r *Recorder) WriteText(name, content string) error {
	if !r.enabled {
		return nil
	}

	path := filepath.Join(r.baseDir, name)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}

	return nil
}

// sanitizeName converts a step name into a safe directory name.
func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, " ", "_")
	name = unsafeChars.ReplaceAllString(name, "_")

	return name
}
