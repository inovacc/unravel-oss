/*
Copyright (c) 2026 Security Research
*/
package debug

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// StepMetadata captures per-analysis-step metadata written as metadata.json.
type StepMetadata struct {
	StepName     string    `json:"step_name"`
	Status       string    `json:"status"` // "ok", "error", "skipped"
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	DurationMs   int64     `json:"duration_ms"`
	Model        string    `json:"model,omitempty"`
	InputTokens  int       `json:"input_tokens,omitempty"`
	OutputTokens int       `json:"output_tokens,omitempty"`
	StopReason   string    `json:"stop_reason,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// StepRecorder records artifacts for a single analysis step.
type StepRecorder struct {
	recorder *Recorder
	dir      string
	meta     *StepMetadata
}

// Start records the step start time.
func (sr *StepRecorder) Start() {
	if !sr.recorder.enabled {
		return
	}

	sr.meta.StartTime = time.Now()
}

// Finish records the end time and writes metadata.json.
func (sr *StepRecorder) Finish() error {
	if !sr.recorder.enabled {
		return nil
	}

	sr.meta.EndTime = time.Now()
	sr.meta.DurationMs = sr.meta.EndTime.Sub(sr.meta.StartTime).Milliseconds()

	return sr.writeJSON("metadata.json", sr.meta)
}

// SetStatus sets the step status in metadata.
func (sr *StepRecorder) SetStatus(status string) {
	if !sr.recorder.enabled {
		return
	}

	sr.meta.Status = status
}

// SetError records an error in metadata.
func (sr *StepRecorder) SetError(err error) {
	if !sr.recorder.enabled || err == nil {
		return
	}

	sr.meta.Error = err.Error()
}

// SetModel sets the model name in metadata.
func (sr *StepRecorder) SetModel(model string) {
	if !sr.recorder.enabled {
		return
	}

	sr.meta.Model = model
}

// SetUsage records API token usage.
func (sr *StepRecorder) SetUsage(inputTokens, outputTokens int, stopReason string) {
	if !sr.recorder.enabled {
		return
	}

	sr.meta.InputTokens = inputTokens
	sr.meta.OutputTokens = outputTokens
	sr.meta.StopReason = stopReason
}

// RecordInput records the input data for this step.
func (sr *StepRecorder) RecordInput(v any) {
	if !sr.recorder.enabled {
		return
	}

	sr.writeJSON("input.json", v)
}

// RecordOutput records the output data for this step.
func (sr *StepRecorder) RecordOutput(v any) {
	if !sr.recorder.enabled {
		return
	}

	sr.writeJSON("output.json", v)
}

// RecordSystemPrompt writes the system prompt used for AI analysis.
func (sr *StepRecorder) RecordSystemPrompt(prompt string) {
	if !sr.recorder.enabled {
		return
	}

	sr.writeFile("system_prompt.md", []byte(prompt))
}

// RecordUserPrompt writes the user prompt sent to the API.
func (sr *StepRecorder) RecordUserPrompt(prompt string) {
	if !sr.recorder.enabled {
		return
	}

	sr.writeFile("user_prompt.md", []byte(prompt))
}

// RecordAPIRequest writes the API request body (without auth headers).
func (sr *StepRecorder) RecordAPIRequest(req any) {
	if !sr.recorder.enabled {
		return
	}

	sr.writeJSON("api_request.json", req)
}

// RecordAPIResponse writes the full API response.
func (sr *StepRecorder) RecordAPIResponse(resp any) {
	if !sr.recorder.enabled {
		return
	}

	sr.writeJSON("api_response.json", resp)
}

// RecordText writes an arbitrary text file into the step directory.
func (sr *StepRecorder) RecordText(name, content string) {
	if !sr.recorder.enabled {
		return
	}

	sr.writeFile(name, []byte(content))
}

func (sr *StepRecorder) writeJSON(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		sr.recorder.logger.Warn("debug: failed to marshal JSON", "file", name, "error", err)

		return err
	}

	return sr.writeFile(name, data)
}

func (sr *StepRecorder) writeFile(name string, data []byte) error {
	path := filepath.Join(sr.dir, name)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		sr.recorder.logger.Warn("debug: failed to write file", "file", path, "error", err)

		return err
	}

	return nil
}
