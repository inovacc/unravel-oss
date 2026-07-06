/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
)

// TestStageTimer_EmitsStructuredKeys verifies that the closure returned by
// stageTimer emits an INFO slog record carrying snake_case keys stage,
// target and a numeric elapsed_ms, captured via a JSON handler on a buffer.
func TestStageTimer_EmitsStructuredKeys(t *testing.T) {
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(orig) })

	end := stageTimer("analyzer", "target-x")
	end()

	// Two records: start + end. Inspect the last (end) line.
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	var last map[string]any
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode slog json: %v", err)
		}
		last = m
	}
	if last == nil {
		t.Fatal("no slog records captured")
	}
	if last["stage"] != "analyzer" {
		t.Fatalf("stage key = %v, want analyzer", last["stage"])
	}
	if last["target"] != "target-x" {
		t.Fatalf("target key = %v, want target-x", last["target"])
	}
	if _, ok := last["elapsed_ms"].(float64); !ok {
		t.Fatalf("elapsed_ms missing or not numeric: %v (%T)", last["elapsed_ms"], last["elapsed_ms"])
	}
}

// TestStageTimer_NeverWritesStdout asserts the helper keeps stdout data-only.
func TestStageTimer_NeverWritesStdout(t *testing.T) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(orig) })

	end := stageTimer("detect", "/tmp/x", "count", 3)
	end("items", 7)

	_ = w.Close()
	var captured bytes.Buffer
	_, _ = captured.ReadFrom(r)
	if captured.Len() != 0 {
		t.Fatalf("stageTimer wrote to os.Stdout: %q", captured.String())
	}
}
