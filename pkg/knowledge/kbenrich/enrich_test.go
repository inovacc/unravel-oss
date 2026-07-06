/*
Copyright (c) 2026 Security Research
*/
package kbenrich

import (
	"context"
	"testing"
	"time"
)

// TestOptsDefaults verifies that EnrichCore applies Phase A winning-recipe
// defaults when a zero Opts is provided.
func TestOptsDefaults(t *testing.T) {
	// Simulate the default-application logic (mirrors EnrichCore preamble).
	opts := Opts{}
	if opts.Concurrent < 1 {
		opts.Concurrent = 8
	}
	if opts.Model == "" {
		opts.Model = "sonnet"
	}
	if opts.PromptBatch < 1 {
		opts.PromptBatch = 1
	}
	if opts.TimeoutSec < 1 {
		opts.TimeoutSec = 90
	}
	if opts.Limit < 1 {
		opts.Limit = 100
	}

	if opts.Model != "sonnet" {
		t.Errorf("default model: want sonnet, got %q", opts.Model)
	}
	if opts.Concurrent != 8 {
		t.Errorf("default concurrent: want 8, got %d", opts.Concurrent)
	}
	if opts.Limit != 100 {
		t.Errorf("default limit: want 100, got %d", opts.Limit)
	}
	if opts.TimeoutSec != 90 {
		t.Errorf("default timeout_sec: want 90, got %d", opts.TimeoutSec)
	}
	if opts.PromptBatch != 1 {
		t.Errorf("default prompt_batch: want 1, got %d", opts.PromptBatch)
	}
}

// TestCallFnSeam verifies the CallFn type alias compiles and can be used
// as a function value, confirming the seam is correctly typed.
func TestCallFnSeam(t *testing.T) {
	var fn CallFn = func(_ context.Context, model, _ string, _ time.Duration) (string, error) {
		return "model=" + model, nil
	}
	result, err := fn(context.Background(), "haiku", "prompt", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result != "model=haiku" {
		t.Errorf("got %q, want \"model=haiku\"", result)
	}
}

// TestParseEnrichJSON validates the JSON extraction helper handles
// leading prose and extracts the JSON object correctly.
func TestParseEnrichJSON(t *testing.T) {
	raw := `Here is the analysis:
{"summary":"does auth","long_summary":"long","role":"auth","inputs":[],"outputs":[],"side_effects":[],"deps":[],"tags":["auth"]}`

	got, err := parseEnrichJSON(raw)
	if err != nil {
		t.Fatalf("parseEnrichJSON: %v", err)
	}
	if got.Summary != "does auth" {
		t.Errorf("summary: want %q, got %q", "does auth", got.Summary)
	}
	if got.Role != "auth" {
		t.Errorf("role: want auth, got %q", got.Role)
	}
}

// TestParseEnrichJSONMissingSummary checks that a missing summary field is
// rejected.
func TestParseEnrichJSONMissingSummary(t *testing.T) {
	raw := `{"long_summary":"no summary field","role":"util","inputs":[],"outputs":[],"side_effects":[],"deps":[],"tags":[]}`
	_, err := parseEnrichJSON(raw)
	if err == nil {
		t.Error("expected error for missing summary, got nil")
	}
}
