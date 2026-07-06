//go:build integration

/*
Copyright (c) 2026 Security Research

Integration smoke: verifies that when samplingResolver is faked-available,
kbllm.Call routes through the adapter and never spawns a subprocess.

This test ONLY checks wiring (adapter selected, called, response returned).
It does NOT exercise the real Claude Code sampling pipeline.
*/
package llm

import (
	"context"
	"testing"
	"time"
)

func TestIntegration_CallRoutesThroughSamplingAdapter(t *testing.T) {
	orig := samplingResolver
	t.Cleanup(func() { samplingResolver = orig })

	const want = "integration-sampling-result"
	fake := &fakeSamplingClient{body: []byte(want)}
	samplingResolver = func() SamplingClient { return fake }

	got, err := Call(context.Background(), "ignored-model", "test prompt", 5*time.Second)
	if err != nil {
		t.Fatalf("Call returned error on sampling path: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if !fake.called {
		t.Fatal("sampling adapter was not called — subprocess path engaged unexpectedly")
	}
}

func TestIntegration_CallFallsBackToSubprocessWhenSamplingNil(t *testing.T) {
	orig := samplingResolver
	t.Cleanup(func() { samplingResolver = orig })

	samplingResolver = nil

	// subprocess "claude" is not available in CI → expect an exec error,
	// confirming the subprocess path was taken (not the sampling path).
	_, err := Call(context.Background(), "any-model", "test prompt", 2*time.Second)
	if err == nil {
		t.Fatal("expected subprocess error when no sampling resolver; got nil")
	}
}
