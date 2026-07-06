/*
Copyright (c) 2026 Security Research

Tests for MCPClassifier: prompt rendering, response parsing, error paths.
Phase 45 / LLMC-02.
*/
package classify

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeClient is a deterministic ClassifyMCPClient driver. The body field is
// returned verbatim; capturedPrompt records the rendered prompt for
// assertions.
type fakeClient struct {
	body           []byte
	err            error
	capturedPrompt string
	calls          int
}

func (f *fakeClient) ClassifyModule(_ context.Context, prompt string) ([]byte, error) {
	f.calls++
	f.capturedPrompt = prompt
	return f.body, f.err
}

// TestMCPClassifier_HappyPath asserts a valid JSON response is parsed into
// a component.Result with classifier='llm'.
func TestMCPClassifier_HappyPath(t *testing.T) {
	fc := &fakeClient{body: []byte(`{"component":"auth","confidence":0.9,"evidence":"jwt symbols present"}`)}
	clf := MCPClassifier{Client: fc}

	res, err := clf.Classify(context.Background(), ModuleRow{ID: 1, Name: "auth.go", Path: "x", SymbolsJSON: "[]"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Component != "auth" {
		t.Fatalf("component = %q; want auth", res.Component)
	}
	if res.Classifier != "llm" {
		t.Fatalf("classifier = %q; want llm", res.Classifier)
	}
	if res.Confidence < 0.89 || res.Confidence > 0.91 {
		t.Fatalf("confidence = %v; want ~0.9", res.Confidence)
	}
	if !strings.Contains(fc.capturedPrompt, "auth.go") {
		t.Fatalf("prompt did not include module name: %q", fc.capturedPrompt)
	}
}

// TestMCPClassifier_NilClient surfaces ErrNoClient — composite wrappers
// rely on this distinct error to drive fallback decisions.
func TestMCPClassifier_NilClient(t *testing.T) {
	_, err := MCPClassifier{}.Classify(context.Background(), ModuleRow{ID: 1})
	if !errors.Is(err, ErrNoClient) {
		t.Fatalf("err = %v; want ErrNoClient", err)
	}
}

// TestMCPClassifier_TransportError propagates the client error wrapped.
func TestMCPClassifier_TransportError(t *testing.T) {
	wantErr := errors.New("boom")
	fc := &fakeClient{err: wantErr}
	_, err := MCPClassifier{Client: fc}.Classify(context.Background(), ModuleRow{ID: 1})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v; want wrapped boom", err)
	}
}

// TestMCPClassifier_EmptyBody is treated as an error so composite falls
// back rather than persisting an empty bucket.
func TestMCPClassifier_EmptyBody(t *testing.T) {
	fc := &fakeClient{body: []byte("   ")}
	_, err := MCPClassifier{Client: fc}.Classify(context.Background(), ModuleRow{ID: 1})
	if err == nil {
		t.Fatalf("expected error on empty body")
	}
}

// TestMCPClassifier_MalformedJSON rejects parse failures explicitly.
func TestMCPClassifier_MalformedJSON(t *testing.T) {
	fc := &fakeClient{body: []byte("not json")}
	_, err := MCPClassifier{Client: fc}.Classify(context.Background(), ModuleRow{ID: 1})
	if err == nil {
		t.Fatalf("expected parse error")
	}
}

// TestMCPClassifier_BucketHallucination rejects unknown taxonomy values
// to defend against model output drift.
func TestMCPClassifier_BucketHallucination(t *testing.T) {
	fc := &fakeClient{body: []byte(`{"component":"unicorn","confidence":0.5}`)}
	_, err := MCPClassifier{Client: fc}.Classify(context.Background(), ModuleRow{ID: 1})
	if err == nil || !strings.Contains(err.Error(), "taxonomy") {
		t.Fatalf("err = %v; want taxonomy rejection", err)
	}
}

// TestMCPClassifier_PromptVersionLocked guards the v1 contract.
func TestMCPClassifier_PromptVersionLocked(t *testing.T) {
	if (MCPClassifier{}).PromptVersion() != "v1" {
		t.Fatalf("PromptVersion drifted from v1")
	}
}
