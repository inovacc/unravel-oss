package reconstruct

import (
	"strings"
	"testing"
)

func TestNewProvenance(t *testing.T) {
	opts := DefaultOptions()
	p := NewProvenance("original content", "reconstructed content", true, nil, opts)

	if p.OriginalHash == "" {
		t.Error("expected non-empty OriginalHash")
	}
	if len(p.OriginalHash) != 64 {
		t.Errorf("expected SHA-256 hash (64 hex chars), got %d chars", len(p.OriginalHash))
	}
	if p.PromptVersion != "v1" {
		t.Errorf("expected PromptVersion=v1, got %s", p.PromptVersion)
	}
	if !p.Verified {
		t.Error("expected Verified=true")
	}
	if p.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestProvenanceConfidence(t *testing.T) {
	opts := DefaultOptions()

	// Verified, no failures -> 1.0
	p := NewProvenance("a", "b", true, nil, opts)
	if p.Confidence != 1.0 {
		t.Errorf("expected 1.0 confidence, got %f", p.Confidence)
	}

	// Not verified, no failures -> 0.8
	p = NewProvenance("a", "b", false, nil, opts)
	if p.Confidence != 0.8 {
		t.Errorf("expected 0.8 confidence, got %f", p.Confidence)
	}

	// With failures -> lower confidence
	p = NewProvenance("a", "b", false, []string{"err1", "err2"}, opts)
	if p.Confidence >= 0.8 {
		t.Errorf("expected confidence < 0.8 with failures, got %f", p.Confidence)
	}
}

func TestProvenanceHeaderJava(t *testing.T) {
	opts := DefaultOptions()
	p := NewProvenance("original", "result", true, nil, opts)
	h := p.Header(LangJava)

	checks := []string{"AI-RECONSTRUCTED", "original_hash:", "confidence:", "prompt_version:", "verified:", "timestamp:"}
	for _, check := range checks {
		if !strings.Contains(h, check) {
			t.Errorf("header missing %q:\n%s", check, h)
		}
	}
	if !strings.HasPrefix(h, "//") {
		t.Errorf("Java header should use // comments, got:\n%s", h)
	}
}

func TestProvenanceHeaderPython(t *testing.T) {
	opts := DefaultOptions()
	p := NewProvenance("original", "result", true, nil, opts)
	h := p.Header(LangPython)

	if !strings.HasPrefix(h, "#") {
		t.Errorf("Python header should use # comments, got:\n%s", h)
	}
	if !strings.Contains(h, "AI-RECONSTRUCTED") {
		t.Errorf("header missing AI-RECONSTRUCTED tag:\n%s", h)
	}
}

func TestProvenanceHeaderGo(t *testing.T) {
	opts := DefaultOptions()
	p := NewProvenance("original", "result", true, nil, opts)
	h := p.Header(LangGo)

	if !strings.HasPrefix(h, "//") {
		t.Errorf("Go header should use // comments, got:\n%s", h)
	}
}

func TestProvenanceHeaderCSharp(t *testing.T) {
	opts := DefaultOptions()
	p := NewProvenance("original", "result", true, nil, opts)
	h := p.Header(LangCSharp)

	if !strings.HasPrefix(h, "//") {
		t.Errorf("C# header should use // comments, got:\n%s", h)
	}
}

func TestProvenanceHeaderWithFailures(t *testing.T) {
	opts := DefaultOptions()
	p := NewProvenance("original", "result", false, []string{"missing func", "wrong type"}, opts)
	h := p.Header(LangJava)

	if !strings.Contains(h, "verify_failures:") {
		t.Errorf("header should include verify_failures:\n%s", h)
	}
}
