/*
Copyright (c) 2026 Security Research
*/
package prompts

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestCSharpPromptEmbedded(t *testing.T) {
	body := CSharpPrompt()
	if body == "" {
		t.Fatal("CSharpPrompt returned empty string")
	}
	for _, marker := range []string{"ilspycmd", "Mandatory rules", "Forbidden"} {
		if !strings.Contains(body, marker) {
			t.Errorf("csharp prompt missing required marker %q", marker)
		}
	}
}

func TestPromptHash_Stable(t *testing.T) {
	h1 := PromptHash("csharp")
	h2 := PromptHash("csharp")
	if h1 != h2 {
		t.Fatalf("PromptHash not stable: %s vs %s", h1, h2)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h1) {
		t.Fatalf("PromptHash result %q is not 64-hex-char sha256", h1)
	}
}

func TestPromptInjection_SentinelsPresent(t *testing.T) {
	body := CSharpPrompt()
	if !strings.Contains(body, "<<<UNRAVEL_DECOMPILED_INPUT_BEGIN>>>") {
		t.Error("missing BEGIN sentinel in csharp prompt")
	}
	if !strings.Contains(body, "<<<UNRAVEL_DECOMPILED_INPUT_END>>>") {
		t.Error("missing END sentinel in csharp prompt")
	}
}

func TestNames_IncludesCSharp(t *testing.T) {
	got := Names()
	found := slices.Contains(got, "csharp")
	if !found {
		t.Fatalf("Names() = %v, missing 'csharp'", got)
	}
}

func TestRead_UnknownPrompt(t *testing.T) {
	_, err := Read("nonexistent_prompt_xyz")
	if err == nil {
		t.Fatal("expected error for unknown prompt")
	}
}

func TestJavaPromptEmbedded(t *testing.T) {
	body := JavaPrompt()
	if body == "" {
		t.Fatal("JavaPrompt returned empty string")
	}
	for _, marker := range []string{"Java code beautification", "<BEGIN_JAVA_SOURCE>", "<END_JAVA_SOURCE>"} {
		if !strings.Contains(body, marker) {
			t.Errorf("java prompt missing required marker %q", marker)
		}
	}
}

func TestJavaPromptHash_Stable(t *testing.T) {
	h1 := PromptHash("java")
	h2 := PromptHash("java")
	if h1 != h2 {
		t.Fatalf("PromptHash(java) not stable: %s vs %s", h1, h2)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h1) {
		t.Fatalf("PromptHash(java) result %q is not 64-hex-char sha256", h1)
	}
}

func TestPromptInjection_JavaSentinelsPresent(t *testing.T) {
	body := JavaPrompt()
	if !strings.Contains(body, "<BEGIN_JAVA_SOURCE>") {
		t.Error("missing BEGIN sentinel in java prompt")
	}
	if !strings.Contains(body, "<END_JAVA_SOURCE>") {
		t.Error("missing END sentinel in java prompt")
	}
}

func TestJavaScriptPromptEmbedded(t *testing.T) {
	body := JavaScriptPrompt()
	if body == "" {
		t.Fatal("JavaScriptPrompt returned empty string")
	}
	for _, marker := range []string{
		"JavaScript code beautification",
		"<BEGIN_JS_SOURCE>",
		"<END_JS_SOURCE>",
		"{framework_json}",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("javascript prompt missing required marker %q", marker)
		}
	}
}

func TestJavaScriptPromptHash_Stable(t *testing.T) {
	h1 := PromptHash("javascript")
	h2 := PromptHash("javascript")
	if h1 != h2 {
		t.Fatalf("PromptHash(javascript) not stable: %s vs %s", h1, h2)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h1) {
		t.Fatalf("PromptHash(javascript) result %q is not 64-hex-char sha256", h1)
	}
}

func TestPromptInjection_JsSentinelsPresent(t *testing.T) {
	body := JavaScriptPrompt()
	if !strings.Contains(body, "<BEGIN_JS_SOURCE>") {
		t.Error("missing BEGIN sentinel in javascript prompt")
	}
	if !strings.Contains(body, "<END_JS_SOURCE>") {
		t.Error("missing END sentinel in javascript prompt")
	}
}

func TestBundlePromptEmbedded(t *testing.T) {
	body := BundlePrompt()
	if body == "" {
		t.Fatal("BundlePrompt returned empty string")
	}
	for _, marker := range []string{
		"JavaScript bundle module-boundary detector",
		"<BEGIN_BUNDLE>",
		"<END_BUNDLE>",
		`"modules"`,
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("bundle prompt missing required marker %q", marker)
		}
	}
}

func TestBundlePromptHash_Stable(t *testing.T) {
	h1 := PromptHash("bundle")
	h2 := PromptHash("bundle")
	if h1 != h2 {
		t.Fatalf("PromptHash(bundle) not stable: %s vs %s", h1, h2)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h1) {
		t.Fatalf("PromptHash(bundle) result %q is not 64-hex-char sha256", h1)
	}
}

func TestPromptInjection_BundleSentinelsPresent(t *testing.T) {
	body := BundlePrompt()
	if !strings.Contains(body, "<BEGIN_BUNDLE>") {
		t.Error("missing BEGIN sentinel in bundle prompt")
	}
	if !strings.Contains(body, "<END_BUNDLE>") {
		t.Error("missing END sentinel in bundle prompt")
	}
}

func TestExecutiveSummaryPrompt_HasSentinels(t *testing.T) {
	body := ExecutiveSummaryPrompt()
	if !strings.Contains(body, "<<<USER_FINDINGS_BEGIN>>>") {
		t.Error("missing USER_FINDINGS_BEGIN sentinel")
	}
	if !strings.Contains(body, "<<<USER_FINDINGS_END>>>") {
		t.Error("missing USER_FINDINGS_END sentinel")
	}
	if !strings.Contains(body, "{{.Findings}}") {
		t.Error("missing {{.Findings}} template placeholder")
	}
	for _, marker := range []string{"tldr", "top_risks", "remediation_priorities"} {
		if !strings.Contains(body, marker) {
			t.Errorf("missing required JSON output field name %q", marker)
		}
	}
}

func TestCSharpPrompt_StillWorks(t *testing.T) {
	body := CSharpPrompt()
	if body == "" {
		t.Fatal("CSharpPrompt regression — returned empty")
	}
	if !strings.Contains(body, "ilspycmd") {
		t.Error("CSharpPrompt regression — content shifted")
	}
}
