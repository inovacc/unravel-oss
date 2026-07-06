package decompiler

import (
	"context"
	"strings"
	"testing"
)

func TestHybridDecompiler_SelectPreferredSource_UsesJudgeWhenAvailable(t *testing.T) {
	var calls int

	h := &HybridDecompiler{
		Judge: judgeFunc(func(ctx context.Context, prompt string) (string, error) {
			calls++
			if !strings.Contains(prompt, "Native metrics:") {
				t.Fatalf("judge prompt missing native metrics: %s", prompt)
			}
			if !strings.Contains(prompt, "Fallback metrics:") {
				t.Fatalf("judge prompt missing fallback metrics: %s", prompt)
			}
			return "FALLBACK", nil
		}),
	}

	nativeSource := "package demo;\n\npublic class Demo {\n    public void run() {\n    }\n}\n"
	fallbackSource := "package demo;\n\npublic class Demo {\n    public void run(){\n    }\n}\n"

	got, err := h.selectPreferredSource(nativeSource, fallbackSource)
	if err != nil {
		t.Fatalf("selectPreferredSource returned error: %v", err)
	}
	if got != fallbackSource {
		t.Fatalf("selectPreferredSource chose wrong source\nwant fallback\n got:\n%s", got)
	}
	if calls != 1 {
		t.Fatalf("judge calls = %d, want 1", calls)
	}
}

func TestHybridDecompiler_SelectPreferredSource_FallsBackToScoreOnBadJudgeOutput(t *testing.T) {
	h := &HybridDecompiler{
		Judge: judgeFunc(func(context.Context, string) (string, error) {
			return "maybe", nil
		}),
	}

	nativeSource := "package demo;\n\nimport java.util.List;\n\npublic class Demo {\n    public void run() {\n    }\n}\n"
	fallbackSource := "public class Demo {\n    public void run() {\n    }\n}\n"

	got, err := h.selectPreferredSource(nativeSource, fallbackSource)
	if err != nil {
		t.Fatalf("selectPreferredSource returned error: %v", err)
	}
	if got != nativeSource {
		t.Fatalf("selectPreferredSource chose wrong source\nwant native\n got:\n%s", got)
	}
}
