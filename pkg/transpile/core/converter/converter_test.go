package converter

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestExtractGoCode(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "fenced go block",
			raw:  "```go\npackage main\n```",
			want: "package main",
		},
		{
			name: "fenced generic block",
			raw:  "```\npackage main\n```",
			want: "package main",
		},
		{
			name: "unfenced code",
			raw:  "package main\n\nfunc main() {}\n",
			want: "package main\n\nfunc main() {}",
		},
		{
			name: "empty string",
			raw:  "",
			want: "",
		},
		{
			name: "whitespace only",
			raw:  "  \n\t\n  ",
			want: "",
		},
		{
			name: "fenced with extra whitespace",
			raw:  "  ```go\n  package main\n  ```  ",
			want: "package main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGoCode(tt.raw)
			if got != tt.want {
				t.Errorf("extractGoCode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatGoCode(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{
			name:    "valid go code",
			src:     "package main\n\nfunc main() {\nfmt.Println(\"hello\")\n}\n",
			wantErr: false,
		},
		{
			name:    "already formatted",
			src:     "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n",
			wantErr: false,
		},
		{
			name:    "invalid syntax",
			src:     "not valid go code at all }{ invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := formatGoCode(tt.src)
			if (err != nil) != tt.wantErr {
				t.Errorf("formatGoCode() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if err == nil && result == "" {
				t.Error("formatGoCode() returned empty string for valid code")
			}
		})
	}
}

func TestFormatGoCode_AddsImports(t *testing.T) {
	src := "package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n"

	result, err := formatGoCode(src)
	if err != nil {
		t.Fatalf("formatGoCode() error = %v", err)
	}

	if !contains(result, "import") {
		t.Error("expected goimports to add import statement")
	}
}

func TestConvertWithLanguage_ReturnsPromptResult(t *testing.T) {
	conv := New(testLogger())
	lang := cpp.New()

	result, err := conv.ConvertWithLanguage(context.Background(), lang, "test.cpp", []byte(`#include <iostream>\nint main() { return 0; }`))
	if err != nil {
		t.Fatalf("ConvertWithLanguage() error = %v", err)
	}

	if result == nil {
		t.Fatal("ConvertWithLanguage() returned nil")
	}

	if result.SystemPrompt == "" {
		t.Error("expected non-empty SystemPrompt")
	}

	if result.UserPrompt == "" {
		t.Error("expected non-empty UserPrompt")
	}

	if result.Language != "C/C++" {
		t.Errorf("expected Language=C/C++, got %s", result.Language)
	}

	if result.Mode != "raw" {
		t.Errorf("expected Mode=raw, got %s", result.Mode)
	}

	if result.GoCode != "" {
		t.Error("raw mode should not produce GoCode")
	}
}

func TestConvertWithDeterministic_ReturnsResult(t *testing.T) {
	conv := New(testLogger())
	lang := cpp.New()

	source := `#include <iostream>

class Point {
public:
    double x, y;
};

int main() {
    Point p;
    p.x = 1.0;
    p.y = 2.0;
    return 0;
}
`

	result, err := conv.ConvertWithDeterministic(context.Background(), lang, "test.cpp", []byte(source))
	if err != nil {
		t.Fatalf("ConvertWithDeterministic() error = %v", err)
	}

	if result == nil {
		t.Fatal("ConvertWithDeterministic() returned nil")
	}

	// Either GoCode is set (deterministic succeeded) or prompts are set (LLM fallback needed)
	if result.GoCode == "" && result.SystemPrompt == "" {
		t.Error("expected either GoCode or SystemPrompt to be set")
	}
}

func TestPromptResult_Format(t *testing.T) {
	t.Run("with GoCode", func(t *testing.T) {
		pr := &PromptResult{
			Language: "C/C++",
			File:     "test.cpp",
			Mode:     "deterministic",
			GoCode:   "package main\n\nfunc main() {}\n",
		}

		formatted := pr.Format()
		if formatted != pr.GoCode {
			t.Errorf("Format() with GoCode should return GoCode directly, got %q", formatted)
		}
	})

	t.Run("with prompts", func(t *testing.T) {
		pr := &PromptResult{
			Language:     "C/C++",
			File:         "test.cpp",
			Mode:         "raw",
			SystemPrompt: "You are a converter.",
			UserPrompt:   "Convert this code.",
		}

		formatted := pr.Format()
		if !contains(formatted, "=== TOGO CONVERSION PROMPTS ===") {
			t.Error("expected formatted output to contain header")
		}

		if !contains(formatted, "=== SYSTEM PROMPT ===") {
			t.Error("expected formatted output to contain system prompt section")
		}

		if !contains(formatted, "=== USER PROMPT ===") {
			t.Error("expected formatted output to contain user prompt section")
		}
	})
}

func TestConvertWithDeterministic_HasConfidence(t *testing.T) {
	conv := New(testLogger())
	lang := cpp.New()

	source := `class Point {
public:
    double x, y;
};
`

	result, err := conv.ConvertWithDeterministic(context.Background(), lang, "point.cpp", []byte(source))
	if err != nil {
		t.Fatalf("ConvertWithDeterministic() error = %v", err)
	}

	if result.Confidence == nil {
		t.Fatal("expected Confidence to be set")
	}

	if result.Confidence.TotalNodes == 0 {
		t.Error("TotalNodes should be > 0")
	}

	if result.Confidence.Ratio < 0 || result.Confidence.Ratio > 1 {
		t.Errorf("Ratio = %f, want 0.0-1.0", result.Confidence.Ratio)
	}
}

func TestConfidenceScore_InFormat(t *testing.T) {
	pr := &PromptResult{
		Language: "Python",
		File:     "test.py",
		Mode:     "deterministic (LLM fallback)",
		Confidence: &ConfidenceScore{
			TotalNodes:         10,
			DeterministicNodes: 7,
			RawNodes:           3,
			Ratio:              0.7,
		},
		SystemPrompt: "system",
		UserPrompt:   "user",
	}

	formatted := pr.Format()
	if !contains(formatted, "70% deterministic") {
		t.Error("expected confidence in formatted output")
	}
	if !contains(formatted, "3 need LLM") {
		t.Error("expected raw node count in formatted output")
	}
}

func TestComputeConfidence(t *testing.T) {
	mod := &ir.Module{
		Decls: []ir.Node{
			&ir.TypeDecl{Kind: ir.TypeDeclStruct, Name: "Foo"},
			&ir.FuncDecl{
				Name: "Bar",
				Body: []ir.Node{
					&ir.ReturnStmt{Values: []ir.Expr{&ir.RawExpr{Text: "x + y"}}},
					&ir.RawStmt{Text: "complex code"},
				},
			},
			&ir.VarDecl{Name: "x"},
		},
	}

	c := computeConfidence(mod)
	// Nodes: TypeDecl(1) + FuncDecl(1) + ReturnStmt(1) + RawStmt(1) + VarDecl(1) = 5 total
	// Raw: RawExpr in ReturnStmt(1) + RawStmt(1) = 2 raw
	if c.TotalNodes != 5 {
		t.Errorf("TotalNodes = %d, want 5", c.TotalNodes)
	}
	if c.RawNodes != 2 {
		t.Errorf("RawNodes = %d, want 2", c.RawNodes)
	}
	if c.DeterministicNodes != 3 {
		t.Errorf("DeterministicNodes = %d, want 3", c.DeterministicNodes)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}

	return false
}
