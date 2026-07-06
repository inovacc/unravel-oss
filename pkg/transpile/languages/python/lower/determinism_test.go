// Package lower_test holds the Python --ast determinism regression test in
// an external test package: internal/languages/python imports
// internal/languages/python/lower, so an in-package (package lower) test that
// also imports internal/languages/python forms an import cycle. The external
// test package breaks the cycle while still exercising the registered plugin
// through the public converter seam (mirrors converter/determinism_test.go).
package lower_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/converter"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages"

	// Side-effect import: registers the Python language plugin (as cmd/convert.go does).
	_ "github.com/inovacc/unravel-oss/pkg/transpile/languages/python"
)

// pythonFlakeCases are the three Python `--ast` prompt-mode scenarios that
// Wave 1 (08-01) recorded as non-deterministic against the committed golden
// baseline (D-02). Root cause (diagnosed in 08-02): these three sources use
// Python syntax the ANTLR grammar cannot parse, so the deterministic seam
// (cmd/convert.go routes Python --ast to ConvertWithDeterministic, since the
// Python plugin is a DeterministicLanguage) HARD-ERRORED on parse failure —
// empty stdout, exit 1 — while the committed golden was recorded from the
// graceful `ast-fallback` raw prompt that ConvertWithLanguageAST emits on
// parse failure. The fix makes ConvertWithDeterministic mirror that graceful
// fallback so a parse-failing `--ast` Python file deterministically yields a
// non-empty ast-fallback prompt (general path fix, NOT per-file pinning).
var pythonFlakeCases = []struct {
	name string
	path string
}{
	{"text_adventure", filepath.Join("..", "..", "..", "test_scenarios", "python", "08_text_adventure", "text_adventure.py")},
	{"sorting_algorithms", filepath.Join("..", "..", "..", "test_scenarios", "python", "11_sorting_algorithms", "sorting_algorithms.py")},
	{"url_shortener", filepath.Join("..", "..", "..", "test_scenarios", "python", "14_url_shortener", "url_shortener.py")},
}

func newTestConverter() *converter.Converter {
	return converter.New(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
}

func pythonDeterministicLang(t *testing.T) languages.DeterministicLanguage {
	t.Helper()

	lang, err := languages.ForFile("module.py")
	if err != nil {
		t.Fatalf("resolve python language: %v", err)
	}

	dl, ok := lang.(languages.DeterministicLanguage)
	if !ok {
		t.Fatalf("python language %T does not implement DeterministicLanguage", lang)
	}

	return dl
}

// TestPythonASTParseFailFallbackDeterministic exercises the SAME seam the CLI
// uses for Python `--ast` (ConvertWithDeterministic) on the three Wave-1
// flake sources. It asserts the observable contract D-02 requires:
//
//  1. parse failure must NOT be a fatal error (the committed golden is a
//     non-empty ast-fallback prompt, not an empty/error result);
//  2. the UserPrompt is non-empty; and
//  3. two in-process runs on the same source produce a byte-identical
//     UserPrompt (general determinism).
//
// RED before the fix: ConvertWithDeterministic returns a fatal parse error
// (empty result). GREEN after: it gracefully falls back to the deterministic
// ast-fallback raw prompt for every parse-failing input.
func TestPythonASTParseFailFallbackDeterministic(t *testing.T) {
	conv := newTestConverter()
	dl := pythonDeterministicLang(t)
	ctx := context.Background()

	for _, tc := range pythonFlakeCases {
		t.Run(tc.name, func(t *testing.T) {
			src, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("read flake source %s: %v", tc.path, err)
			}

			base := filepath.Base(tc.path)

			run1, err := conv.ConvertWithDeterministic(ctx, dl, base, src)
			if err != nil {
				t.Fatalf("run 1: parse-failing --ast Python must fall back, got fatal error: %v", err)
			}

			run2, err := conv.ConvertWithDeterministic(ctx, dl, base, src)
			if err != nil {
				t.Fatalf("run 2: parse-failing --ast Python must fall back, got fatal error: %v", err)
			}

			if run1.UserPrompt == "" {
				t.Fatalf("expected non-empty fallback UserPrompt for parse-failing %s", tc.name)
			}

			if run1.UserPrompt != run2.UserPrompt {
				l1 := splitLines(run1.UserPrompt)
				l2 := splitLines(run2.UserPrompt)
				diffAt, a, b := firstDiff(l1, l2)
				t.Fatalf("non-deterministic fallback prompt for %s: first diff at line %d\n--- run1[%d] ---\n%s\n--- run2[%d] ---\n%s",
					tc.name, diffAt, diffAt, a, diffAt, b)
			}
		})
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}

func firstDiff(a, b []string) (int, string, string) {
	n := min(len(b), len(a))
	for i := range n {
		if a[i] != b[i] {
			return i + 1, a[i], b[i]
		}
	}
	if len(a) != len(b) {
		return n + 1, "<a longer/shorter>", "<b longer/shorter>"
	}
	return 0, "", ""
}
