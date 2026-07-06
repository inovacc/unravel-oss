package converter

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages"

	// Side-effect import: registers the Java language plugin (as cmd/convert.go does).
	_ "github.com/inovacc/unravel-oss/pkg/transpile/languages/java"
)

// pureCoreJava is a small entirely D-01-core Java source: a class with a
// field, a constructor, and one simple method — NO lambda, reflection, or
// annotation-as-behavior. It must convert through the deterministic pipeline
// byte-identically with no LLM prompt.
const pureCoreJava = `package sample;

public class Counter {
    private int value;

    public Counter(int start) {
        this.value = start;
    }

    public int getValue() {
        return this.value;
    }
}
`

// lambdaHeavyJava exercises a Java stream/lambda construct that cannot be
// lowered deterministically — it must still travel the deterministic PATH
// (Mode "deterministic (LLM fallback)", Path "deterministic") per D-02/D-05.
const lambdaHeavyJava = `package sample;

import java.util.List;
import java.util.stream.Collectors;

public class Names {
    public List<String> upper(List<String> in) {
        return in.stream()
                 .map(s -> s.toUpperCase())
                 .filter(s -> s.length() > 1)
                 .collect(Collectors.toList());
    }
}
`

func newTestConverter() *Converter {
	return New(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
}

func javaDeterministicLang(t *testing.T) languages.DeterministicLanguage {
	t.Helper()

	lang, err := languages.ForFile("Sample.java")
	if err != nil {
		t.Fatalf("resolve java language: %v", err)
	}

	dl, ok := lang.(languages.DeterministicLanguage)
	if !ok {
		t.Fatalf("java language %T does not implement DeterministicLanguage", lang)
	}

	return dl
}

// TestJavaDeterministicConvertTwice proves a pure-core Java file converts
// byte-identically across two runs through the deterministic pipeline with
// no LLM prompt (D-07/SC2).
func TestJavaDeterministicConvertTwice(t *testing.T) {
	conv := newTestConverter()
	dl := javaDeterministicLang(t)
	src := []byte(pureCoreJava)
	ctx := context.Background()

	run1, err := conv.ConvertWithDeterministic(ctx, dl, "Counter.java", src)
	if err != nil {
		t.Fatalf("run 1 conversion failed: %v", err)
	}

	run2, err := conv.ConvertWithDeterministic(ctx, dl, "Counter.java", src)
	if err != nil {
		t.Fatalf("run 2 conversion failed: %v", err)
	}

	if run1.GoCode != run2.GoCode {
		t.Fatalf("non-deterministic output:\n--- run1 ---\n%s\n--- run2 ---\n%s", run1.GoCode, run2.GoCode)
	}

	if run1.Mode != "deterministic" {
		t.Fatalf("Mode = %q, want %q (pure-core file must not need LLM fallback)", run1.Mode, "deterministic")
	}

	if run1.Path != "deterministic" {
		t.Fatalf("Path = %q, want %q", run1.Path, "deterministic")
	}

	if run1.GoCode == "" {
		t.Fatalf("expected non-empty deterministic GoCode for a pure-core file")
	}
}

// TestJavaHybridStillDeterministicPath proves that a lambda/stream-heavy Java
// file routed through ConvertWithDeterministic stays classified on the
// deterministic PATH regardless of whether the residual gap triggers an LLM
// fallback (D-02/D-05): the Path marker is "deterministic" for BOTH
// Mode "deterministic" and Mode "deterministic (LLM fallback)".
//
// NOTE: whether a stream construct trips NeedsLLMFallback depends on the
// Wave-1 lowerer's RawStmt/RawExpr emission maturity (out of Plan 06-02
// scope, which only wires the plugin + Path field). This test asserts the
// invariant 06-02 actually guarantees: the Path classification is correct
// on the deterministic seam for either Mode outcome.
func TestJavaHybridStillDeterministicPath(t *testing.T) {
	conv := newTestConverter()
	dl := javaDeterministicLang(t)
	src := []byte(lambdaHeavyJava)
	ctx := context.Background()

	res, err := conv.ConvertWithDeterministic(ctx, dl, "Names.java", src)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	if res.Mode != "deterministic" && res.Mode != "deterministic (LLM fallback)" {
		t.Fatalf("Mode = %q, want a deterministic-seam mode", res.Mode)
	}

	if res.Path != "deterministic" {
		t.Fatalf("Path = %q, want %q (deterministic seam is always the deterministic path, D-05)", res.Path, "deterministic")
	}
}
