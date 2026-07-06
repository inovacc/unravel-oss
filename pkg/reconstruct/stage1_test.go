package reconstruct

import (
	"os"
	"strings"
	"testing"
)

func TestStructuralCleanupJava(t *testing.T) {
	input, err := os.ReadFile("testdata/input/Sample.java")
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	expected, err := os.ReadFile("testdata/expected/sample_cleaned.java")
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}

	got := StructuralCleanup(string(input), LangJava)
	want := string(expected)

	// Normalize line endings for comparison.
	got = strings.ReplaceAll(got, "\r\n", "\n")
	want = strings.ReplaceAll(want, "\r\n", "\n")

	if got != want {
		t.Errorf("Java cleanup mismatch.\n--- GOT ---\n%s\n--- WANT ---\n%s", got, want)
	}
}

func TestStructuralCleanupJavaScript(t *testing.T) {
	input, err := os.ReadFile("testdata/input/bundle.min.js")
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	expected, err := os.ReadFile("testdata/expected/bundle_cleaned.js")
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}

	got := StructuralCleanup(string(input), LangJavaScript)
	want := string(expected)

	got = strings.ReplaceAll(got, "\r\n", "\n")
	want = strings.ReplaceAll(want, "\r\n", "\n")

	if got != want {
		t.Errorf("JS cleanup mismatch.\n--- GOT (len=%d) ---\n%s\n--- WANT (len=%d) ---\n%s", len(got), got, len(want), want)
	}
}

func TestStructuralCleanupJavaRemovesGotoLabels(t *testing.T) {
	input := `public void test() {
    /* goto */ label_1:
    int x = 0;
    label_2:
    x++;
}`
	got := StructuralCleanup(input, LangJava)
	if strings.Contains(got, "goto") {
		t.Errorf("expected goto comments removed, got: %s", got)
	}
	if strings.Contains(got, "label_1") || strings.Contains(got, "label_2") {
		t.Errorf("expected labels removed, got: %s", got)
	}
}

func TestStructuralCleanupJavaRemovesSyntheticAccessors(t *testing.T) {
	input := `public class Foo {
    static /* synthetic */ List access$000(Foo x0) {
        return x0.items;
    }

    public void real() {}
}`
	got := StructuralCleanup(input, LangJava)
	if strings.Contains(got, "access$000") {
		t.Errorf("expected synthetic accessor removed, got: %s", got)
	}
	if !strings.Contains(got, "real()") {
		t.Errorf("expected real method preserved, got: %s", got)
	}
}

func TestStructuralCleanupUnknownLanguage(t *testing.T) {
	input := "line1   \n\n\n\n\nline2\n"
	got := StructuralCleanup(input, LangUnknown)

	// Should collapse 5 blank lines to max 2 (3+ consecutive newlines OK, 4+ not).
	if strings.Contains(got, "\n\n\n\n") {
		t.Errorf("expected max 2 consecutive blank lines, got: %q", got)
	}
	if strings.Contains(got, "line1   ") {
		t.Errorf("expected trailing whitespace trimmed, got: %q", got)
	}
}
