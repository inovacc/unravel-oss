package decompiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBooleanConditionStructuredIf pins two decompiler-parity fixes together on
// Cond.pick (`if (flag(n)) return 1; return 2;`):
//
//  1. Boolean-as-int: `ifeq` on a boolean must not render as `expr == 0` (a
//     boolean cannot be compared to an int; won't compile).
//  2. op03 control-flow structuring: the if-goto must become a real StructuredIf
//     with a positive condition, `if (this.flag(var1)) { return 1; }` — matching
//     CFR's `if (this.flag(n)) { return 1; }` — not leak as `/* unknown: if ...
//     goto N */`.
func TestBooleanConditionStructuredIf(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "Cond.class"))
	if err != nil {
		t.Fatalf("read Cond.class: %v", err)
	}
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes: %v", err)
	}
	// (1) No boolean-compared-to-int.
	if strings.Contains(source, "== 0") || strings.Contains(source, "!= 0") {
		t.Errorf("boolean condition still compared to int (== 0 / != 0):\n%s", source)
	}
	// (2) pick's guard is a structured if with the positive boolean condition.
	if !strings.Contains(source, "if (this.flag(var1)) {") {
		t.Errorf("expected structured `if (this.flag(var1)) {`:\n%s", source)
	}
	// pick's if must not leak as a raw unstructured if-goto.
	if strings.Contains(source, "/* unknown: if") {
		t.Errorf("if-goto not structured (leaked as /* unknown */):\n%s", source)
	}
}
