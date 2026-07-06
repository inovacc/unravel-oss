/*
Copyright (c) 2026 Security Research
*/
package jsdeob

import "testing"

func TestLint_Balanced(t *testing.T) {
	src := `const x = (1 + 2); function f() { return [1, 2, 3]; } // ok`
	if err := Lint(src); err != nil {
		t.Errorf("balanced: unexpected error: %v", err)
	}
}

func TestLint_UnbalancedBrace(t *testing.T) {
	src := `function f() { return 1; `
	if err := Lint(src); err == nil {
		t.Error("expected error for unmatched brace")
	}
}

func TestLint_UnterminatedString(t *testing.T) {
	src := `const s = "hello`
	if err := Lint(src); err == nil {
		t.Error("expected error for unterminated string")
	}
}

func TestLint_TemplateLiteralWithBraces(t *testing.T) {
	// Template literal containing braces inside is treated as a string
	// (lite parser); the lint should still pass because the template
	// literal is closed and outer JS is balanced.
	src := "const s = `value=${42}`; const t = 1;"
	if err := Lint(src); err != nil {
		t.Errorf("template literal: unexpected error: %v", err)
	}
}

func TestLint_LineComment(t *testing.T) {
	src := "// const x = ( unbalanced\nconst y = 1;"
	if err := Lint(src); err != nil {
		t.Errorf("line comment: unexpected error: %v", err)
	}
}

func TestLint_BlockComment(t *testing.T) {
	src := "/* const x = ( unbalanced */\nconst y = 1;"
	if err := Lint(src); err != nil {
		t.Errorf("block comment: unexpected error: %v", err)
	}
}
