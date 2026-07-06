/*
Copyright (c) 2026 Security Research
*/
package jsdeob

import "fmt"

// Lint performs a lightweight syntactic sanity check on a JavaScript source
// string. It is intentionally conservative: it verifies that brackets,
// braces, and parentheses are balanced and that string literals are closed.
// It does NOT replace a real JS parser — its purpose is to catch obviously
// broken JS produced by template-based generators.
//
// Used by pkg/frida/autogen to gate generated scripts before writing to
// disk (FRIDA-GEN-01 acceptance: every generated *.js must lint clean).
func Lint(src string) error {
	var parens, braces, brackets int
	var inString bool
	var stringQuote byte
	var inLineComment, inBlockComment bool
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inLineComment {
			if c == '\n' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlockComment = false
				i++
			}
			continue
		}
		if inString {
			if c == '\\' && i+1 < len(src) {
				i++
				continue
			}
			if c == stringQuote {
				inString = false
			}
			continue
		}
		switch c {
		case '/':
			if i+1 < len(src) {
				if src[i+1] == '/' {
					inLineComment = true
					i++
					continue
				}
				if src[i+1] == '*' {
					inBlockComment = true
					i++
					continue
				}
			}
		case '"', '\'', '`':
			inString = true
			stringQuote = c
		case '(':
			parens++
		case ')':
			parens--
			if parens < 0 {
				return fmt.Errorf("jsdeob.Lint: unmatched ')' at offset %d", i)
			}
		case '{':
			braces++
		case '}':
			braces--
			if braces < 0 {
				return fmt.Errorf("jsdeob.Lint: unmatched '}' at offset %d", i)
			}
		case '[':
			brackets++
		case ']':
			brackets--
			if brackets < 0 {
				return fmt.Errorf("jsdeob.Lint: unmatched ']' at offset %d", i)
			}
		}
	}
	if inString {
		return fmt.Errorf("jsdeob.Lint: unterminated string literal (quote=%q)", stringQuote)
	}
	if inBlockComment {
		return fmt.Errorf("jsdeob.Lint: unterminated block comment")
	}
	if parens != 0 {
		return fmt.Errorf("jsdeob.Lint: unbalanced parens (delta=%d)", parens)
	}
	if braces != 0 {
		return fmt.Errorf("jsdeob.Lint: unbalanced braces (delta=%d)", braces)
	}
	if brackets != 0 {
		return fmt.Errorf("jsdeob.Lint: unbalanced brackets (delta=%d)", brackets)
	}
	return nil
}
