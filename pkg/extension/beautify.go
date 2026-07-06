/*
Copyright © 2026 Security Research
*/
package extension

import (
	"regexp"
	"strings"
)

// beautifyJS formats minified JavaScript code for readability.
// Ported from js_deobfuscator/pkg/deobfuscator/beautify.go.
func beautifyJS(code string) string {
	var result strings.Builder

	indent := 0
	inString := false
	stringChar := byte(0)
	escaped := false

	for i := 0; i < len(code); i++ {
		c := code[i]

		if !escaped && (c == '"' || c == '\'' || c == '`') {
			if !inString {
				inString = true
				stringChar = c
			} else if c == stringChar {
				inString = false
			}
		}

		escaped = !escaped && c == '\\'

		if inString {
			result.WriteByte(c)
			continue
		}

		switch c {
		case '{':
			result.WriteByte(c)

			indent++

			result.WriteByte('\n')
			bWriteIndent(&result, indent)
		case '}':
			indent--
			if indent < 0 {
				indent = 0
			}

			result.WriteByte('\n')
			bWriteIndent(&result, indent)
			result.WriteByte(c)
		case ';':
			result.WriteByte(c)

			if !bIsInsideForLoop(code, i) {
				result.WriteByte('\n')
				bWriteIndent(&result, indent)
			}
		case ',':
			result.WriteByte(c)

			if i+1 < len(code) && code[i+1] != ' ' && code[i+1] != '\n' {
				result.WriteByte(' ')
			}
		default:
			result.WriteByte(c)
		}
	}

	output := result.String()

	multiNewline := regexp.MustCompile(`\n{3,}`)
	output = multiNewline.ReplaceAllString(output, "\n\n")

	lines := strings.Split(output, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}

	return strings.Join(lines, "\n")
}

func bWriteIndent(b *strings.Builder, level int) {
	for range level {
		b.WriteString("  ")
	}
}

func bIsInsideForLoop(code string, pos int) bool {
	start := max(pos-50, 0)

	segment := code[start:pos]

	forIdx := strings.LastIndex(segment, "for")
	if forIdx == -1 {
		return false
	}

	parenDepth := 0

	for i := forIdx; i < len(segment); i++ {
		switch segment[i] {
		case '(':
			parenDepth++
		case ')':
			parenDepth--
		}
	}

	return parenDepth > 0
}
