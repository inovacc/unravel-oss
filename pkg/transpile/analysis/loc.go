package analysis

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// LOCStats holds lines-of-code metrics for a file or aggregate.
type LOCStats struct {
	Lines    int `json:"lines"`
	Code     int `json:"code"`
	Comments int `json:"comments"`
	Blanks   int `json:"blanks"`
}

// Add accumulates another LOCStats into this one.
func (s *LOCStats) Add(other LOCStats) {
	s.Lines += other.Lines
	s.Code += other.Code
	s.Comments += other.Comments
	s.Blanks += other.Blanks
}

// CountFile counts LOC metrics for a single C++ source file.
// Uses a state machine that handles block comments (with nesting),
// line comments, and string/char literals to avoid false positives.
func CountFile(path string) (LOCStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return LOCStats{}, err
	}

	defer func() { _ = f.Close() }()

	var stats LOCStats

	inBlockComment := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		stats.Lines++

		trimmed := trimLeftSpace(line)

		if len(trimmed) == 0 {
			stats.Blanks++
			continue
		}

		classified := classifyLine(trimmed, inBlockComment)
		inBlockComment = classified.endsInBlock

		switch classified.kind {
		case lineKindCode:
			stats.Code++
		case lineKindComment:
			stats.Comments++
		case lineKindMixed:
			stats.Code++
		}
	}

	if err := scanner.Err(); err != nil {
		return LOCStats{}, err
	}

	return stats, nil
}

// lineKind represents what a line contains.
type lineKind int

const (
	lineKindCode lineKind = iota
	lineKindComment
	lineKindMixed // has both code and comment
)

type lineClass struct {
	kind        lineKind
	endsInBlock bool
}

// classifyLine determines whether a trimmed, non-empty line is code, comment, or mixed.
// It tracks block comment state across lines.
func classifyLine(trimmed string, inBlockComment bool) lineClass {
	hasCode := false
	hasComment := false
	inString := false
	inChar := false
	i := 0
	n := len(trimmed)

	for i < n {
		ch := trimmed[i]

		if inBlockComment {
			hasComment = true

			if ch == '*' && i+1 < n && trimmed[i+1] == '/' {
				inBlockComment = false
				i += 2

				continue
			}

			i++

			continue
		}

		// Inside string literal
		if inString {
			if ch == '\\' && i+1 < n {
				i += 2 // skip escaped char
				continue
			}

			if ch == '"' {
				inString = false
			}

			i++

			continue
		}

		// Inside char literal
		if inChar {
			if ch == '\\' && i+1 < n {
				i += 2
				continue
			}

			if ch == '\'' {
				inChar = false
			}

			i++

			continue
		}

		// Check for line comment
		if ch == '/' && i+1 < n && trimmed[i+1] == '/' {
			hasComment = true
			break // rest of line is comment
		}

		// Check for block comment start
		if ch == '/' && i+1 < n && trimmed[i+1] == '*' {
			inBlockComment = true
			hasComment = true
			i += 2

			continue
		}

		// String literal start
		if ch == '"' {
			inString = true
			hasCode = true
			i++

			continue
		}

		// Char literal start
		if ch == '\'' {
			inChar = true
			hasCode = true
			i++

			continue
		}

		// Any other non-whitespace is code
		if ch != ' ' && ch != '\t' {
			hasCode = true
		}

		i++
	}

	result := lineClass{endsInBlock: inBlockComment}

	switch {
	case hasCode && hasComment:
		result.kind = lineKindMixed
	case hasComment:
		result.kind = lineKindComment
	default:
		result.kind = lineKindCode
	}

	return result
}

// trimLeftSpace trims leading whitespace bytes (space, tab).
func trimLeftSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}

	return s[i:]
}

// CountPythonFile counts LOC metrics for a single Python source file.
// Handles # line comments, triple-quoted strings (""" and ”'), and
// regular string literals with escape handling.
func CountPythonFile(path string) (LOCStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return LOCStats{}, err
	}

	defer func() { _ = f.Close() }()

	var stats LOCStats

	inTripleQuote := byte(0) // 0 = not in triple quote, '"' or '\'' = in triple quote

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		stats.Lines++

		trimmed := trimLeftSpace(line)

		if len(trimmed) == 0 {
			stats.Blanks++
			continue
		}

		classified := classifyPythonLine(trimmed, inTripleQuote)
		inTripleQuote = classified.tripleQuoteChar

		switch classified.kind {
		case lineKindCode:
			stats.Code++
		case lineKindComment:
			stats.Comments++
		case lineKindMixed:
			stats.Code++
		}
	}

	if err := scanner.Err(); err != nil {
		return LOCStats{}, err
	}

	return stats, nil
}

type pyLineClass struct {
	kind            lineKind
	tripleQuoteChar byte // 0 = not in triple quote, '"' or '\'' = in triple quote
}

// classifyPythonLine determines whether a trimmed, non-empty Python line
// is code, comment, or mixed. It tracks triple-quoted string state across lines.
func classifyPythonLine(trimmed string, inTripleQuote byte) pyLineClass {
	hasCode := false
	hasComment := false
	i := 0
	n := len(trimmed)

	for i < n {
		ch := trimmed[i]

		// Inside a triple-quoted string
		if inTripleQuote != 0 {
			hasCode = true

			if ch == inTripleQuote && i+2 < n && trimmed[i+1] == inTripleQuote && trimmed[i+2] == inTripleQuote {
				inTripleQuote = 0
				i += 3

				continue
			}

			if ch == '\\' && i+1 < n {
				i += 2
				continue
			}

			i++

			continue
		}

		// Check for # line comment
		if ch == '#' {
			hasComment = true
			break // rest of line is comment
		}

		// Check for triple-quoted string start
		if (ch == '"' || ch == '\'') && i+2 < n && trimmed[i+1] == ch && trimmed[i+2] == ch {
			// Standalone triple-quote on a line with no other code is treated as comment
			if !hasCode {
				// Check if the triple quote also closes on this line
				closeIdx := strings.Index(trimmed[i+3:], string([]byte{ch, ch, ch}))
				if closeIdx >= 0 {
					// Opens and closes on same line — treat as docstring/comment if no code before
					hasComment = true
					i = i + 3 + closeIdx + 3

					continue
				}
				// Multi-line triple quote starting — treat as comment
				hasComment = true
				inTripleQuote = ch

				break
			}
			// Code before triple quote — it's a string value
			inTripleQuote = ch
			i += 3

			continue
		}

		// Regular string literal
		if ch == '"' || ch == '\'' {
			hasCode = true
			quote := ch

			i++
			for i < n {
				if trimmed[i] == '\\' && i+1 < n {
					i += 2
					continue
				}

				if trimmed[i] == quote {
					i++
					break
				}

				i++
			}

			continue
		}

		// Any other non-whitespace is code
		if ch != ' ' && ch != '\t' {
			hasCode = true
		}

		i++
	}

	result := pyLineClass{tripleQuoteChar: inTripleQuote}

	switch {
	case hasCode && hasComment:
		result.kind = lineKindMixed
	case hasComment:
		result.kind = lineKindComment
	default:
		result.kind = lineKindCode
	}

	return result
}

// CountFileAuto dispatches LOC counting by file extension.
func CountFileAuto(path string) (LOCStats, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py":
		return CountPythonFile(path)
	case ".java":
		// Java uses the same // and /* */ comment syntax as C/C++
		return CountFile(path)
	default:
		return CountFile(path)
	}
}
