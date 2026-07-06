/*
Copyright (c) 2026 Security Research
*/

// Package chunk implements a language-aware brace-counter state machine
// that splits decompiled / minified source code into AI-beautifiable
// units. It is the shared core consumed by C# (pkg/dotnet/decompile),
// Java (pkg/java/beautify), and JavaScript (pkg/jsdeob) reconstruction
// tracks.
//
// The package is stdlib-only by design — it MUST NOT import any
// language-specific package under pkg/dotnet, pkg/java, or pkg/jsdeob —
// otherwise consumers would create import cycles when they consume this
// package (D-05 / D-21).
package chunk

import (
	"fmt"
	"regexp"
	"strings"
)

// Lang selects per-language tokenization rules.
type Lang int

const (
	// LangCSharp enables C# verbatim (`@"..."`), interpolated (`$"..."`),
	// and char-literal modes plus C# top-level type detection.
	LangCSharp Lang = iota
	// LangJava enables Java text-block (`"""..."""`), char-literal modes
	// and Java top-level type detection (class/interface/enum/record/@interface).
	LangJava
	// LangJavaScript enables template-literal (`` `...` ``) and regex-literal
	// (`/.../`) modes plus top-level function/class/const-fn detection.
	LangJavaScript
)

// Languages returns the supported Lang values, primarily for diagnostics.
func Languages() []Lang { return []Lang{LangCSharp, LangJava, LangJavaScript} }

// Mode is the state-machine mode driving brace counting. Names are kept
// stable for grep-based acceptance criteria.
//
// Code | LineComment | BlockComment | Str | CharLit | VerbatimStr |
// InterpolatedStr | TemplateStr | RegexLit
type Mode int

const (
	Code Mode = iota
	LineComment
	BlockComment
	Str
	CharLit
	VerbatimStr
	InterpolatedStr
	TemplateStr
	RegexLit
)

// DefaultMaxBytes is the per-chunk hard cap before method-group fallback
// splitting kicks in.
const DefaultMaxBytes = 50 * 1024

// scanLimit bounds how far the state machine will scan looking for the
// opening `{` of a type declaration before bailing out.
const scanLimit = 1 << 20 // 1 MB

// maxDepth caps brace nesting depth tolerated by the state machine.
const maxDepth = 1024

// Unit is one chunk fed to the AI beautifier. Named Unit (not Chunk) to
// avoid clashing with the package-level Chunk function. Consumers may
// alias as `type Chunk = chunkpkg.Unit` for readability.
type Unit struct {
	Lang          Lang   `json:"lang"`
	Namespace     string `json:"namespace"`
	Type          string `json:"type"`
	StartByte     int    `json:"start_byte"`
	EndByte       int    `json:"end_byte"`
	Body          string `json:"body"`
	SubChunkOf    string `json:"sub_chunk_of,omitempty"`
	SubChunkIndex int    `json:"sub_chunk_index,omitempty"`
	ParseErr      string `json:"parse_err,omitempty"`
}

// Options configures Chunk.
type Options struct {
	MaxBytes int
}

// per-language regex tables.
var (
	reCSharpType = regexp.MustCompile(
		`^\s*(?:(?:public|internal|private|protected|sealed|abstract|static|partial|unsafe|ref|readonly)\s+)+(class|struct|interface|record|enum)\s+([A-Za-z_]\w*)`,
	)
	reCSharpNs = regexp.MustCompile(
		`^\s*namespace\s+([\w.]+)\s*(\{|;)`,
	)
	reCSharpMethod = regexp.MustCompile(
		`^\s*(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal|static|virtual|override|abstract|sealed|async|extern|unsafe|new|\s)+\s*\S+\s+\w+\s*\([^)]*\)\s*(?:where[^{]*)?\{?\s*$`,
	)

	reJavaType = regexp.MustCompile(
		`^\s*(?:(?:@[A-Za-z_]\w*(?:\([^)]*\))?\s+)*)(?:(?:public|private|protected|abstract|final|static|sealed|non-sealed|strictfp)\s+)*(class|interface|enum|record|@interface)\s+([A-Za-z_]\w*)`,
	)
	reJavaPkg = regexp.MustCompile(
		`^\s*package\s+([\w.]+)\s*;`,
	)
	reJavaMethod = regexp.MustCompile(
		`^\s*(?:@[A-Za-z_]\w*(?:\([^)]*\))?\s*)*(?:public|private|protected|static|final|abstract|synchronized|native|default|\s)+\s*\S+\s+\w+\s*\([^)]*\)\s*(?:throws[^{]*)?\{?\s*$`,
	)

	reJSTopLevel = regexp.MustCompile(
		`^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?(function\s*\*?|class)\s+([A-Za-z_$][\w$]*)`,
	)
	reJSConstFn = regexp.MustCompile(
		`^\s*(?:export\s+(?:default\s+)?)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*\*?|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)`,
	)
	reJSMethod = regexp.MustCompile(
		`^\s*(?:async\s+|static\s+|get\s+|set\s+|\s)*[A-Za-z_$#][\w$]*\s*\([^)]*\)\s*\{?\s*$`,
	)
)

// Chunk scans src under the rules of lang and emits one Chunk per
// top-level declaration. Brace counting is mode-aware (skips braces
// inside strings, comments, char literals, template literals, regex
// literals). Per D-10, units exceeding opts.MaxBytes are split via
// method/function-group fallback.
func Chunk(src []byte, lang Lang, opts Options) (chunks []Unit, err error) {
	defer func() {
		if r := recover(); r != nil {
			chunks = []Unit{{
				Lang:     lang,
				Type:     "<unparseable>",
				Body:     string(src),
				ParseErr: fmt.Sprintf("panic in Chunk: %v", r),
			}}
			err = fmt.Errorf("chunk panic: %v", r)
		}
	}()

	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	out := make([]Unit, 0, 8)

	type nsEntry struct {
		name    string
		openIdx int // -1 for file-scoped (C#) or sentinel (Java)
	}
	var nsStack []nsEntry
	currentNS := func() string {
		if len(nsStack) == 0 {
			return ""
		}
		parts := make([]string, 0, len(nsStack))
		for _, e := range nsStack {
			parts = append(parts, e.name)
		}
		return strings.Join(parts, ".")
	}

	n := len(src)
	i := 0
	mode := Code
	scanned := 0
	statementStart := true
	// JS-specific: track last non-whitespace token kind for division-vs-regex.
	jsLastTokKind := jsTokOther

	for i < n {
		scanned++
		if scanned > scanLimit*4 {
			break
		}

		if mode == Code && statementStart {
			// Fast path: top-level/namespace decls always begin with a letter,
			// underscore, `@` (Java annotation), `[` (C# attribute), or
			// whitespace. Skip the regex when the current byte is clearly
			// not a candidate — this keeps pathological input (e.g. 1 MB
			// of `{` bytes) from quadratic regex scans.
			c0 := src[i]
			if !isStmtStartCandidate(c0) {
				goto advanceByte
			}
			// Language-specific namespace/package detection.
			switch lang {
			case LangCSharp:
				if m := reCSharpNs.FindSubmatchIndex(src[i:]); m != nil && m[0] == 0 {
					nsName := string(src[i+m[2] : i+m[3]])
					punct := src[i+m[4]]
					if punct == ';' {
						nsStack = append(nsStack, nsEntry{name: nsName, openIdx: -1})
						i += m[1]
						statementStart = true
						continue
					}
					openIdx := i + m[4]
					nsStack = append(nsStack, nsEntry{name: nsName, openIdx: openIdx})
					i = openIdx + 1
					statementStart = true
					continue
				}
			case LangJava:
				if m := reJavaPkg.FindSubmatchIndex(src[i:]); m != nil && m[0] == 0 {
					nsName := string(src[i+m[2] : i+m[3]])
					nsStack = append(nsStack, nsEntry{name: nsName, openIdx: -1})
					i += m[1]
					statementStart = true
					continue
				}
			case LangJavaScript:
				// JS has no analogous package decl (modules are file-scoped).
			}

			// Language-specific top-level type / function detection.
			if typeName, ok := matchTopLevel(src, i, lang); ok {
				chunkStart := extendUpwardForAnnotations(src, i, lang)
				openIdx, ok := findOpenBraceFromCode(src, i, lang)
				if !ok {
					end := i
					for end < n && src[end] != ';' && src[end] != '\n' {
						end++
					}
					if end < n {
						end++
					}
					out = append(out, Unit{
						Lang:      lang,
						Namespace: currentNS(),
						Type:      typeName,
						StartByte: chunkStart,
						EndByte:   end,
						Body:      string(src[chunkStart:end]),
					})
					i = end
					statementStart = true
					continue
				}

				closeIdx, perr := matchBalancedBrace(src, openIdx, lang)
				if perr != nil {
					out = append(out, Unit{
						Lang:      lang,
						Namespace: currentNS(),
						Type:      typeName,
						StartByte: chunkStart,
						EndByte:   n,
						Body:      string(src[chunkStart:n]),
						ParseErr:  perr.Error(),
					})
					i = n
					continue
				}

				chunkEnd := closeIdx + 1
				ch := Unit{
					Lang:      lang,
					Namespace: currentNS(),
					Type:      typeName,
					StartByte: chunkStart,
					EndByte:   chunkEnd,
					Body:      string(src[chunkStart:chunkEnd]),
				}
				if len(ch.Body) > maxBytes {
					out = append(out, splitMethodGroups(ch, lang, maxBytes)...)
				} else {
					out = append(out, ch)
				}
				i = chunkEnd
				statementStart = true
				continue
			}
		}

	advanceByte:
		// Advance one byte through the state machine.
		c := src[i]
		switch mode {
		case Code:
			advanced, newMode, newStmtStart, newTokKind := stepCode(src, i, lang, jsLastTokKind)
			if newMode != Code {
				mode = newMode
			}
			statementStart = newStmtStart
			jsLastTokKind = newTokKind
			// nsStack pop on `}` for C# block-namespaces and any close-brace.
			if c == '}' && len(nsStack) > 0 {
				top := nsStack[len(nsStack)-1]
				if top.openIdx >= 0 && top.openIdx < i {
					nsStack = nsStack[:len(nsStack)-1]
				}
			}
			i += advanced
			continue
		case LineComment:
			if c == '\n' {
				mode = Code
				statementStart = true
			}
		case BlockComment:
			if c == '*' && i+1 < n && src[i+1] == '/' {
				mode = Code
				i += 2
				continue
			}
		case Str:
			if c == '\\' && i+1 < n {
				i += 2
				continue
			}
			if c == '"' {
				mode = Code
			}
		case VerbatimStr:
			if c == '"' {
				if i+1 < n && src[i+1] == '"' {
					i += 2
					continue
				}
				mode = Code
			}
		case InterpolatedStr:
			if c == '\\' && i+1 < n {
				i += 2
				continue
			}
			if c == '"' {
				mode = Code
			}
		case CharLit:
			if c == '\\' && i+1 < n {
				i += 2
				continue
			}
			if c == '\'' {
				mode = Code
			}
		case TemplateStr:
			// `}` and `{` are only meaningful inside `${...}` interpolation;
			// otherwise braces inside backticks are literal text.
			if c == '\\' && i+1 < n {
				i += 2
				continue
			}
			if c == '`' {
				mode = Code
			}
			// Note: we don't track ${...} interpolation depth precisely here
			// because the contained expression is balanced and exits on the
			// matching `}` — for chunking purposes, we just need to ensure
			// the outer brace counter doesn't mistake template text for code.
		case RegexLit:
			if c == '\\' && i+1 < n {
				i += 2
				continue
			}
			if c == '/' {
				// Skip flags.
				j := i + 1
				for j < n && isIdentByte(src[j]) {
					j++
				}
				mode = Code
				i = j
				continue
			}
		}
		i++
	}

	if len(out) == 0 {
		out = append(out, Unit{
			Lang:      lang,
			Namespace: currentNS(),
			Type:      "<no-top-level-unit>",
			StartByte: 0,
			EndByte:   n,
			Body:      string(src),
		})
	}

	return out, nil
}

// jsTokKind tracks the kind of the last non-whitespace token in
// JavaScript code, to disambiguate `/` as division vs. regex literal.
type jsTokKind int

const (
	jsTokOther    jsTokKind = iota // start of file, after `(`, `,`, `=`, `;`, etc. → `/` is regex
	jsTokIdentNum                  // identifier, number, `)`, `]` → `/` is division
)

// stepCode advances one byte in Code mode and returns (bytesAdvanced,
// newMode, newStatementStart, newJSTokKind).
func stepCode(src []byte, i int, lang Lang, lastTok jsTokKind) (int, Mode, bool, jsTokKind) {
	n := len(src)
	c := src[i]
	switch c {
	case '/':
		if i+1 < n {
			if src[i+1] == '/' {
				return 2, LineComment, false, lastTok
			}
			if src[i+1] == '*' {
				return 2, BlockComment, false, lastTok
			}
		}
		// JavaScript regex disambiguation.
		if lang == LangJavaScript && lastTok == jsTokOther {
			return 1, RegexLit, false, jsTokOther
		}
		return 1, Code, false, jsTokIdentNum
	case '"':
		// Java text block `"""..."""` is treated as a plain string scope
		// for chunking purposes. We enter Str here; the closing `"` handler
		// only exits on a single `"` that is not escaped, so triple-quote
		// content with embedded `}` will not break brace counting because
		// braces inside Str do not count.
		_ = lang
		return 1, Str, false, jsTokIdentNum
	case '\'':
		// In JS, single-quote strings are also Str. In C#/Java, char literal.
		if lang == LangJavaScript {
			return 1, Str, false, jsTokIdentNum
		}
		return 1, CharLit, false, jsTokIdentNum
	case '`':
		if lang == LangJavaScript {
			return 1, TemplateStr, false, jsTokIdentNum
		}
		return 1, Code, false, jsTokIdentNum
	case '@':
		if lang == LangCSharp && i+1 < n && src[i+1] == '"' {
			return 2, VerbatimStr, false, jsTokIdentNum
		}
		return 1, Code, false, jsTokIdentNum
	case '$':
		if lang == LangCSharp && i+1 < n && src[i+1] == '"' {
			return 2, InterpolatedStr, false, jsTokIdentNum
		}
		return 1, Code, false, jsTokIdentNum
	}

	switch c {
	case '{', ';', '\n':
		return 1, Code, true, jsTokOther
	case '}':
		return 1, Code, true, jsTokIdentNum // `)` `]` `}` are "ident-ish" for JS regex heuristic
	case ' ', '\t', '\r':
		return 1, Code, false, lastTok
	}

	// Default: advance, statementStart=false. Update JS token kind: any
	// alnum/`)`/`]` makes next `/` a division.
	if isIdentByte(c) || c == ')' || c == ']' {
		return 1, Code, false, jsTokIdentNum
	}
	return 1, Code, false, jsTokOther
}

// isStmtStartCandidate reports whether byte c could begin a top-level
// declaration line (letter, `_`, `@`, `[`, or whitespace). Used as a
// cheap filter before invoking per-language regex.
func isStmtStartCandidate(c byte) bool {
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
		return true
	}
	switch c {
	case '_', '@', '[', ' ', '\t', '\r', '\n', 'e', 'i', 'l', 'v', 'c', 'f', 'p':
		return true
	}
	return false
}

func isIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '$'
}

// matchTopLevel returns (typeName, true) if a top-level type/function
// declaration starts at src[pos] under lang, else ("", false).
func matchTopLevel(src []byte, pos int, lang Lang) (string, bool) {
	switch lang {
	case LangCSharp:
		if m := reCSharpType.FindSubmatchIndex(src[pos:]); m != nil && m[0] == 0 {
			return string(src[pos+m[4] : pos+m[5]]), true
		}
	case LangJava:
		if m := reJavaType.FindSubmatchIndex(src[pos:]); m != nil && m[0] == 0 {
			return string(src[pos+m[4] : pos+m[5]]), true
		}
	case LangJavaScript:
		if m := reJSTopLevel.FindSubmatchIndex(src[pos:]); m != nil && m[0] == 0 {
			return string(src[pos+m[4] : pos+m[5]]), true
		}
		if m := reJSConstFn.FindSubmatchIndex(src[pos:]); m != nil && m[0] == 0 {
			return string(src[pos+m[2] : pos+m[3]]), true
		}
	}
	return "", false
}

// extendUpwardForAnnotations walks backward from start across consecutive
// lines that begin with `[` (C# attributes) or `@` (Java annotations).
// JavaScript has neither — returns start unchanged.
func extendUpwardForAnnotations(src []byte, start int, lang Lang) int {
	if lang == LangJavaScript || start <= 0 {
		return start
	}
	pos := start
	for pos > 0 {
		prevEnd := pos - 1
		if prevEnd < 0 || src[prevEnd] != '\n' {
			return pos
		}
		prevStart := prevEnd
		for prevStart > 0 && src[prevStart-1] != '\n' {
			prevStart--
		}
		prevLine := strings.TrimLeft(string(src[prevStart:prevEnd]), " \t")
		switch lang {
		case LangCSharp:
			if strings.HasPrefix(prevLine, "[") {
				pos = prevStart
				continue
			}
		case LangJava:
			if strings.HasPrefix(prevLine, "@") {
				pos = prevStart
				continue
			}
		}
		return pos
	}
	return pos
}

// stepLiteral advances one position while scanning inside a non-Code lexical
// mode (a comment or string/char/template/regex literal). c is src[i]; bound is
// the exclusive end of the scan. It returns the updated mode and the next index,
// mirroring the per-mode transitions shared by findOpenBraceFromCode and
// matchBalancedBrace.
func stepLiteral(src []byte, i, bound int, mode Mode) (Mode, int) {
	c := src[i]
	switch mode {
	case LineComment:
		if c == '\n' {
			mode = Code
		}
	case BlockComment:
		if c == '*' && i+1 < bound && src[i+1] == '/' {
			return Code, i + 2
		}
	case Str:
		if c == '\\' && i+1 < bound {
			return mode, i + 2
		}
		if c == '"' {
			mode = Code
		}
	case VerbatimStr:
		if c == '"' {
			if i+1 < bound && src[i+1] == '"' {
				return mode, i + 2
			}
			mode = Code
		}
	case InterpolatedStr:
		if c == '\\' && i+1 < bound {
			return mode, i + 2
		}
		if c == '"' {
			mode = Code
		}
	case CharLit:
		if c == '\\' && i+1 < bound {
			return mode, i + 2
		}
		if c == '\'' {
			mode = Code
		}
	case TemplateStr:
		if c == '\\' && i+1 < bound {
			return mode, i + 2
		}
		if c == '`' {
			mode = Code
		}
	case RegexLit:
		if c == '\\' && i+1 < bound {
			return mode, i + 2
		}
		if c == '/' {
			j := i + 1
			for j < bound && isIdentByte(src[j]) {
				j++
			}
			return Code, j
		}
	}
	return mode, i + 1
}

// findOpenBraceFromCode scans forward from pos looking for the first
// opening `{` that occurs in Code mode under lang. Bounded by scanLimit.
func findOpenBraceFromCode(src []byte, pos int, lang Lang) (int, bool) {
	mode := Code
	end := min(pos+scanLimit, len(src))
	lastTok := jsTokOther
	i := pos
	for i < end {
		c := src[i]
		if mode == Code {
			if c == '{' {
				return i, true
			}
			if c == ';' {
				return -1, false
			}
			adv, nm, _, ntk := stepCode(src, i, lang, lastTok)
			mode = nm
			lastTok = ntk
			i += adv
			continue
		}
		mode, i = stepLiteral(src, i, end, mode)
	}
	return -1, false
}

// matchBalancedBrace assumes src[openIdx] == '{' and walks forward,
// brace-counting in Code mode. Iterative, bounded.
func matchBalancedBrace(src []byte, openIdx int, lang Lang) (int, error) {
	if openIdx < 0 || openIdx >= len(src) || src[openIdx] != '{' {
		return -1, fmt.Errorf("matchBalancedBrace: openIdx %d not '{'", openIdx)
	}
	depth := 1
	mode := Code
	n := len(src)
	lastTok := jsTokOther
	i := openIdx + 1
	for i < n {
		c := src[i]
		if mode == Code {
			if c == '{' {
				depth++
				if depth > maxDepth {
					return -1, fmt.Errorf("brace depth exceeded %d", maxDepth)
				}
				i++
				continue
			}
			if c == '}' {
				depth--
				if depth == 0 {
					return i, nil
				}
				i++
				continue
			}
			adv, nm, _, ntk := stepCode(src, i, lang, lastTok)
			mode = nm
			lastTok = ntk
			i += adv
			continue
		}
		mode, i = stepLiteral(src, i, n, mode)
	}
	return -1, fmt.Errorf("unmatched opening brace at %d", openIdx)
}

// methodRegexFor returns the per-language method/function declaration
// regex used by splitMethodGroups.
func methodRegexFor(lang Lang) *regexp.Regexp {
	switch lang {
	case LangCSharp:
		return reCSharpMethod
	case LangJava:
		return reJavaMethod
	case LangJavaScript:
		return reJSMethod
	}
	return reCSharpMethod
}

// splitMethodGroups splits an oversized type/function chunk into
// method/function-group bundles ≤ maxBytes. Concatenation of resulting
// bodies = original body.
func splitMethodGroups(ch Unit, lang Lang, maxBytes int) []Unit {
	body := ch.Body
	if len(body) <= maxBytes {
		return []Unit{ch}
	}

	re := methodRegexFor(lang)

	starts := []int{0}
	mode := Code
	lastTok := jsTokOther
	for i := 0; i < len(body); i++ {
		c := body[i]
		if mode == Code {
			if c == '\n' {
				next := i + 1
				lineEnd := next
				for lineEnd < len(body) && body[lineEnd] != '\n' {
					lineEnd++
				}
				if next < len(body) {
					line := body[next:lineEnd]
					if re.MatchString(line) {
						starts = append(starts, next)
					}
				}
				lastTok = jsTokOther
				continue
			}
			adv, nm, _, ntk := stepCode([]byte(body), i, lang, lastTok)
			mode = nm
			lastTok = ntk
			i += adv - 1
			continue
		}
		switch mode {
		case LineComment:
			if c == '\n' {
				mode = Code
			}
		case BlockComment:
			if c == '*' && i+1 < len(body) && body[i+1] == '/' {
				mode = Code
				i++
			}
		case Str:
			if c == '\\' && i+1 < len(body) {
				i++
				continue
			}
			if c == '"' {
				mode = Code
			}
		case VerbatimStr:
			if c == '"' {
				if i+1 < len(body) && body[i+1] == '"' {
					i++
					continue
				}
				mode = Code
			}
		case InterpolatedStr:
			if c == '\\' && i+1 < len(body) {
				i++
				continue
			}
			if c == '"' {
				mode = Code
			}
		case CharLit:
			if c == '\\' && i+1 < len(body) {
				i++
				continue
			}
			if c == '\'' {
				mode = Code
			}
		case TemplateStr:
			if c == '\\' && i+1 < len(body) {
				i++
				continue
			}
			if c == '`' {
				mode = Code
			}
		case RegexLit:
			if c == '\\' && i+1 < len(body) {
				i++
				continue
			}
			if c == '/' {
				j := i + 1
				for j < len(body) && isIdentByte(body[j]) {
					j++
				}
				mode = Code
				i = j - 1
			}
		}
	}
	starts = append(starts, len(body))

	out := []Unit{}
	idx := 0
	curStart := starts[0]

	emit := func(end int) {
		if end <= curStart {
			return
		}
		out = append(out, Unit{
			Lang:          lang,
			Namespace:     ch.Namespace,
			Type:          ch.Type,
			StartByte:     ch.StartByte + curStart,
			EndByte:       ch.StartByte + end,
			Body:          body[curStart:end],
			SubChunkOf:    ch.Type,
			SubChunkIndex: idx,
		})
		idx++
		curStart = end
	}

	for k := 1; k < len(starts); k++ {
		if (starts[k] - curStart) <= maxBytes {
			continue
		}
		if starts[k-1] > curStart {
			emit(starts[k-1])
		} else {
			emit(starts[k])
		}
	}
	if curStart < len(body) {
		emit(len(body))
	}
	if len(out) == 0 {
		return []Unit{ch}
	}
	return out
}
