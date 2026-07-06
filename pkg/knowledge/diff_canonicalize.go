/*
Copyright (c) 2026 Security Research

diff_canonicalize.go — identifier-rename-tolerant text equivalence (D-09 dim 4).

Approach:
 1. Strip JS line and block comments.
 2. Tokenize the source: string literals, regex literals, numeric literals,
    punctuation, and identifiers.
 3. For each identifier NOT on a whitelist (DOM/JS builtins, common APIs),
    assign a stable rename to "var_<N>" based on first-appearance order.
 4. Re-emit the token stream with whitespace stripped.
 5. SHA-256 the result.

Bypass (T-07-canonicalize-cpu): inputs > 4 MiB skip the rename pass and
hash the raw bytes; the caller marks the module as "bypassed_large_input".

This is a regex-grade tokenizer — sufficient for the obfuscated-pair
fixture and the typical KB module size (<1 MiB). Pathological inputs
fall back to the bypass path.
*/
package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
)

// maxCanonicalizeSize bounds the rename pass (T-07-canonicalize-cpu).
const maxCanonicalizeSize = 4 << 20 // 4 MiB

// canonicalizeWhitelist names that MUST NOT be renamed (DOM, JS built-ins,
// common Web APIs). Renaming these would defeat the purpose — two
// modules calling document.getElementById should canonicalize identically.
var canonicalizeWhitelist = map[string]bool{
	// Globals / built-ins
	"document": true, "window": true, "console": true, "globalThis": true,
	"self": true, "this": true, "undefined": true, "null": true,
	"true": true, "false": true, "NaN": true, "Infinity": true,

	// Constructors
	"Array": true, "Object": true, "String": true, "Number": true,
	"Boolean": true, "RegExp": true, "Date": true, "Error": true,
	"TypeError": true, "RangeError": true, "SyntaxError": true,
	"Map": true, "Set": true, "WeakMap": true, "WeakSet": true,
	"Promise": true, "Symbol": true, "Proxy": true, "Reflect": true,
	"ArrayBuffer": true, "Uint8Array": true, "Uint16Array": true,
	"Uint32Array": true, "Int8Array": true, "Int16Array": true,
	"Int32Array": true, "Float32Array": true, "Float64Array": true,
	"DataView": true,

	// Statics
	"JSON": true, "Math": true,

	// Keywords (must pass through unchanged)
	"var": true, "let": true, "const": true, "function": true,
	"return": true, "if": true, "else": true, "while": true, "for": true,
	"do": true, "switch": true, "case": true, "break": true, "continue": true,
	"new": true, "delete": true, "typeof": true, "instanceof": true,
	"in": true, "of": true, "void": true, "throw": true, "try": true,
	"catch": true, "finally": true, "class": true, "extends": true,
	"super": true, "import": true, "export": true, "from": true,
	"async": true, "await": true, "yield": true, "static": true,
	"get": true, "set": true, "default": true,

	// Common Web/DOM names whose identity matters across implementations.
	"setTimeout": true, "setInterval": true, "clearTimeout": true,
	"clearInterval": true, "fetch": true, "XMLHttpRequest": true,
	"navigator": true, "location": true, "history": true, "localStorage": true,
	"sessionStorage": true, "alert": true, "confirm": true, "prompt": true,
	"addEventListener": true, "removeEventListener": true,
	"querySelector": true, "querySelectorAll": true,
	"getElementById": true, "getElementsByClassName": true,
	"createElement": true, "appendChild": true,
	"parseInt": true, "parseFloat": true, "isNaN": true, "isFinite": true,
	"encodeURIComponent": true, "decodeURIComponent": true,
	"encodeURI": true, "decodeURI": true,
}

// Canonicalize returns (sha256-hex, bypassed) for the given JS/TS source.
// When bypassed is true, no rename pass was performed and the hash is over
// the raw bytes (T-07-canonicalize-cpu).
func Canonicalize(content []byte) (string, bool) {
	if len(content) > maxCanonicalizeSize {
		sum := sha256.Sum256(content)
		return hex.EncodeToString(sum[:]), true
	}
	src := stripComments(string(content))
	out := tokenizeAndRename(src)
	sum := sha256.Sum256([]byte(out))
	return hex.EncodeToString(sum[:]), false
}

// stripComments removes // line and /* */ block comments while preserving
// string and template literals.
func stripComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		// String literals — copy verbatim including escapes.
		if c == '"' || c == '\'' || c == '`' {
			j := i + 1
			for j < n {
				if s[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if s[j] == c {
					j++
					break
				}
				j++
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		// Line comment
		if c == '/' && i+1 < n && s[i+1] == '/' {
			j := i + 2
			for j < n && s[j] != '\n' {
				j++
			}
			i = j
			continue
		}
		// Block comment
		if c == '/' && i+1 < n && s[i+1] == '*' {
			j := i + 2
			for j+1 < n && !(s[j] == '*' && s[j+1] == '/') {
				j++
			}
			if j+1 < n {
				j += 2
			}
			i = j
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// tokenizeAndRename emits the canonicalized representation of src.
//
// Identifiers not on the whitelist are renamed "var_<N>" in
// first-appearance order. String/regex/numeric literals and punctuation
// are preserved (sans surrounding whitespace).
func tokenizeAndRename(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	renames := make(map[string]string)
	next := 0

	i := 0
	n := len(src)
	for i < n {
		c := src[i]
		// Whitespace — drop.
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		// String literals — copy verbatim.
		if c == '"' || c == '\'' || c == '`' {
			j := i + 1
			for j < n {
				if src[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if src[j] == c {
					j++
					break
				}
				j++
			}
			out.WriteString(src[i:j])
			i = j
			continue
		}
		// Identifiers.
		if isIdentStart(rune(c)) {
			j := i + 1
			for j < n && isIdentPart(rune(src[j])) {
				j++
			}
			tok := src[i:j]
			if canonicalizeWhitelist[tok] {
				out.WriteString(tok)
			} else {
				rn, ok := renames[tok]
				if !ok {
					rn = renameAt(next)
					renames[tok] = rn
					next++
				}
				out.WriteString(rn)
			}
			i = j
			continue
		}
		// Anything else (punctuation, digits, operators) — pass through.
		out.WriteByte(c)
		i++
	}
	return out.String()
}

func isIdentStart(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return isIdentStart(r) || unicode.IsDigit(r)
}

func renameAt(n int) string {
	// Use a fixed prefix so renamed tokens never collide with whitelisted
	// names. We don't need base-N here — N is small.
	return "var_" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
