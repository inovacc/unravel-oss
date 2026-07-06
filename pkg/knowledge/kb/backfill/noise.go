/*
Copyright (c) 2026 Security Research
*/

package backfill

import (
	"encoding/json"
	"regexp"
	"strings"
)

// jsKeywords is the set of language keywords that should never appear as
// meaningful symbol names. Their presence in a "methods" or "functions"
// array signals old regex extraction gone wrong.
var jsKeywords = map[string]struct{}{
	"return": {}, "switch": {}, "if": {}, "for": {}, "while": {},
	"catch": {}, "throw": {}, "var": {}, "let": {}, "const": {},
	"function": {}, "class": {}, "import": {}, "export": {},
	"default": {}, "new": {}, "delete": {}, "typeof": {},
	"instanceof": {}, "void": {}, "break": {}, "continue": {},
	"case": {}, "else": {}, "try": {}, "do": {}, "in": {},
	"of": {}, "yield": {}, "async": {}, "await": {},
	// Go keywords that could slip in
	"func": {}, "package": {}, "type": {}, "struct": {},
	"interface": {}, "map": {}, "chan": {}, "go": {},
	"defer": {}, "select": {}, "range": {},
}

// regexCharClassRe matches strings that look like a regex character class
// (e.g. "[A-Z]", "[0-9]", "[\s]", "[^abc]"). These appear when the legacy
// extractor accidentally captured a regexp literal as a tag/symbol name.
var regexCharClassRe = regexp.MustCompile(`^\[[\^]?[A-Za-z0-9\\.\-_^$|?*+(){}\[\]]{1,20}\]$`)

// IsNoisy returns true when symbolsJSON looks like it came from the legacy
// regex extractor and contains unreliable data. A noisy value should be
// replaced by re-running the langs walker on the stored body.
//
// IsNoisy returns true when ANY of:
//  1. The string is blank / empty.
//  2. The JSON fails to parse (corrupt).
//  3. A "methods", "functions", or "classes" array contains a JS/Go keyword.
//  4. Any string value in any array looks like a regex character class.
//  5. Every array in the top-level object is empty (no usable symbols at all).
func IsNoisy(symbolsJSON string) bool {
	s := strings.TrimSpace(symbolsJSON)
	if s == "" {
		return true
	}

	// Attempt to parse as a JSON object with string-array values.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &obj); err != nil {
		// Unparseable → treat as noisy.
		return true
	}
	if len(obj) == 0 {
		return true
	}

	allEmpty := true
	for key, raw := range obj {
		var arr []string
		if err := json.Unmarshal(raw, &arr); err != nil {
			// Non-array value (e.g. nested object) — not a noise signal by itself.
			allEmpty = false
			continue
		}
		if len(arr) > 0 {
			allEmpty = false
		}
		for _, v := range arr {
			// Check for regex character classes in any array.
			if regexCharClassRe.MatchString(v) {
				return true
			}
			// Check for keywords only in symbol-name arrays.
			if key == "methods" || key == "functions" || key == "classes" || key == "types" {
				if _, bad := jsKeywords[strings.ToLower(v)]; bad {
					return true
				}
			}
		}
	}

	if allEmpty {
		return true
	}
	return false
}
