package jsdeob

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// UnpackPacked unpacks base64 and charcode encoded payloads
func UnpackPacked(code string) (string, int) {
	count := 0
	result := code

	// Base64 encoded payloads: atob("...")
	atobPattern := regexp.MustCompile(`atob\s*\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)`)
	for {
		match := atobPattern.FindStringSubmatch(result)
		if match == nil {
			break
		}

		decoded, err := base64.StdEncoding.DecodeString(match[1])
		if err == nil {
			result = strings.Replace(result, match[0], `"`+string(decoded)+`"`, 1)
			count++
		} else {
			break
		}
	}

	// String.fromCharCode(...) patterns
	charCodePattern := regexp.MustCompile(`String\.fromCharCode\s*\(([\d,\s]+)\)`)
	result = charCodePattern.ReplaceAllStringFunc(result, func(match string) string {
		inner := charCodePattern.FindStringSubmatch(match)
		if len(inner) > 1 {
			decoded := DecodeCharCodes(inner[1])
			if decoded != "" {
				count++
				return `"` + decoded + `"`
			}
		}

		return match
	})

	return result, count
}

// DecodeStrings decodes hex, unicode, and array-based string encodings
func DecodeStrings(code string) (string, int) {
	count := 0
	result := code

	// Hex strings: "\x48\x65\x6c\x6c\x6f"
	hexPattern := regexp.MustCompile(`"((?:\\x[0-9a-fA-F]{2})+)"`)
	result = hexPattern.ReplaceAllStringFunc(result, func(match string) string {
		inner := match[1 : len(match)-1]

		decoded := DecodeHexString(inner)
		if decoded != inner {
			count++
			return `"` + decoded + `"`
		}

		return match
	})

	// Unicode escapes: "\u0048\u0065\u006c\u006c\u006f"
	unicodePattern := regexp.MustCompile(`"((?:\\u[0-9a-fA-F]{4})+)"`)
	result = unicodePattern.ReplaceAllStringFunc(result, func(match string) string {
		inner := match[1 : len(match)-1]

		decoded := DecodeUnicodeString(inner)
		if decoded != inner {
			count++
			return `"` + decoded + `"`
		}

		return match
	})

	// Array-based string lookup: _0x1234[0]
	arrayPattern := regexp.MustCompile(`(var\s+)?(_0x[a-f0-9]+)\s*=\s*\[((?:"[^"]*"|'[^']*'|,|\s)*)\];?`)
	arrays := make(map[string][]string)

	for _, match := range arrayPattern.FindAllStringSubmatch(result, -1) {
		varName := match[2]
		arrContent := match[3]
		strPattern := regexp.MustCompile(`["']([^"']*)["']`)
		elements := strPattern.FindAllStringSubmatch(arrContent, -1)

		var arr []string
		for _, el := range elements {
			arr = append(arr, el[1])
		}

		arrays[varName] = arr
	}

	for varName, arr := range arrays {
		lookupPattern := regexp.MustCompile(regexp.QuoteMeta(varName) + `\[(\d+)\]`)
		result = lookupPattern.ReplaceAllStringFunc(result, func(match string) string {
			idxMatch := lookupPattern.FindStringSubmatch(match)
			if len(idxMatch) > 1 {
				idx, err := strconv.Atoi(idxMatch[1])
				if err == nil && idx < len(arr) {
					count++
					return `"` + arr[idx] + `"`
				}
			}

			return match
		})
	}

	return result, count
}

// DecodeHexString converts \x48\x65\x6c\x6c\x6f to Hello
func DecodeHexString(s string) string {
	var result strings.Builder

	parts := strings.SplitSeq(s, "\\x")
	for part := range parts {
		if part == "" {
			continue
		}

		if len(part) >= 2 {
			b, err := hex.DecodeString(part[:2])
			if err == nil {
				result.Write(b)
				result.WriteString(part[2:])
			} else {
				result.WriteString("\\x" + part)
			}
		}
	}

	return result.String()
}

// DecodeUnicodeString converts \u0048\u0065\u006c\u006c\u006f to Hello
func DecodeUnicodeString(s string) string {
	var result strings.Builder

	parts := strings.SplitSeq(s, "\\u")
	for part := range parts {
		if part == "" {
			continue
		}

		if len(part) >= 4 {
			code, err := strconv.ParseInt(part[:4], 16, 32)
			if err == nil {
				result.WriteRune(rune(code))
				result.WriteString(part[4:])
			} else {
				result.WriteString("\\u" + part)
			}
		}
	}

	return result.String()
}

// DecodeCharCodes converts "72, 101, 108, 108, 111" to "Hello"
func DecodeCharCodes(s string) string {
	var result strings.Builder

	parts := strings.SplitSeq(s, ",")
	for part := range parts {
		part = strings.TrimSpace(part)

		code, err := strconv.Atoi(part)
		if err != nil {
			return ""
		}

		if code > 0 && code < utf8.MaxRune {
			result.WriteRune(rune(code))
		}
	}

	return result.String()
}
