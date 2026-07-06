/*
Copyright (c) 2026 Security Research
*/
// Redact strips PII / secrets out of free-form error strings before they land
// in enrich_attempts.error_message_redacted. Pure function, package-level
// precompiled regexes, idempotent: Redact(Redact(x)) == Redact(x).
//
// Hierarchy of rules (order matters — DSN/API-key rules MUST run before the
// generic "kv pair" rule so they capture the full secret, not just the
// trailing token):
//
//  1. Postgres DSNs            → <dsn>
//  2. anthropic-style API keys → <anthropic-key>
//  3. Env-var leakage lines    → <env>=<redacted>
//  4. Generic key=val pairs    → key=<redacted>
//  5. Windows abs paths        → <path>
//  6. POSIX abs paths          → <path>  (preserves leading whitespace/colon)
//  7. Truncate to 4 KB + "…(truncated)" suffix
//
// Net result: the categorical error_class field still carries the diagnostic
// signal even if the prose around it is heavily redacted.
package kbenrich

import (
	"regexp"
	"strings"
)

const redactMaxBytes = 4096

const truncatedSuffix = "…(truncated)"

var (
	reDSN          = regexp.MustCompile(`postgres(?:ql)?://[^\s]+`)
	reAnthropicKey = regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)
	reEnvVarLine   = regexp.MustCompile(`(?m)^[A-Z_][A-Z0-9_]*=.+$`)
	reKVPair       = regexp.MustCompile(`(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*\S+`)
	reWindowsPath  = regexp.MustCompile(`[A-Za-z]:\\(?:[^\\\r\n\s]+\\)+[^\\\r\n\s]*`)
	rePosixPath    = regexp.MustCompile(`(^|[\s:])/(?:[^/\s]+/)+[^/\s]*`)
)

// Redact applies the redaction rules. Empty input returns empty output.
func Redact(s string) string {
	if s == "" {
		return s
	}

	// 1) DSNs
	s = reDSN.ReplaceAllString(s, "<dsn>")
	// 2) anthropic-style API keys
	s = reAnthropicKey.ReplaceAllString(s, "<anthropic-key>")
	// 3) env-var leakage lines (must precede generic kv pair so the whole line
	//    becomes <env>=<redacted>, not just the value)
	s = reEnvVarLine.ReplaceAllString(s, "<env>=<redacted>")
	// 4) generic kv pairs
	s = reKVPair.ReplaceAllStringFunc(s, func(m string) string {
		// Preserve the key name and "=" — value becomes <redacted>.
		// Match shape: <key><sep><val> where sep is ':' or '='.
		// We always normalise to key=<redacted> for both cases.
		// Extract the leading word boundary key.
		for i := range len(m) {
			if m[i] == ':' || m[i] == '=' {
				return m[:i] + "=<redacted>"
			}
		}
		return "<redacted>"
	})
	// 5) Windows absolute paths
	s = reWindowsPath.ReplaceAllString(s, "<path>")
	// 6) POSIX absolute paths (preserves the leading whitespace/colon group).
	s = rePosixPath.ReplaceAllString(s, "$1<path>")

	// 7) Truncate.
	if len(s) > redactMaxBytes {
		// Avoid double-suffixing on idempotent re-runs.
		if before, ok := strings.CutSuffix(s, truncatedSuffix); ok {
			s = before
		}
		s = s[:redactMaxBytes] + truncatedSuffix
	}

	return s
}
