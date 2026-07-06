/*
Copyright (c) 2026 Security Research

Package component provides a pure-Go, blank-import-driven rule registry that
classifies modules into one of 11 fixed taxonomy buckets per migration 000005.
Apply is pure (no DB). The DB-touching layer lives in component/classify.
*/
package component

import "regexp"

// Module is the input row to the classifier. Fields map onto kb columns:
//   - Name        -> modules.name
//   - Path        -> modules.body_excerpt (used as source-path proxy in v1)
//   - SymbolsJSON -> modules.symbols_json (raw JSON string; lowercase scan)
type Module struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	SymbolsJSON string `json:"symbols_json"`
}

// Result is the classifier verdict for one Module.
type Result struct {
	Component  string  `json:"component"`  // one of taxonomy buckets
	Confidence float32 `json:"confidence"` // 0.65 / 0.80 / 0.95 / 1.0 (other)
	Classifier string  `json:"classifier"` // always "rule" in P31
	Evidence   string  `json:"evidence"`   // human-readable rule trace
}

// Rule is a registered classifier rule. Negative rules (Suppress=true) are
// evaluated as a preflight pass; positive rules run after.
type Rule struct {
	Name           string         // unique identifier, e.g. "auth/oauth-jwt"
	Component      string         // taxonomy bucket; ignored when Suppress=true except as the suppression target
	Confidence     float32        // 0.65 / 0.80 / 0.95 (positive rules only)
	PathRegex      *regexp.Regexp // optional, pre-compiled
	NameRegex      *regexp.Regexp // optional, pre-compiled
	SymbolKeywords []string       // case-insensitive substring; matched against lowercase(SymbolsJSON)
	Suppress       bool           // true = negative rule
	Priority       int            // tiebreak per priorities.go
}

// Buckets is the locked taxonomy. P31 must NOT add new entries.
var Buckets = []string{
	"communication", "auth", "ui", "ipc", "security",
	"stealth", "telemetry", "storage", "crypto", "protocol", "other",
}
