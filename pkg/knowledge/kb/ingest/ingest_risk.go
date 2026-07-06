/*
Copyright (c) 2026 Security Research

Risk-source canonicalization for the v2.5 ingest writer.

Each analyzer (UWP, Electron/Tauri, Android) emits its own risk score
shape inside the per-app knowledge.json. Phase 30 ingest does NOT
re-derive risk from raw evidence — it canonicalizes the analyzer
output to (risk_score *int, risk_level string) per D-30-RISK-CANONICAL.

When no analyzer emitted a score the result is (nil, "unknown") — NOT
"low". This preserves the "we don't know" signal for downstream
queries.

License: BSD-3-Clause.
*/

package ingest

// CanonicalizeRisk maps analyzer-specific risk fields to canonical
// (*risk_score, risk_level) per D-30-RISK-CANONICAL.
//
// Order of precedence:
//  1. UWP path: uwp_analyze.score.value + uwp_analyze.score.level
//  2. Electron/Tauri path: security.risk_score + security.risk_level
//  3. Android path: android_manifest.security_score (level derived)
//
// Returns (nil, "unknown") when none of the above paths yielded a
// usable score — preserving the "we don't know" signal.
func CanonicalizeRisk(knowledgeJSON map[string]any) (*int, string) {
	if knowledgeJSON == nil {
		return nil, "unknown"
	}

	// 1. UWP — uwp_analyze.score.{value,level}
	if uwp, ok := knowledgeJSON["uwp_analyze"].(map[string]any); ok {
		if score, ok := uwp["score"].(map[string]any); ok {
			if score != nil {
				if v, ok := readInt(score["value"]); ok {
					level, _ := score["level"].(string)
					if level == "" {
						level = levelFromScore(v)
					}
					return &v, level
				}
			}
		}
	}

	// 2. Electron / Tauri — security.{risk_score,risk_level}
	if sec, ok := knowledgeJSON["security"].(map[string]any); ok {
		if v, ok := readInt(sec["risk_score"]); ok {
			level, _ := sec["risk_level"].(string)
			if level == "" {
				level = levelFromScore(v)
			}
			return &v, level
		}
	}

	// 3. Android — android_manifest.security_score
	if am, ok := knowledgeJSON["android_manifest"].(map[string]any); ok {
		if v, ok := readInt(am["security_score"]); ok {
			return &v, levelFromScore(v)
		}
	}

	return nil, "unknown"
}

// readInt accepts the wide variety of numeric shapes that arrive from
// JSON unmarshalling into map[string]any (float64 default), as well as
// raw ints emitted from in-memory test fixtures.
func readInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case float32:
		return int(n), true
	}
	return 0, false
}

// levelFromScore maps a 0-100 risk score to a canonical level bucket.
// Per D-30-RISK-CANONICAL:
//
//	0–24   → "low"
//	25–49  → "medium"
//	50–74  → "high"
//	75–100 → "critical"
//
// Out-of-range scores clamp to the nearest bucket.
func levelFromScore(score int) string {
	switch {
	case score < 25:
		return "low"
	case score < 50:
		return "medium"
	case score < 75:
		return "high"
	default:
		return "critical"
	}
}
