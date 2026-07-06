// Package exportbundle defines the deterministic, bounded layout for the
// kb_export fidelity bundle (manifest + content-addressed body files).
// Pure: no DB, no filesystem, no AI.
package exportbundle

import "strings"

// SchemaVersion is the fidelity-bundle manifest schema version.
const SchemaVersion = 1

// BodyPath returns the deterministic relative path for a module body keyed by
// its content sha256: bodies/<first2>/<sha>.txt. Empty sha → empty path.
func BodyPath(sha256 string) string {
	s := strings.TrimSpace(sha256)
	if s == "" {
		return ""
	}
	prefix := s
	if len(s) > 2 {
		prefix = s[:2]
	}
	return "bodies/" + prefix + "/" + s + ".txt"
}

// Budget enforces operator scope/size bounds. Limit<=0 means unlimited count;
// MaxBytes<=0 means unlimited bytes. Add reports whether the item fits; once
// a bound is exceeded Truncated latches true and Add returns false.
type Budget struct {
	Limit     int
	MaxBytes  int64
	count     int
	bytes     int64
	Truncated bool
}

// Add accounts for one module of n body-bytes. Returns false (and latches
// Truncated) when admitting it would exceed Limit or MaxBytes.
func (b *Budget) Add(n int64) bool {
	if b.Truncated {
		return false
	}
	if b.Limit > 0 && b.count+1 > b.Limit {
		b.Truncated = true
		return false
	}
	if b.MaxBytes > 0 && b.bytes+n > b.MaxBytes {
		b.Truncated = true
		return false
	}
	b.count++
	b.bytes += n
	return true
}

// ManifestRecord is one module's fidelity record.
type ManifestRecord struct {
	ModuleID      int64  `json:"module_id"`
	App           string `json:"app"`
	Name          string `json:"name"`
	SyntheticName string `json:"synthetic_name,omitempty"`
	BodySHA256    string `json:"body_sha256"`
	BodySize      int64  `json:"body_size"`
	Lang          string `json:"lang,omitempty"`
	BodyPath      string `json:"body_path,omitempty"`
	BodyStatus    string `json:"body_status"` // full | excerpt | absent
	Summary       string `json:"summary,omitempty"`
	Tags          string `json:"tags,omitempty"`
	Role          string `json:"role,omitempty"`
	LongSummary   string `json:"long_summary,omitempty"`
	Inputs        string `json:"inputs_json,omitempty"`
	Outputs       string `json:"outputs_json,omitempty"`
	SideEffects   string `json:"side_effects,omitempty"`
	Deps          string `json:"deps_json,omitempty"`
}

// Manifest is the bundle's manifest.json.
type Manifest struct {
	SchemaVersion   int              `json:"schema_version"`
	KbID            string           `json:"kb_id"`
	GeneratedAtUnix int64            `json:"generated_at_unix"`
	ModuleCount     int              `json:"module_count"`
	Truncated       bool             `json:"truncated"`
	TruncatedReason string           `json:"truncated_reason,omitempty"`
	Records         []ManifestRecord `json:"records"`
}
