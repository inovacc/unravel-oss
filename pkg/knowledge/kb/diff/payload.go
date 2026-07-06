/*
Copyright (c) 2026 Security Research
*/

// Package diff defines typed payload schemas, canonical identifiers, and the
// consecutive-epoch / long-range diff primitives consumed by the v2.5 KB
// ingest writer (Phase 30) and by downstream CLI/MCP surfaces.
//
// Per D-30-DIFF-PAYLOAD-TYPED, every kb_diffs row carries one of nine typed
// JSONB payload shapes. Per D-30-DIFF-IDENTIFIER, the kb_diffs.identifier
// column uses a category-specific canonical form (see Identifier).
package diff

// Category constants — must match the kb_diffs_category_chk CHECK constraint
// in migration 000005.
const (
	CategoryDep        = "dep"
	CategoryCapability = "capability"
	CategoryURL        = "url"
	CategoryRisk       = "risk"
	CategoryCert       = "cert"
	CategoryFact       = "fact"
	CategoryModule     = "module"
	// CategoryComponent is forward-compat for Phase 31 classifier writes.
	// Phase 30 ingest never emits these (D-30-COMPONENT-DEFERRED).
	CategoryComponent = "component"
	CategoryFile      = "file"
)

// Change-type constants — must match the kb_diffs_change_chk CHECK constraint
// in migration 000005.
const (
	ChangeAdded    = "added"
	ChangeRemoved  = "removed"
	ChangeModified = "modified"
)

// DepDiff is the JSONB payload for category=dep.
type DepDiff struct {
	Name       string `json:"name"`
	OldVersion string `json:"old_version,omitempty"`
	NewVersion string `json:"new_version,omitempty"`
	Source     string `json:"source"`
}

// CapabilityDiff is the JSONB payload for category=capability.
type CapabilityDiff struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Severity  string `json:"severity"`
}

// URLDiff is the JSONB payload for category=url.
type URLDiff struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
}

// RiskDiff is the JSONB payload for category=risk. Pointer fields preserve the
// "score not emitted" signal across JSON marshal/unmarshal.
type RiskDiff struct {
	OldScore *int   `json:"old_score,omitempty"`
	NewScore *int   `json:"new_score,omitempty"`
	Delta    *int   `json:"delta,omitempty"`
	OldLevel string `json:"old_level,omitempty"`
	NewLevel string `json:"new_level,omitempty"`
}

// CertDiff is the JSONB payload for category=cert.
type CertDiff struct {
	FingerprintOld string `json:"fingerprint_old,omitempty"`
	FingerprintNew string `json:"fingerprint_new,omitempty"`
	SubjectOld     string `json:"subject_old,omitempty"`
	SubjectNew     string `json:"subject_new,omitempty"`
}

// FactDiff is the JSONB payload for category=fact. Key is expected to already
// carry the "<category>/<key>" composition per D-30-DIFF-IDENTIFIER.
type FactDiff struct {
	Key      string `json:"key"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// ModuleDiff is the JSONB payload for category=module.
type ModuleDiff struct {
	BodySHA256 string `json:"body_sha256"`
	Name       string `json:"name"`
	Lang       string `json:"lang"`
}

// ComponentDiff is the JSONB payload for category=component. Forward-compat
// only — Phase 30 ingest never emits these (D-30-COMPONENT-DEFERRED); Phase 31
// classifier owns these writes.
type ComponentDiff struct {
	ModuleID     string `json:"module_id"`
	OldComponent string `json:"old_component,omitempty"`
	NewComponent string `json:"new_component,omitempty"`
	Classifier   string `json:"classifier"`
}

// FileDiff is the JSONB payload for category=file.
type FileDiff struct {
	FileSHA256 string `json:"file_sha256"`
	RelPath    string `json:"rel_path"`
	SizeBytes  int64  `json:"size_bytes"`
}

// Diff is the row-shaped result returned by ComputeConsecutive ready for
// kb_diffs INSERT.
//
// FromSourceID / ToSourceID are knowledge_sources.id (BIGINT PK per migration
// 000005's foreign-key declaration: from_source_id BIGINT REFERENCES
// knowledge_sources(id)). The plan text described these as UUIDs but the
// actual schema lands them as BIGINT integer PKs — using int64 here keeps the
// Go shape aligned with the SQL surface.
//
// ComputedAt is a millisecond unix epoch to match kb_diffs.computed_at BIGINT.
//
// Payload is the marshalled JSON for the typed payload struct (DepDiff /
// CapabilityDiff / etc.) and lands in kb_diffs.payload JSONB unchanged.
type Diff struct {
	FromSourceID int64
	ToSourceID   int64
	Category     string
	ChangeType   string
	Identifier   string
	Payload      []byte
	ComputedAt   int64
}
