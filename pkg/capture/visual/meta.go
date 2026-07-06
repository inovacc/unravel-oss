/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/knowledge"
)

// Meta is the per-state _meta.json schema (D-15).
type Meta struct {
	RunID                   string   `json:"run_id"`
	Component               string   `json:"component"`
	StateSlug               string   `json:"state_slug"`
	Route                   string   `json:"route,omitempty"`
	Viewport                Viewport `json:"viewport"`
	Framework               string   `json:"framework"`
	FrameworkConfidence     float64  `json:"framework_confidence"`
	FrameworkEvidence       []string `json:"framework_evidence"`
	FrameworkAwareTree      bool     `json:"framework_aware_tree"`
	CapturedAt              string   `json:"captured_at"`
	Mode                    string   `json:"mode"`
	ContentProtectionWarned bool     `json:"content_protection_warned"`
	ImageSHA256             string   `json:"image_sha256"`
	ImagePHash              string   `json:"image_phash,omitempty"`
	TreeSHA256              string   `json:"tree_sha256"`
	LayoutSHA256            string   `json:"layout_sha256"`
	Errors                  []string `json:"errors,omitempty"`
}

// sha256Hex computes the canonical "sha256:<hex>" identifier for content
// addressing in _meta.json.
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// writeMeta atomically writes _meta.json into stateDir. Reuses
// knowledge.WriteJSONAtomic for path-traversal + symlink-reject + temp+rename
// guarantees (T-08-01, T-08-02).
func writeMeta(stateDir string, m *Meta) error {
	return knowledge.WriteJSONAtomic(filepath.Join(stateDir, "_meta.json"), m)
}
