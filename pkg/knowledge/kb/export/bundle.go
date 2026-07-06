/*
Copyright (c) 2026 Security Research

Package export produces portable KB bundles per D-43-BUNDLE-SCHEMA-V1.
Bundle is a directory tree; Pack wraps as .kbb.tar.gz for transport.

The bundle schema is a contract between Plan 43-01 (export) and Plan 43-02
(import). Determinism is REQUIRED: same input must produce byte-identical
manifest bytes across runs (mitigates T-43-04 — repudiation via spurious
checksum mismatch).
*/
package export

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// BundleSchemaVersion is the current bundle schema. v2.9 P54 introduced V2
// (Ed25519-signed) per ADR-0007; V1 stays importable through 2026-09-07.
const BundleSchemaVersion = 2

// BundleSchemaV1Removal is the calendar gate for dropping V1 import support.
// Until that date, V1 bundles import with a deprecation warning. See
// `.planning/notes/2026-05-07-bundle-schema-v2.md`.
var BundleSchemaV1Removal = time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)

// SignatureAlgorithm names the canonical signature primitive for V2 bundles.
const SignatureAlgorithm = "ed25519"

// ManifestDigestAlg names the digest used as the signature input.
const ManifestDigestAlg = "sha256"

// BundleManifest is the bundle.json contents.
type BundleManifest struct {
	BundleSchemaVersion int       `json:"bundle_schema_version"`
	KbID                string    `json:"kb_id"`
	PackageID           string    `json:"package_id"`
	Platform            string    `json:"platform"`
	ExportedAt          time.Time `json:"exported_at"`
	ExportedBy          string    `json:"exported_by"`
	Counts              Counts    `json:"counts"`
	// Checksum is the sha256 (hex) of the canonical knowledge.json bytes.
	// Verified on import (Plan 43-02).
	Checksum string `json:"checksum"`
	// V2-only: advisory algorithm names. Empty for V1 manifests.
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	ManifestDigestAlg  string `json:"manifest_digest_alg,omitempty"`
}

// Counts describes the per-table row counts inside the bundle.
type Counts struct {
	KnowledgeSources int `json:"knowledge_sources"`
	AppFacts         int `json:"app_facts"`
	KbDiffs          int `json:"kb_diffs"`
}

// MarshalManifest produces canonical (sorted-key, RFC3339-UTC, two-space indent)
// JSON. Same input → byte-identical output across runs.
//
// Determinism rules:
//  1. ExportedAt is forced to UTC and rendered via RFC3339Nano.
//  2. Top-level keys are emitted in sorted (alphabetic) order.
//  3. Two-space indentation, no trailing newline.
func MarshalManifest(m *BundleManifest) ([]byte, error) {
	if m == nil {
		return nil, errors.New("kb_export: nil manifest")
	}
	if m.BundleSchemaVersion == 0 {
		m.BundleSchemaVersion = BundleSchemaVersion
	}
	// Build a string-keyed map so we can canonicalize ordering ourselves.
	kv := map[string]any{
		"bundle_schema_version": m.BundleSchemaVersion,
		"kb_id":                 m.KbID,
		"package_id":            m.PackageID,
		"platform":              m.Platform,
		"exported_at":           m.ExportedAt.UTC().Format(time.RFC3339Nano),
		"exported_by":           m.ExportedBy,
		"counts": map[string]any{
			"knowledge_sources": m.Counts.KnowledgeSources,
			"app_facts":         m.Counts.AppFacts,
			"kb_diffs":          m.Counts.KbDiffs,
		},
		"checksum": m.Checksum,
	}
	// V2 advisory fields. Default to ed25519/sha256 when emitting V2 manifests
	// so the canonical bytes self-document the signature contract.
	if m.BundleSchemaVersion >= 2 {
		algo := m.SignatureAlgorithm
		if algo == "" {
			algo = SignatureAlgorithm
		}
		dig := m.ManifestDigestAlg
		if dig == "" {
			dig = ManifestDigestAlg
		}
		kv["signature_algorithm"] = algo
		kv["manifest_digest_alg"] = dig
	}
	return canonicalJSON(kv)
}

// UnmarshalManifest parses a manifest with strict validation (rejects
// schema mismatch, missing kb_id, bad checksum encoding).
func UnmarshalManifest(b []byte) (*BundleManifest, error) {
	var raw struct {
		BundleSchemaVersion int    `json:"bundle_schema_version"`
		KbID                string `json:"kb_id"`
		PackageID           string `json:"package_id"`
		Platform            string `json:"platform"`
		ExportedAt          string `json:"exported_at"`
		ExportedBy          string `json:"exported_by"`
		Counts              Counts `json:"counts"`
		Checksum            string `json:"checksum"`
		SignatureAlgorithm  string `json:"signature_algorithm"`
		ManifestDigestAlg   string `json:"manifest_digest_alg"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("kb_export: parse manifest: %w", err)
	}
	// Tolerant version envelope: V1 + V2 both accepted. Caller decides whether
	// to enforce V2-only via signature verification. V1 import emits a
	// deprecation warning at the cmd layer.
	if raw.BundleSchemaVersion != 1 && raw.BundleSchemaVersion != 2 {
		return nil, fmt.Errorf("kb_export: bundle_schema_version unsupported (got %d, want 1 or 2)",
			raw.BundleSchemaVersion)
	}
	if raw.KbID == "" {
		return nil, errors.New("kb_export: manifest missing kb_id")
	}
	if l := len(raw.Checksum); l != 0 && l != 64 {
		return nil, fmt.Errorf("kb_export: invalid checksum length %d (want hex sha256, 64 chars)", l)
	}
	t, err := time.Parse(time.RFC3339Nano, raw.ExportedAt)
	if err != nil {
		// Tolerate plain RFC3339 (no fractional seconds).
		t, err = time.Parse(time.RFC3339, raw.ExportedAt)
		if err != nil {
			return nil, fmt.Errorf("kb_export: parse exported_at %q: %w", raw.ExportedAt, err)
		}
	}
	return &BundleManifest{
		BundleSchemaVersion: raw.BundleSchemaVersion,
		KbID:                raw.KbID,
		PackageID:           raw.PackageID,
		Platform:            raw.Platform,
		ExportedAt:          t.UTC(),
		ExportedBy:          raw.ExportedBy,
		Counts:              raw.Counts,
		Checksum:            raw.Checksum,
		SignatureAlgorithm:  raw.SignatureAlgorithm,
		ManifestDigestAlg:   raw.ManifestDigestAlg,
	}, nil
}

// canonicalJSON emits JSON with sorted keys at every nesting level, two-space
// indent, no trailing newline. Numbers and strings are rendered through
// json.Marshal so escaping matches the std lib exactly.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v, ""); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any, indent string) error {
	const step = "  "
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			buf.WriteString("{}")
			return nil
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteString("{\n")
		next := indent + step
		for i, k := range keys {
			buf.WriteString(next)
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteString(": ")
			if err := writeCanonical(buf, x[k], next); err != nil {
				return err
			}
			if i < len(keys)-1 {
				buf.WriteString(",")
			}
			buf.WriteString("\n")
		}
		buf.WriteString(indent)
		buf.WriteString("}")
	case []any:
		if len(x) == 0 {
			buf.WriteString("[]")
			return nil
		}
		buf.WriteString("[\n")
		next := indent + step
		for i, item := range x {
			buf.WriteString(next)
			if err := writeCanonical(buf, item, next); err != nil {
				return err
			}
			if i < len(x)-1 {
				buf.WriteString(",")
			}
			buf.WriteString("\n")
		}
		buf.WriteString(indent)
		buf.WriteString("]")
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(raw)
	}
	return nil
}
