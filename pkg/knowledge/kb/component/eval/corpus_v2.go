/*
Copyright (c) 2026 Security Research

corpus_v2.go: P40 — schema_version 2 corpus with Pass-B human-relabel fields.
v1 corpus.json preserved as .archive sibling per D-40-CORPUS-JSON-SCHEMA-V2.

Path remap (Plan 40-01 deviation): planner referenced fictional
pkg/knowledge/kb/classify/. Actual layout puts the eval gate alongside
component/eval/ (siblings: classify/, corpus/, eval/, rules/, runtime/).

License: BSD-3-Clause.
*/
package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

// CorpusV2 is the Pass-B relabeled corpus shape.
type CorpusV2 struct {
	SchemaVersion int             `json:"schema_version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Source        string          `json:"source"`
	Entries       []CorpusEntryV2 `json:"entries"`
}

// CorpusEntryV2 records a single human-reviewed module entry.
//
// Pass-A baseline fields (preserved verbatim from v1 LabeledModule):
//   - Name, Path, SymbolsJSON, ExpectedComponent, Notes
//
// Pass-B P40 additions:
//   - ID, PredictedLabel, HumanLabel, Confidence, ReviewStatus, ReviewerNotes
type CorpusEntryV2 struct {
	// v1 baseline (Pass-A):
	Name              string `json:"name"`
	Path              string `json:"path"`
	SymbolsJSON       string `json:"symbols_json"`
	ExpectedComponent string `json:"expected_component"`
	Notes             string `json:"notes,omitempty"`

	// P40 Pass-B additions:
	ID             string  `json:"id"`              // sha256(name+"|"+path)[:16] hex — deterministic
	PredictedLabel string  `json:"predicted_label"` // derived by component.Apply
	HumanLabel     string  `json:"human_label"`     // starts == ExpectedComponent (Pass-A baseline)
	Confidence     float64 `json:"confidence"`      // from component.Apply.Result.Confidence
	ReviewStatus   string  `json:"review_status"`   // accepted | rejected | edited | pending
	ReviewerNotes  string  `json:"reviewer_notes,omitempty"`
}

// LoadCorpusV2 reads a corpus_v2.json. Errors on missing required fields,
// schema mismatch, or out-of-range confidence.
func LoadCorpusV2(path string) (*CorpusV2, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read corpus_v2: %w", err)
	}
	var c CorpusV2
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("unmarshal corpus_v2: %w", err)
	}
	if c.SchemaVersion != 2 {
		return nil, fmt.Errorf("schema_version=%d, want 2", c.SchemaVersion)
	}
	for i, e := range c.Entries {
		if e.ID == "" || e.Name == "" || e.HumanLabel == "" {
			return nil, fmt.Errorf("entry[%d] missing required field (id/name/human_label)", i)
		}
		if e.Confidence < 0 || e.Confidence > 1 {
			return nil, fmt.Errorf("entry[%d] confidence=%v not in [0,1]", i, e.Confidence)
		}
	}
	return &c, nil
}

// WriteCorpusV2 writes a corpus to disk with canonical formatting:
// entries sorted by ID, two-space indent, RFC3339 UTC second-precision time.
func WriteCorpusV2(path string, c *CorpusV2) error {
	if c == nil {
		return fmt.Errorf("nil corpus")
	}
	sorted := make([]CorpusEntryV2, len(c.Entries))
	copy(sorted, c.Entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	out := CorpusV2{
		SchemaVersion: 2,
		GeneratedAt:   c.GeneratedAt.UTC().Round(time.Second),
		Source:        c.Source,
		Entries:       sorted,
	}
	enc, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal corpus_v2: %w", err)
	}
	return os.WriteFile(path, append(enc, '\n'), 0o644)
}

// entryID computes a deterministic id from (name+"|"+path).
func entryID(name, path string) string {
	h := sha256.Sum256([]byte(name + "|" + path))
	return hex.EncodeToString(h[:])[:16]
}

// MigrateCorpusV1ToV2 reads a v1 corpus.json (Corpus{Version:1, Modules:[]LabeledModule})
// and emits a v2 stub. For each v1 module:
//   - id = sha256(name+"|"+path)[:16]
//   - predicted_label = component.Apply(module).Component
//   - human_label = ExpectedComponent (Pass-A baseline; reviewer adjusts during Pass-B)
//   - confidence = float64(component.Apply.Result.Confidence)
//   - review_status = "pending"
//
// Caller archives v1 separately. Output canonicalized via WriteCorpusV2.
func MigrateCorpusV1ToV2(v1Path, v2Path string) error {
	raw, err := os.ReadFile(v1Path)
	if err != nil {
		return fmt.Errorf("read v1: %w", err)
	}
	var v1 Corpus
	if err := json.Unmarshal(raw, &v1); err != nil {
		return fmt.Errorf("unmarshal v1: %w", err)
	}
	if v1.Version != 1 {
		return fmt.Errorf("v1 corpus version=%d, want 1", v1.Version)
	}
	if len(v1.Modules) == 0 {
		return fmt.Errorf("v1 corpus empty")
	}

	entries := make([]CorpusEntryV2, 0, len(v1.Modules))
	for _, m := range v1.Modules {
		res := component.Apply(component.Module{
			Name:        m.Name,
			Path:        m.Path,
			SymbolsJSON: m.SymbolsJSON,
		})
		entries = append(entries, CorpusEntryV2{
			Name:              m.Name,
			Path:              m.Path,
			SymbolsJSON:       m.SymbolsJSON,
			ExpectedComponent: m.ExpectedComponent,
			Notes:             m.Notes,
			ID:                entryID(m.Name, m.Path),
			PredictedLabel:    res.Component,
			HumanLabel:        m.ExpectedComponent,
			Confidence:        float64(res.Confidence),
			ReviewStatus:      "pending",
			ReviewerNotes:     "",
		})
	}

	out := &CorpusV2{
		SchemaVersion: 2,
		GeneratedAt:   time.Now().UTC().Round(time.Second),
		Source:        "p40 migrated from v1 corpus.json (Pass-A baseline → Pass-B pending)",
		Entries:       entries,
	}
	return WriteCorpusV2(v2Path, out)
}
