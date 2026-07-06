/*
Copyright (c) 2026 Security Research

Package corpus generates draft eval corpora for the rule-based component
classifier (Phase 31 carry → Phase 34). Implements D-34-CORPUS-GENERATOR
+ D-34-CORPUS-NO-AUTO-PROMOTE.

The generator extracts modules for a (kb_id, epoch) snapshot via the shared
classify.LoadSnapshotModules helper, runs component.Apply for a draft
expected_component label per module, and writes the result to a `.draft`
file. The active corpus.json (used by TestCorpusPrecision_Gate) is NEVER
overwritten; an analyst must manually review and rename `.draft` → main.

Schema-of-record is pkg/knowledge/kb/component/eval/testdata/corpus.json
(version=1; fields: name, path, symbols_json, expected_component, notes).
*/
package corpus

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/jsonutil"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/classify"
)

// Report summarizes one GenerateDraft run. JSON tags use snake_case to match
// CLI parity (D-34-CLI-PARITY).
type Report struct {
	KBID          string `json:"kb_id"`
	Epoch         int64  `json:"epoch"`
	ModuleCount   int    `json:"module_count"`
	OutPath       string `json:"out_path"`
	SchemaVersion int    `json:"schema_version"`
}

// labeledModule mirrors pkg/knowledge/kb/component/eval.LabeledModule. We
// don't import the eval package to avoid a dep cycle through testdata.
type labeledModule struct {
	Name              string `json:"name"`
	Path              string `json:"path"`
	SymbolsJSON       string `json:"symbols_json"`
	ExpectedComponent string `json:"expected_component"`
	Notes             string `json:"notes,omitempty"`
}

type corpusFile struct {
	Version int             `json:"version"`
	Modules []labeledModule `json:"modules"`
}

// GenerateDraft extracts the (kbID, epoch) snapshot modules, runs
// component.Apply per module, and writes a corpus draft JSON to outPath.
//
// Per D-34-CORPUS-NO-AUTO-PROMOTE, outPath MUST end in `.draft`. Any other
// suffix returns an error before any I/O — guarantees the active corpus.json
// (precision gate) cannot be overwritten by this tool.
func GenerateDraft(ctx context.Context, db *sql.DB, kbID string, epoch int64, outPath string) (*Report, error) {
	if !strings.HasSuffix(outPath, ".draft") {
		return nil, fmt.Errorf("refuse to overwrite active corpus: outPath must end in .draft (got %q)", outPath)
	}
	if kbID == "" {
		return nil, fmt.Errorf("kb_id is empty")
	}
	mods, err := classify.LoadSnapshotModules(ctx, db, kbID, epoch)
	if err != nil {
		return nil, fmt.Errorf("load snapshot: %w", err)
	}

	rows := make([]labeledModule, 0, len(mods))
	for _, m := range mods {
		res := component.Apply(component.Module{
			ID:          m.ID,
			Name:        m.Name,
			Path:        m.Path,
			SymbolsJSON: m.SymbolsJSON,
		})
		rows = append(rows, labeledModule{
			Name:              m.Name,
			Path:              m.Path,
			SymbolsJSON:       m.SymbolsJSON,
			ExpectedComponent: res.Component,
			Notes:             fmt.Sprintf("draft: %s", res.Evidence),
		})
	}

	payload := corpusFile{Version: 1, Modules: rows}
	data, err := jsonutil.MarshalIndentedNewline(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal corpus: %w", err)
	}

	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir out: %w", err)
		}
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return nil, fmt.Errorf("write corpus: %w", err)
	}

	return &Report{
		KBID:          kbID,
		Epoch:         epoch,
		ModuleCount:   len(rows),
		OutPath:       outPath,
		SchemaVersion: 1,
	}, nil
}
