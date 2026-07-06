//go:build integration

/*
Copyright (c) 2026 Security Research

Integration test for `unravel kb classify --eval-corpus-build` (Phase 34,
Plan 04). Seeds a synthetic kb_id snapshot, runs the corpus generator, and
asserts the .draft file conforms to the eval corpus schema.
*/
package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/corpus"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime" // populate rule registry
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

func TestClassify_EvalCorpusBuild(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })

	const kbID = "kb34corpus00001a"
	const epoch int64 = 3
	ctx := context.Background()

	// Synthetic kb_apps row required by FK from knowledge_sources.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at, metadata)
		 VALUES ($1, 'corpus-test', 'Corpus Test', 'unknown', 0, 0, '{}'::jsonb)
		 ON CONFLICT (kb_id) DO NOTHING`, kbID); err != nil {
		t.Fatalf("seed kb_apps: %v", err)
	}

	// Seed knowledge_sources snapshot.
	var ksID int64
	if err := db.QueryRowContext(ctx,
		`INSERT INTO knowledge_sources (kb_id, app, epoch, captured_at, ks_id_fs)
		 VALUES ($1, 'corpus-test', $2, 0, 'corpus-test_3')
		 RETURNING id`, kbID, epoch).Scan(&ksID); err != nil {
		t.Fatalf("seed knowledge_sources: %v", err)
	}

	// Seed 3 modules with diverse signals so component.Apply yields varied labels.
	mods := []struct {
		name, body, syms string
	}{
		{"AuthLoginManager", "src/auth/LoginManager.cs", `["jwt","oauth_token"]`},
		{"NetHttpApi", "src/net/HttpApi.cs", `["http.Client","fetch"]`},
		{"GenericHelpers", "src/util/Helpers.cs", `["Format","Pad"]`},
	}
	for _, m := range mods {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO modules (name, body_excerpt, symbols_json, first_source_id)
			 VALUES ($1, $2, $3, $4)`, m.name, m.body, m.syms, ksID); err != nil {
			t.Fatalf("seed module %s: %v", m.name, err)
		}
	}

	// Snapshot active corpus before generator runs.
	const activePath = "../pkg/knowledge/kb/component/eval/testdata/corpus.json"
	before, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("read active corpus: %v", err)
	}
	beforeHash := sha256.Sum256(before)

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "corpus.json.draft")
	rep, err := corpus.GenerateDraft(ctx, db, kbID, epoch, outPath)
	if err != nil {
		t.Fatalf("GenerateDraft: %v", err)
	}
	if rep.SchemaVersion != 1 {
		t.Fatalf("schema version: want 1, got %d", rep.SchemaVersion)
	}
	if rep.ModuleCount != 3 {
		t.Fatalf("module count: want 3, got %d", rep.ModuleCount)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read draft: %v", err)
	}
	var parsed struct {
		Version int `json:"version"`
		Modules []struct {
			Name              string `json:"name"`
			Path              string `json:"path"`
			SymbolsJSON       string `json:"symbols_json"`
			ExpectedComponent string `json:"expected_component"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse draft: %v", err)
	}
	if parsed.Version != 1 {
		t.Fatalf("draft version: want 1, got %d", parsed.Version)
	}
	if len(parsed.Modules) != 3 {
		t.Fatalf("draft modules: want 3, got %d", len(parsed.Modules))
	}
	for _, m := range parsed.Modules {
		if m.ExpectedComponent == "" {
			t.Errorf("empty expected_component for %s", m.Name)
		}
	}

	// Active corpus.json must remain byte-identical (D-34-CORPUS-NO-AUTO-PROMOTE).
	after, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("re-read active corpus: %v", err)
	}
	afterHash := sha256.Sum256(after)
	if beforeHash != afterHash {
		t.Fatal("active corpus.json was mutated by generator")
	}
}
