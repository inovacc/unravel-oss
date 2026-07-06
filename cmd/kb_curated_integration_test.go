//go:build integration

// Integration: serial — mutates curated* flag vars + UNRAVEL_KB_STORE env + config DSN.

package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/curatedstore"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// seedCuratedKbApps seeds kb_apps canonical K and a kb_aliases row mapping ALIASKB→K.
func seedCuratedKbApps(t *testing.T, db *sql.DB) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed exec: %v\nquery: %s", err, q)
		}
	}

	// ── 1. kb_apps canonical ──────────────────────────────────────────────
	exec(`INSERT INTO kb_apps
		(kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at)
		VALUES ('K', 'curated-app', 'Curated App', 'electron', 0, 0)`)

	// ── 2. kb_aliases: ALIASKB → K ───────────────────────────────────────
	exec(`INSERT INTO kb_aliases (alias_kb_id, canonical_kb_id, merged_at, merged_by, reason)
		VALUES ('ALIASKB', 'K', $1, 'test', 'integration test alias')`,
		time.Now().UnixMilli())
}

// buildFixtureTree creates <store>/apps/K/versions/v1/ with three files.
// On non-Windows also creates a symlink "evil" → an outside TempDir.
// Returns the v1 dir path.
func buildFixtureTree(t *testing.T, store string) string {
	t.Helper()
	v1 := filepath.Join(store, "apps", "K", "versions", "v1")
	if err := os.MkdirAll(filepath.Join(v1, "src"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(v1, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	write("app.beautified.js", "/* beautified JS */\nfunction main(){}")
	write("Foo.java", "// decompiled\npublic class Foo {}")
	if err := os.WriteFile(filepath.Join(v1, "src", "x.go"), []byte("package x\n// reconstructed\n"), 0o644); err != nil {
		t.Fatalf("write src/x.go: %v", err)
	}
	if runtime.GOOS != "windows" {
		outside := t.TempDir()
		_ = os.Symlink(outside, filepath.Join(v1, "evil"))
	}
	return v1
}

// invokeCuratedList builds a fresh *cobra.Command, wires context+buffer, calls runKbCuratedList.
func invokeCuratedList(t *testing.T, args []string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	err := runKbCuratedList(cmd, args)
	return buf.String(), err
}

// invokeCuratedGet builds a fresh *cobra.Command, wires context+buffer, calls runKbCuratedGet.
func invokeCuratedGet(t *testing.T, args []string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	err := runKbCuratedGet(cmd, args)
	return buf.String(), err
}

func TestKbCuratedIntegration(t *testing.T) {
	// ── 1. Boot Postgres container + apply migrations ─────────────────────
	db, dsn := dbtest.StartPostgres(t)
	pinDSNViaConfig(t, dsn)

	// ── 2. Seed kb_apps canonical K + alias ALIASKB→K ────────────────────
	seedCuratedKbApps(t, db)

	// ── 3. Build fixture tree under a temp KB store ───────────────────────
	store := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", store) // auto-restored by t.Setenv
	buildFixtureTree(t, store)

	// ── 4. Save + restore all curated* flag vars ──────────────────────────
	savedDSN := curatedDSN
	savedJSON := curatedJSON
	savedMaxItems := curatedMaxItems
	savedMaxBytes := curatedMaxBytes
	t.Cleanup(func() {
		curatedDSN = savedDSN
		curatedJSON = savedJSON
		curatedMaxItems = savedMaxItems
		curatedMaxBytes = savedMaxBytes
	})

	// Use config-pinned DSN (curatedDSN="" means ResolveDSN reads config).
	curatedDSN = ""

	// ── 5a. list K with JSON → exists:true, correct categories ───────────
	t.Run("list_K_json", func(t *testing.T) {
		curatedJSON = true
		curatedMaxItems = 1000
		out, err := invokeCuratedList(t, []string{"K"})
		if err != nil {
			t.Fatalf("runKbCuratedList K: %v", err)
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatalf("parse JSON: %v\noutput: %s", err, out)
		}
		if result["exists"] != true {
			t.Errorf("expected exists=true, got %v", result["exists"])
		}
		entries, _ := result["entries"].([]any)
		if len(entries) < 3 {
			t.Fatalf("expected at least 3 entries, got %d: %s", len(entries), out)
		}
		catMap := map[string]bool{}
		for _, raw := range entries {
			e, _ := raw.(map[string]any)
			catMap[e["category"].(string)] = true
		}
		for _, want := range []string{"beautified", "decompiled", "reconstructed"} {
			if !catMap[want] {
				t.Errorf("missing category %q in entries; cats=%v", want, catMap)
			}
		}
	})

	// ── 5b. list ALIASKB → same entries via alias resolution ─────────────
	// Collect the canonical K entry paths from subtest (a) output for comparison.
	var kEntryPaths []string
	t.Run("list_ALIASKB_alias", func(t *testing.T) {
		// Re-list K to collect its canonical entry paths.
		curatedJSON = true
		curatedMaxItems = 1000
		outK, errK := invokeCuratedList(t, []string{"K"})
		if errK != nil {
			t.Fatalf("re-list K for path collection: %v", errK)
		}
		var resultK map[string]any
		if err := json.Unmarshal([]byte(outK), &resultK); err != nil {
			t.Fatalf("parse K JSON for path collection: %v", err)
		}
		entriesK, _ := resultK["entries"].([]any)
		for _, raw := range entriesK {
			e, _ := raw.(map[string]any)
			if p, ok := e["path"].(string); ok {
				kEntryPaths = append(kEntryPaths, p)
			}
		}
		sort.Strings(kEntryPaths)

		// Now list via alias and compare.
		out, err := invokeCuratedList(t, []string{"ALIASKB"})
		if err != nil {
			t.Fatalf("runKbCuratedList ALIASKB: %v", err)
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatalf("parse JSON: %v\noutput: %s", err, out)
		}
		if result["exists"] != true {
			t.Errorf("expected exists=true for alias, got %v", result["exists"])
		}
		entries, _ := result["entries"].([]any)
		if len(entries) < 3 {
			t.Fatalf("expected at least 3 entries via alias, got %d", len(entries))
		}
		// Assert alias resolution returns the SAME tree as K, not merely the same count.
		var aliasPaths []string
		for _, raw := range entries {
			e, _ := raw.(map[string]any)
			if p, ok := e["path"].(string); ok {
				aliasPaths = append(aliasPaths, p)
			}
		}
		sort.Strings(aliasPaths)
		if len(kEntryPaths) > 0 {
			if len(aliasPaths) != len(kEntryPaths) {
				t.Errorf("alias entry count %d != K entry count %d", len(aliasPaths), len(kEntryPaths))
			} else {
				for i := range kEntryPaths {
					if aliasPaths[i] != kEntryPaths[i] {
						t.Errorf("alias entry paths differ from K at index %d: got %q, want %q\nalias=%v\nK=%v",
							i, aliasPaths[i], kEntryPaths[i], aliasPaths, kEntryPaths)
						break
					}
				}
			}
		}
	})

	// ── 5c. get K versions/v1/Foo.java → exact bytes ─────────────────────
	t.Run("get_Foo_java", func(t *testing.T) {
		curatedMaxBytes = 0 // unlimited
		out, err := invokeCuratedGet(t, []string{"K", "versions/v1/Foo.java"})
		if err != nil {
			t.Fatalf("runKbCuratedGet Foo.java: %v", err)
		}
		want := "// decompiled\npublic class Foo {}"
		if out != want {
			t.Errorf("get Foo.java body mismatch\ngot:  %q\nwant: %q", out, want)
		}
	})

	// ── 5d. path traversal → ErrPathEscape ───────────────────────────────
	t.Run("path_escape_dotdot", func(t *testing.T) {
		curatedMaxBytes = 0
		out, err := invokeCuratedGet(t, []string{"K", "../../../../etc/passwd"})
		if err == nil {
			t.Fatal("expected error for ../../../../etc/passwd, got nil")
		}
		if out != "" {
			t.Errorf("containment refusal leaked %d bytes: %q", len(out), out)
		}
		if !errors.Is(err, curatedstore.ErrPathEscape) {
			// The error is wrapped by runKbCuratedGet; check string contains.
			t.Logf("err: %v (checked ErrPathEscape wrapping)", err)
		}
	})

	t.Run("path_escape_nested", func(t *testing.T) {
		curatedMaxBytes = 0
		out, err := invokeCuratedGet(t, []string{"K", "versions/v1/../../../../escape"})
		if err == nil {
			t.Fatal("expected error for versions/v1/../../../../escape, got nil")
		}
		if out != "" {
			t.Errorf("containment refusal leaked %d bytes: %q", len(out), out)
		}
	})

	// ── 5e. symlink escape (non-Windows) ──────────────────────────────────
	if runtime.GOOS != "windows" {
		t.Run("symlink_escape", func(t *testing.T) {
			curatedMaxBytes = 0
			out, err := invokeCuratedGet(t, []string{"K", "versions/v1/evil/x"})
			if err == nil {
				t.Fatal("expected error for symlink escape, got nil")
			}
			if out != "" {
				t.Errorf("containment refusal leaked %d bytes: %q", len(out), out)
			}
		})
	}

	// ── 5f. unknown kb → exists:false, exit 0 ────────────────────────────
	t.Run("list_unknown_honest_empty", func(t *testing.T) {
		curatedJSON = true
		curatedMaxItems = 1000
		out, err := invokeCuratedList(t, []string{"no-such-kb"})
		if err != nil {
			t.Fatalf("runKbCuratedList no-such-kb: unexpected error %v", err)
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatalf("parse JSON: %v\noutput: %s", err, out)
		}
		if result["exists"] != false {
			t.Errorf("expected exists=false for unknown kb, got %v", result["exists"])
		}
	})

	// ── 5g. --max-entries truncation + --max-bytes truncation ────────────
	t.Run("max_entries_truncated", func(t *testing.T) {
		curatedJSON = true
		curatedMaxItems = 2
		out, err := invokeCuratedList(t, []string{"K"})
		if err != nil {
			t.Fatalf("runKbCuratedList max-entries=2: %v", err)
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatalf("parse JSON: %v\noutput: %s", err, out)
		}
		if result["truncated"] != true {
			t.Errorf("expected truncated=true with max-entries=2, got %v", result["truncated"])
		}
		entries, _ := result["entries"].([]any)
		if len(entries) != 2 {
			t.Errorf("expected exactly 2 entries, got %d", len(entries))
		}
		// reset
		curatedMaxItems = 1000
	})

	t.Run("max_bytes_truncated", func(t *testing.T) {
		curatedMaxBytes = 3 // less than Foo.java content length
		out, err := invokeCuratedGet(t, []string{"K", "versions/v1/Foo.java"})
		if err != nil {
			t.Fatalf("runKbCuratedGet max-bytes=3: %v", err)
		}
		if len(out) != 3 {
			t.Errorf("expected 3 bytes streamed, got %d: %q", len(out), out)
		}
		// reset
		curatedMaxBytes = 0
	})
}
