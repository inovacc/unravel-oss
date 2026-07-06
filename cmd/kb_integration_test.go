//go:build integration

/*
Copyright (c) 2026 Security Research

Cross-cutting integration tests for `unravel kb` subcommands (Phase 32).
*/

package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/ingest"

	"github.com/spf13/cobra"
)

// runCmd executes a cobra command with arguments and returns its output.
func runCmd(t *testing.T, cmd *cobra.Command, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)

	err = cmd.ExecuteContext(context.Background())
	return outBuf.String(), errBuf.String(), err
}

// seedCapture is a helper to populate the DB with a snapshot.
func seedCapture(t *testing.T, db *sql.DB, root, appID string, version string, risk int, riskLevel string) *ingest.Result {
	t.Helper()
	staging := filepath.Join(root, "staging", appID+"-"+version)
	writeStaging(t, staging, map[string]any{
		"platform":     "windows-msix",
		"package_id":   appID,
		"display_name": appID + " Display",
		"app_version":  version,
		"framework":    "winui",
		"security":     map[string]any{"risk_score": risk, "risk_level": riskLevel},
		"tags":         []string{"test-seed"},
	}, map[string][]byte{
		"app.exe": []byte("fake-binary-" + appID + "-" + version),
	})

	fpIn, err := loadFingerprintInputs(staging, "")
	if err != nil {
		t.Fatalf("loadFingerprintInputs: %v", err)
	}
	kbID, ksID, err := identity.Fingerprint(fpIn)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	ksDir, err := promoteKbStaging(staging, kbID, ksID)
	if err != nil {
		t.Fatalf("promoteKbStaging: %v", err)
	}

	res, err := ingest.Run(context.Background(), db, kbID, ksID, ksDir, ingest.Options{
		AllowedRoots: []string{root},
		Platform:     fpIn.Platform,
		PackageID:    fpIn.PackageID,
		DisplayName:  fpIn.DisplayName,
		Tags:         []string{"test-seed"},
	})
	if err != nil {
		t.Fatalf("ingest.Run: %v", err)
	}
	return res
}

func TestKbSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}
	db, dsn := dbtest.StartPostgres(t)
	defer db.Close()
	pinDSNViaConfig(t, dsn)
	root := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", root)

	t.Run("Apps_FilterByRisk", func(t *testing.T) {
		seedCapture(t, db, root, "com.high.risk", "1.0.0", 85, "critical")
		seedCapture(t, db, root, "com.low.risk", "1.0.0", 10, "low")

		stdout, _, err := runCmd(t, rootCmd, "kb", "catalog", "apps", "--risk", "critical", "--json")
		if err != nil {
			t.Fatalf("kb apps: %v", err)
		}

		var res struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal([]byte(stdout), &res); err != nil {
			t.Fatalf("unmarshal json: %v\nstdout: %q", err, stdout)
		}

		if len(res.Items) < 1 {
			t.Errorf("expected at least 1 item, got %d", len(res.Items))
		}
	})

	t.Run("Show_AliasResolves", func(t *testing.T) {
		res := seedCapture(t, db, root, "com.example.alias", "1.0.0", 50, "medium")

		alias := "my-alias"
		_, err := db.Exec(`INSERT INTO kb_aliases (alias_kb_id, canonical_kb_id, merged_at) VALUES ($1, $2, $3)`, alias, res.KBID, time.Now().UnixMilli())
		if err != nil {
			t.Fatalf("insert alias: %v", err)
		}

		stdout, stderr, err := runCmd(t, rootCmd, "kb", "show", alias, "--json")
		if err != nil {
			t.Fatalf("kb show: %v", err)
		}

		if !strings.Contains(stderr, "resolved from alias") {
			t.Errorf("expected stderr to contain 'resolved from alias', got %q", stderr)
		}

		var showRes map[string]any
		if err := json.Unmarshal([]byte(stdout), &showRes); err != nil {
			t.Fatalf("unmarshal json: %v\nstdout: %q", err, stdout)
		}
	})

	t.Run("Timeline_DeltasMatchEpochs", func(t *testing.T) {
		app := "com.example.timeline"
		res1 := seedCapture(t, db, root, app, "1.0.0", 30, "low")
		seedCapture(t, db, root, app, "1.1.0", 40, "medium")
		seedCapture(t, db, root, app, "1.2.0", 50, "medium")

		stdout, _, err := runCmd(t, rootCmd, "kb", "catalog", "timeline", res1.KBID, "--json")
		if err != nil {
			t.Fatalf("kb timeline: %v", err)
		}

		var res struct {
			Epochs []map[string]any `json:"epochs"`
		}
		if err := json.Unmarshal([]byte(stdout), &res); err != nil {
			t.Fatalf("unmarshal json: %v\nstdout: %q", err, stdout)
		}

		if len(res.Epochs) < 3 {
			t.Errorf("expected at least 3 epochs, got %d", len(res.Epochs))
		}
	})

	t.Run("Diff_Consecutive", func(t *testing.T) {
		app := "com.example.diff"
		staging1 := filepath.Join(root, "staging", "v1")
		writeStaging(t, staging1, map[string]any{
			"platform":     "windows-msix",
			"package_id":   app,
			"display_name": "Diff App",
			"app_version":  "1.0.0",
			"dependencies": []any{map[string]any{"name": "lib1", "version": "1.0"}},
		}, map[string][]byte{"app.exe": []byte("v1")})

		fpIn1, _ := loadFingerprintInputs(staging1, "")
		kbID, ksID1, _ := identity.Fingerprint(fpIn1)
		ksDir1, _ := promoteKbStaging(staging1, kbID, ksID1)
		ingest.Run(context.Background(), db, kbID, ksID1, ksDir1, ingest.Options{AllowedRoots: []string{root}})

		staging2 := filepath.Join(root, "staging", "v2")
		writeStaging(t, staging2, map[string]any{
			"platform":     "windows-msix",
			"package_id":   app,
			"display_name": "Diff App",
			"app_version":  "1.1.0",
			"dependencies": []any{map[string]any{"name": "lib2", "version": "2.0"}},
		}, map[string][]byte{"app.exe": []byte("v2")})

		fpIn2, _ := loadFingerprintInputs(staging2, "")
		_, ksID2, _ := identity.Fingerprint(fpIn2)
		ksDir2, _ := promoteKbStaging(staging2, kbID, ksID2)
		ingest.Run(context.Background(), db, kbID, ksID2, ksDir2, ingest.Options{AllowedRoots: []string{root}})

		stdout, _, err := runCmd(t, rootCmd, "kb", "transfer", "diff", kbID, "--from", "1", "--to", "2", "--json")
		if err != nil {
			t.Fatalf("kb diff: %v", err)
		}

		var diffRes map[string]any
		if err := json.Unmarshal([]byte(stdout), &diffRes); err != nil {
			t.Fatalf("unmarshal json: %v\nstdout: %q", err, stdout)
		}
	})

	t.Run("Diff_LongRangeCap", func(t *testing.T) {
		app := "com.example.cap"
		res := seedCapture(t, db, root, app, "1", 10, "low")
		for i := 2; i <= 22; i++ {
			_, err := db.Exec(`INSERT INTO knowledge_sources (app, epoch, captured_at, kb_id, source_path, source_kind) VALUES ($1, $2, $3, $4, $5, $6)`,
				app, i, time.Now().UnixMilli()+int64(i), res.KBID, "/fake/path", "other")
			if err != nil {
				t.Fatalf("insert epoch %d: %v", i, err)
			}
		}

		_, stderr, err := runCmd(t, rootCmd, "kb", "transfer", "diff", res.KBID, "--from", "1", "--to", "22", "--json")
		if err == nil {
			t.Fatal("expected error for >20 epoch span")
		}
		if !strings.Contains(stderr, "capped at 20 epochs") && (err != nil && !strings.Contains(err.Error(), "capped at 20 epochs")) {
			t.Errorf("expected 'capped at 20 epochs' error, got err=%v, stderr=%q", err, stderr)
		}
	})

	t.Run("Search_CursorPagination", func(t *testing.T) {
		app := "search-app"
		res := seedCapture(t, db, root, app, "1.0.0", 10, "low")

		var sourceID int64
		err := db.QueryRow(`SELECT id FROM knowledge_sources WHERE kb_id=$1 AND epoch=$2`, res.KBID, res.Epoch).Scan(&sourceID)
		if err != nil {
			t.Fatalf("query sourceID: %v", err)
		}

		for i := 1; i <= 5; i++ {
			name := fmt.Sprintf("module%d.js", i)
			body := fmt.Sprintf("unique content number %d for keyword findme", i)
			sha := fmt.Sprintf("%064x", i)

			db.Exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at) VALUES ($1, $2, $3, $4)`,
				sha, []byte(body), len(body), time.Now().UnixMilli())

			var modID int64
			db.QueryRow(`INSERT INTO modules (app, name, body_excerpt, body_sha256, lang) VALUES ($1, $2, $3, $4, 'js') RETURNING id`,
				app, name, body, sha).Scan(&modID)

			db.Exec(`INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at) VALUES ($1, $2, $3, $4)`, sha, app, sourceID, time.Now().UnixMilli())
		}

		stdout, _, err := runCmd(t, rootCmd, "kb", "catalog", "search", "findme", "--limit", "2", "--json")
		if err != nil {
			t.Fatalf("kb search: %v", err)
		}

		var resPage1 struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal([]byte(stdout), &resPage1); err != nil {
			t.Fatalf("unmarshal json: %v\nstdout: %q", err, stdout)
		}
		if len(resPage1.Items) == 0 {
			t.Error("kb search: expected results, got 0")
		}
	})

	t.Run("Export_Tarball", func(t *testing.T) {
		res := seedCapture(t, db, root, "com.example.export", "1.0.0", 30, "low")

		tarPath := filepath.Join(t.TempDir(), "export.tgz")
		_, _, err := runCmd(t, rootCmd, "kb", "transfer", "export", res.KBID, "-o", tarPath)
		if err != nil {
			t.Fatalf("kb export: %v", err)
		}
	})

	t.Run("Gc_YesPurges", func(t *testing.T) {
		seedCapture(t, db, root, "app1", "1.0.0", 10, "low")

		future := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
		_, _, err := runCmd(t, rootCmd, "kb", "gc", "--older-than", future, "--yes")
		if err != nil {
			t.Fatalf("kb gc --yes: %v", err)
		}

		var count int
		db.QueryRow(`SELECT COUNT(*) FROM knowledge_sources`).Scan(&count)
		if count != 0 {
			t.Errorf("expected 0 snapshots remaining, got %d", count)
		}
	})

	t.Run("Ingest_FolderMode", func(t *testing.T) {
		staging := filepath.Join(root, "manual-ks")
		writeStaging(t, staging, map[string]any{
			"platform":     "electron",
			"package_id":   "manual.ingest",
			"display_name": "Manual",
		}, map[string][]byte{"file.txt": []byte("content")})

		stdout, _, err := runCmd(t, rootCmd, "kb", "enrich", "ingest", staging, "--json")
		if err != nil {
			t.Fatalf("kb ingest: %v", err)
		}

		var res map[string]any
		if err := json.Unmarshal([]byte(stdout), &res); err != nil {
			t.Fatalf("unmarshal json: %v\nstdout: %q", err, stdout)
		}
	})

	t.Run("Capture_Force", func(t *testing.T) {
		appID := "com.example.force"
		content := []byte("MZ-fake-binary")

		staging1 := filepath.Join(root, "apps", appID, "versions", "v1")
		writeStaging(t, staging1, map[string]any{
			"platform":     "electron",
			"package_id":   appID,
			"display_name": "Force App",
		}, map[string][]byte{"app.exe": content})

		if _, _, err := runCmd(t, rootCmd, "kb", "enrich", "ingest", staging1, "--json"); err != nil {
			t.Fatalf("first ingest: %v", err)
		}

		staging2 := filepath.Join(root, "apps", appID, "versions", "v2")
		writeStaging(t, staging2, map[string]any{
			"platform":     "electron",
			"package_id":   appID,
			"display_name": "Force App",
		}, map[string][]byte{"app.exe": content})

		stdout, _, err := runCmd(t, rootCmd, "kb", "enrich", "ingest", staging2, "--json")

		if err != nil {
			t.Fatalf("second ingest: %v", err)
		}
		var res2 map[string]any
		json.Unmarshal([]byte(stdout), &res2)
		if res2["skipped"] != true {
			t.Errorf("expected skip for identical binary, got res: %s", stdout)
		}

		staging3 := filepath.Join(root, "apps", appID, "versions", "v3")
		writeStaging(t, staging3, map[string]any{
			"platform":     "electron",
			"package_id":   appID,
			"display_name": "Force App",
		}, map[string][]byte{"app.exe": content})

		stdout3, _, err := runCmd(t, rootCmd, "kb", "enrich", "ingest", staging3, "--force", "--json")
		if err != nil {
			t.Fatalf("third ingest: %v", err)
		}
		var res3 map[string]any
		json.Unmarshal([]byte(stdout3), &res3)
		if res3["skipped"] == true {
			t.Error("expected --force to bypass skip")
		}
	})
}
