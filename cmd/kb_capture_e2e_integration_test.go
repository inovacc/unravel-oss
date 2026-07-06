//go:build integration

/*
Copyright (c) 2026 Security Research

End-to-end integration tests for `unravel kb capture` Phase 35
identity propagation. Verifies that adding top-level platform/
package_id/display_name/publisher to KnowledgeResult unblocks the
kb capture pipeline end-to-end.

These tests drive runKbCapture in-process (NOT the synthetic post-stage
shortcut used by kb_capture_integration_test.go). Real dissect →
Extract → knowledge.json → loadFingerprintInputs → ingest pipeline runs
against the actual fixture binary, so the P35 identity propagation
contract is exercised at the runtime level (not just unit-test level).

Fixture inventory:

	input/fdroid.apk         PRESENT (in repo)   — android / org.fdroid.fdroid / F-Droid / ""
	input/whatsapp.msix      OPTIONAL            — windows / 5319275A.WhatsAppDesktop / WhatsApp / CN=...
	input/teams.msix         OPTIONAL            — windows / MSTeams_8wekyb3d8bbwe / Microsoft Teams / CN=...
	input/dotnet-console.exe OPTIONAL            — windows / <AssemblyName> / <AssemblyName> / ""
	input/sample.ipa         OPTIONAL            — ios / <BundleID> / <CFBundleDisplayName> / <TeamID?>

Manual UAT (Windows host required for UWP/MSIX, macOS+iOS toolchain for IPA):

	1. Place the optional fixture under input/ with the exact name above.
	2. Run: go test -tags=integration -run TestKBCapture_SkipWhenFixtureAbsent ./cmd/ -v -count=1
	3. The corresponding subtest runs the full capture pipeline and asserts
	   platform + package_id from the manifest. Other subtests still SKIP.

Run: `go test -tags=integration ./cmd/... -run TestKBCapture_RealAPK -count=1`
*/

package cmd

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// requireFixture skips the calling test when path does not exist on disk.
// Skip — never Fatal — keeps CI green on machines that lack the optional
// platform fixtures (Windows MSIX / iOS IPA / .NET console artifact).
func requireFixture(t *testing.T, path string) string {
	t.Helper()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		t.Skipf("fixture not present: %s", path)
	} else if err != nil {
		t.Fatalf("stat fixture %s: %v", path, err)
	}
	return path
}

// resolveFixture handles the cwd shift between `go test ./cmd/...` (cwd =
// repo/cmd) and a top-level run. Tries the relative path first, then the
// parent directory. Returns the first existing path or the original.
func resolveFixture(t *testing.T, rel string) string {
	t.Helper()
	if _, err := os.Stat(rel); err == nil {
		return rel
	}
	parent := filepath.Join("..", rel)
	if _, err := os.Stat(parent); err == nil {
		return parent
	}
	return rel
}

// driveKbCapture runs runKbCapture in-process against the given app path,
// pinning UNRAVEL_KB_STORE to a tempdir and UNRAVEL_KB_DSN to the
// testcontainers Postgres DSN. Returns the resulting kb_apps row data.
func driveKbCapture(t *testing.T, ctx context.Context, db *sql.DB, dsn, appPath string) (kbID, platform, packageID, displayName string) {
	t.Helper()

	root := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", root)
	pinDSNViaConfig(t, dsn)

	// Snapshot + restore package-level capture flags so parallel test
	// runs don't bleed state across each other.
	saved := kbCaptureFlags
	t.Cleanup(func() { kbCaptureFlags = saved })
	kbCaptureFlags.tags = nil
	kbCaptureFlags.reason = "p35-e2e-test"
	kbCaptureFlags.by = "executor"
	kbCaptureFlags.jsonOut = false
	kbCaptureFlags.verbose = false
	kbCaptureFlags.force = false

	// Drive the orchestrator. cmd is allowed to be nil because runKbCapture
	// guards the cmd.Context() lookup. We pass kbCaptureCmd so the final
	// printSummary call has an OutOrStdout.
	cmd := kbCaptureCmd
	cmd.SetContext(ctx)
	if err := runKbCapture(cmd, []string{appPath}); err != nil {
		t.Fatalf("runKbCapture(%s): %v", appPath, err)
	}

	// Bound the DB lookup so a hung query doesn't blow the test timeout.
	qctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	row := db.QueryRowContext(qctx,
		`SELECT kb_id, platform, package_id, display_name
		   FROM kb_apps
		  ORDER BY last_seen_at DESC
		  LIMIT 1`)
	var kb sql.NullString
	if err := row.Scan(&kb, &platform, &packageID, &displayName); err != nil {
		t.Fatalf("scan kb_apps row: %v", err)
	}
	if !kb.Valid || kb.String == "" {
		t.Fatalf("kb_apps row has empty kb_id (P35 identity propagation regressed)")
	}
	return kb.String, platform, packageID, displayName
}

// TestKBCapture_RealAPK drives `unravel kb capture` end-to-end against
// the real fdroid.apk fixture. Asserts that Plan 35-01's extractIdentity
// helper produces a knowledge.json with non-empty platform/package_id,
// and that the full pipeline writes a kb_apps row with those values
// (NOT the legacy P34 'unknown' fallback path).
func TestKBCapture_RealAPK(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}

	apkPath := resolveFixture(t, "input/fdroid.apk")
	requireFixture(t, apkPath)

	db, dsn := dbtest.StartPostgres(t)
	ctx := context.Background()

	kbID, platform, packageID, displayName := driveKbCapture(t, ctx, db, dsn, apkPath)

	if platform != "android" {
		t.Errorf("platform: got=%q want=%q (P35 KNID-01 regression)", platform, "android")
	}
	if packageID != "org.fdroid.fdroid" {
		t.Errorf("package_id: got=%q want=%q", packageID, "org.fdroid.fdroid")
	}
	if displayName == "" {
		t.Errorf("display_name should be populated for fdroid.apk; got empty")
	}
	if kbID == "" {
		t.Errorf("kb_id must be non-empty after capture")
	}

	// Negative assertion: confirm the legacy P34 'unknown'-platform
	// fallback was NOT taken. If P35-01's extractIdentity is silently
	// returning empty on android, ingest synthesizes a row with
	// platform='unknown' (D-34-BACKFILL-ID) — that path must remain
	// unreachable for this fixture.
	var unknownRows int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM kb_apps WHERE platform = 'unknown'`).Scan(&unknownRows); err != nil {
		t.Fatalf("count unknown-platform rows: %v", err)
	}
	if unknownRows != 0 {
		t.Errorf("P34 fallback path was taken: %d kb_apps rows have platform='unknown'; expected 0", unknownRows)
	}
}

// TestKBCapture_RealAPK_QuerySurface (Phase 36 Plan 01) drives the FULL
// kb query surface — `kb apps`, `kb timeline`, `kb diff`, `kb search` —
// against the committed input/fdroid.apk fixture. Establishes the
// baseline assertions that every other platform must meet in Plan 36-02:
//
//   - Capture-twice → same kb_id (D-29 idempotent SHA-256[:16] backfill).
//   - kb apps surfaces the captured row with platform/package_id/display_name.
//   - kb timeline returns 2 epoch rows.
//   - kb diff (epoch1 → epoch2) is a typed empty diff (D-36-DIFF-ZERO-NOISE-BASELINE).
//   - kb search returns ≥1 hit for both exact-package and substring-display modes.
//   - Negative: zero kb_apps rows with platform=unknown (P34 fallback unreachable).
func TestKBCapture_RealAPK_QuerySurface(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}

	apkPath := resolveFixture(t, "input/fdroid.apk")
	requireFixture(t, apkPath)

	db, dsn := dbtest.StartPostgres(t)
	ctx := context.Background()

	// Capture #1.
	kbID, platform, packageID, displayName := driveKbCapture(t, ctx, db, dsn, apkPath)
	if kbID == "" {
		t.Fatal("first capture: kb_id empty")
	}
	if platform != "android" {
		t.Errorf("platform: got=%q want=android", platform)
	}
	if packageID != "org.fdroid.fdroid" {
		t.Errorf("package_id: got=%q want=org.fdroid.fdroid", packageID)
	}
	if displayName == "" {
		t.Fatal("display_name empty after first capture")
	}

	// Capture #2 — SAME binary. D-29 guarantees same kb_id.
	kbID2, _, _, _ := driveKbCapture(t, ctx, db, dsn, apkPath)
	if kbID2 != kbID {
		t.Fatalf("D-29 idempotent backfill regression: kb_id1=%q kb_id2=%q (want equal)", kbID, kbID2)
	}

	// --- Query surface drivers ------------------------------------------------

	// 1) kb apps
	apps := driveKbApps(t, ctx, db)
	var matched bool
	for _, row := range apps {
		gotKbID, _ := row["kb_id"].(string)
		if gotKbID != kbID {
			continue
		}
		matched = true
		gotPlatform, _ := row["platform"].(string)
		gotPkg, _ := row["package_id"].(string)
		gotDisplay, _ := row["display_name"].(string)
		if gotPlatform != "android" {
			t.Errorf("kb apps: platform=%q want=android (kb_id == kbID row)", gotPlatform)
		}
		if gotPkg != "org.fdroid.fdroid" {
			t.Errorf("kb apps: package_id=%q want=org.fdroid.fdroid", gotPkg)
		}
		if gotDisplay == "" {
			t.Errorf("kb apps: display_name empty for kb_id == kbID")
		}
	}
	if !matched {
		t.Fatalf("kb apps: no row with kb_id == kbID (=%q); rows=%d", kbID, len(apps))
	}

	// P37 Plan 37-03 depth_covered assertions: fdroid.apk should populate
	// >= 4 dimensions with total > 0 (manifest, dex_classes, dex_methods,
	// permissions at minimum). Per D-37 loud-failure rule, any dimension
	// with total > 0 must have ratio > 0.
	var depthRow map[string]any
	for _, row := range apps {
		if gotKbID, _ := row["kb_id"].(string); gotKbID == kbID {
			depthRow = row
			break
		}
	}
	if depthRow == nil {
		t.Fatalf("kb apps: no row matching kbID for depth_covered assertion")
	}
	depthRaw, ok := depthRow["depth_covered"]
	if !ok {
		t.Fatalf("kb_apps row missing depth_covered field")
	}
	depthArr, ok := depthRaw.([]any)
	if !ok {
		t.Fatalf("depth_covered is not an array, got %T", depthRaw)
	}
	if len(depthArr) < 4 {
		t.Errorf("expected >= 4 depth_covered dimensions for fdroid.apk, got %d", len(depthArr))
	}
	nonZeroDims := 0
	for _, item := range depthArr {
		dim, ok := item.(map[string]any)
		if !ok {
			t.Errorf("depth_covered entry is not an object")
			continue
		}
		total, _ := dim["total"].(float64) // JSON numbers are float64 after Unmarshal
		ratio, _ := dim["ratio"].(float64)
		name, _ := dim["dimension"].(string)
		if total > 0 {
			nonZeroDims++
			if ratio == 0 {
				t.Errorf("dimension %q has total=%v but ratio=0 (loud-failure signal per D-37)", name, total)
			}
		}
	}
	if nonZeroDims < 4 {
		t.Errorf("expected >= 4 non-zero dimensions for fdroid.apk, got %d", nonZeroDims)
	}

	// Negative assertion (preserved from TestKBCapture_RealAPK): no kb_apps
	// row should have platform == "unknown" — the P34 fallback path must
	// remain unreachable for fdroid.apk.
	for _, row := range apps {
		if p, _ := row["platform"].(string); p == "unknown" {
			t.Errorf("kb apps: row with platform=unknown leaked through (P34 fallback path; kb_id=%v)", row["kb_id"])
		}
	}

	// 2) kb timeline
	timeline := driveKbTimeline(t, ctx, db, kbID)
	if len(timeline) < 1 {
		t.Fatalf("kb timeline: expected >=1 epoch row, got %d", len(timeline))
	}
	if len(timeline) != 2 {
		t.Errorf("kb timeline: expected 2 epoch rows after capture-twice, got %d", len(timeline))
	}

	// 3) kb diff (zero-noise baseline)
	diff := driveKbDiff(t, ctx, db, kbID, 1, 2)
	cats, _ := diff["categories"].(map[string]any)
	for catName, raw := range cats {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, change := range []string{"added", "removed", "modified"} {
			arr, _ := c[change].([]any)
			if len(arr) != 0 {
				t.Errorf("kb diff: D-36-DIFF-ZERO-NOISE-BASELINE violated; categories[%q].%s has %d items (want 0)",
					catName, change, len(arr))
			}
		}
	}

	// 4a) kb search — exact-package query.
	searchExact := driveKbSearch(t, ctx, db, "org.fdroid.fdroid", "exact-package")
	if len(searchExact) == 0 {
		t.Errorf("kb search exact-package: zero hits for %q (D-36-SEARCH-STRICT-DUAL violated)", "org.fdroid.fdroid")
	} else {
		topKbID, _ := searchExact[0]["app_kb_id"].(string)
		if topKbID != kbID {
			t.Errorf("kb search exact-package: top hit app_kb_id=%q want kb_id == kbID (=%q)", topKbID, kbID)
		}
	}

	// 4b) kb search — substring-display query (first 3 chars of display name).
	if len(displayName) >= 3 {
		searchSub := driveKbSearch(t, ctx, db, displayName[:3], "substring-display")
		if len(searchSub) == 0 {
			t.Errorf("kb search substring-display: zero hits for %q", displayName[:3])
		} else {
			var anyMatch bool
			for _, hit := range searchSub {
				if appKbID, _ := hit["app_kb_id"].(string); appKbID == kbID {
					anyMatch = true
					break
				}
			}
			if !anyMatch {
				t.Errorf("kb search substring-display: no hit has app_kb_id == kbID (=%q)", kbID)
			}
		}
	}
}

// TestKBCapture_SkipWhenFixtureAbsent exercises the skip mechanism for
// the optional UWP / Electron-MSIX / .NET / iOS fixtures. On a default
// developer machine (only fdroid.apk present), all 4 subtests SKIP —
// that is the EXPECTED behavior and what this test verifies.
//
// When any optional fixture IS present (Windows host with whatsapp.msix,
// for example), the corresponding subtest drives the full capture
// pipeline and asserts platform + package_id from the manifest.
func TestKBCapture_SkipWhenFixtureAbsent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}

	cases := []struct {
		name            string
		path            string
		expectPlatform  string
		expectPackageID string // empty = assert only platform (varies by build)
	}{
		{"UWP_WhatsApp", "input/whatsapp.msix", "windows", "5319275A.WhatsAppDesktop"},
		{"ElectronMSIX_Teams", "input/teams.msix", "windows", "MSTeams_8wekyb3d8bbwe"},
		{"DotNet_Console", "input/dotnet-console.exe", "windows", ""},
		{"iOS_IPA", "input/sample.ipa", "ios", ""},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			path := resolveFixture(t, c.path)
			requireFixture(t, path) // SKIP if absent — primary assertion of this test

			// Optional-success branch: fixture present → drive capture.
			db, dsn := dbtest.StartPostgres(t)
			ctx := context.Background()

			_, platform, packageID, _ := driveKbCapture(t, ctx, db, dsn, path)

			if platform != c.expectPlatform {
				t.Errorf("[%s] platform: got=%q want=%q", c.name, platform, c.expectPlatform)
			}
			if c.expectPackageID != "" && packageID != c.expectPackageID {
				t.Errorf("[%s] package_id: got=%q want=%q", c.name, packageID, c.expectPackageID)
			}
		})
	}
}
