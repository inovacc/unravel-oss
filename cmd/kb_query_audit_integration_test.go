//go:build integration

/*
Copyright (c) 2026 Security Research

Phase 36 Plan 02: Multi-platform UAT scaffold.

Drives `unravel kb capture` plus the full kb query surface (apps /
timeline / diff / search) against env-var-resolved fixtures for the four
non-APK platforms tracked by CAPE-02..05:

  - UWP-WhatsApp           UNRAVEL_TEST_WHATSAPP_MSIX
  - Electron-MSIX-Teams    UNRAVEL_TEST_TEAMS_MSIX
  - .NET console           UNRAVEL_TEST_DOTNET_EXE
  - iOS IPA                UNRAVEL_TEST_IOS_IPA

Skip-when-fixture-absent: per D-36-FIXTURE-ENV-VARS each subtest reads ONE
env var. If it is unset OR the file does not exist, the subtest skips.
On default dev hosts (no env vars set) all four subtests skip cleanly and
the parent test passes.

Reuses Plan 36-01 helpers (driveKbApps / driveKbTimeline / driveKbDiff /
driveKbSearch in kb_query_audit_helpers_integration_test.go) and the
P35-02 driveKbCapture helper from kb_capture_e2e_integration_test.go.
*/

package cmd

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// platformUATCase pins the per-platform expectations driving the
// table-driven TestKBCapture_AllPlatforms_QuerySurface test below.
type platformUATCase struct {
	name              string // subtest name, e.g. "UWP_WhatsApp"
	envVar            string // e.g. "UNRAVEL_TEST_WHATSAPP_MSIX"
	expectedPlatform  string // "windows" | "ios" | "android"
	packageIDRegex    string // anchored regex matched against kb_apps.package_id
	displayNameSubstr int    // leading-char count for substring-display search query (3 by default)
}

// allPlatformCases captures the 4 non-APK platforms covered by CAPE-02..05.
//
// Per <must_haves> in 36-02-multiplatform-uat-scaffold-PLAN.md:
//   - UWP WhatsApp           → (windows, ^5319275A\.WhatsAppDesktop)
//   - Electron-MSIX Teams    → (windows, ^MSTeams_8wekyb3d8bbwe$ | ^MicrosoftTeams)
//   - .NET console           → (windows, non-empty)
//   - iOS IPA                → (ios,     non-empty)
var allPlatformCases = []platformUATCase{
	{
		name:              "UWP_WhatsApp",
		envVar:            "UNRAVEL_TEST_WHATSAPP_MSIX",
		expectedPlatform:  "windows",
		packageIDRegex:    `^5319275A\.WhatsAppDesktop`,
		displayNameSubstr: 3,
	},
	{
		name:              "ElectronMSIX_Teams",
		envVar:            "UNRAVEL_TEST_TEAMS_MSIX",
		expectedPlatform:  "windows",
		packageIDRegex:    `^MSTeams_8wekyb3d8bbwe$|^MicrosoftTeams`,
		displayNameSubstr: 3,
	},
	{
		name:              "DotNet_Console",
		envVar:            "UNRAVEL_TEST_DOTNET_EXE",
		expectedPlatform:  "windows",
		packageIDRegex:    `.+`,
		displayNameSubstr: 3,
	},
	{
		name:              "iOS_IPA",
		envVar:            "UNRAVEL_TEST_IOS_IPA",
		expectedPlatform:  "ios",
		packageIDRegex:    `.+`,
		displayNameSubstr: 3,
	},
}

// TestKBCapture_AllPlatforms_QuerySurface drives the full capture +
// query-surface assertion stack for the 4 non-APK platforms. Shares ONE
// Postgres testcontainer across all subtests to bound runtime <300s
// (per T-36-06 in the plan threat model).
func TestKBCapture_AllPlatforms_QuerySurface(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}

	// Pre-flight: if NO env vars are set (default dev box), skip Postgres
	// startup entirely. testcontainers Postgres is expensive (~5s); avoid
	// paying it just to run 4 nested t.Skipf calls.
	anySet := false
	for _, tc := range allPlatformCases {
		if os.Getenv(tc.envVar) != "" {
			anySet = true
			break
		}
	}
	if !anySet {
		t.Skipf("none of the platform env vars set; skipping multi-platform UAT (set any of %s/%s/%s/%s to enable)",
			allPlatformCases[0].envVar,
			allPlatformCases[1].envVar,
			allPlatformCases[2].envVar,
			allPlatformCases[3].envVar)
	}

	db, dsn := dbtest.StartPostgres(t)
	ctx := context.Background()

	for _, tc := range allPlatformCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			path := os.Getenv(tc.envVar)
			if path == "" {
				t.Skipf("set %s to enable %s subtest", tc.envVar, tc.name)
			}
			requireFixture(t, path)

			// Capture-twice to exercise D-29 idempotent backfill + seed
			// kb_diff zero-noise baseline (D-36-DIFF-ZERO-NOISE-BASELINE).
			kbID1, _, _, _ := driveKbCapture(t, ctx, db, dsn, path)
			kbID2, _, _, _ := driveKbCapture(t, ctx, db, dsn, path)
			if kbID1 == "" {
				t.Fatalf("[%s] first capture: kb_id empty", tc.name)
			}
			if kbID1 != kbID2 {
				t.Fatalf("[%s] D-29 idempotent backfill regression: kb_id1=%q kb_id2=%q",
					tc.name, kbID1, kbID2)
			}

			// kb apps: locate row matching kb_id1 and assert platform + package_id.
			apps := driveKbApps(t, ctx, db)
			var matchedRow map[string]any
			for _, row := range apps {
				if got, _ := row["kb_id"].(string); got == kbID1 {
					matchedRow = row
					break
				}
			}
			if matchedRow == nil {
				t.Fatalf("[%s] kb apps: no row with kb_id == kbID1 (=%q)", tc.name, kbID1)
			}
			gotPlatform, _ := matchedRow["platform"].(string)
			if gotPlatform != tc.expectedPlatform {
				t.Errorf("[%s] platform: got=%q want=%q", tc.name, gotPlatform, tc.expectedPlatform)
			}
			gotPkg, _ := matchedRow["package_id"].(string)
			if !regexp.MustCompile(tc.packageIDRegex).MatchString(gotPkg) {
				t.Errorf("[%s] package_id: got=%q does not match %q", tc.name, gotPkg, tc.packageIDRegex)
			}
			displayName, _ := matchedRow["display_name"].(string)
			if displayName == "" {
				t.Errorf("[%s] display_name empty for kb_id == kbID1", tc.name)
			}

			// P38 Plan 38-03: depth_covered assertions per Windows-stack
			// subtest. D-38-DIMENSIONS-PER-STACK requires uwp.* dimensions
			// for UWP-WhatsApp and BOTH uwp.* + electron.* for hybrid
			// Electron-MSIX (Teams) per D-38-HYBRID-DUAL-COVERAGE.
			if tc.expectedPlatform == "windows" {
				depthRaw, _ := matchedRow["depth_covered"].([]any)
				var uwpHits, electronHits, webview2Hits int
				var loudFailures []string
				for _, item := range depthRaw {
					dim, ok := item.(map[string]any)
					if !ok {
						continue
					}
					name, _ := dim["dimension"].(string)
					total, _ := dim["total"].(float64)
					ratio, _ := dim["ratio"].(float64)
					if total > 0 {
						switch {
						case strings.HasPrefix(name, "uwp.") || strings.HasPrefix(name, "winui."):
							uwpHits++
						case strings.HasPrefix(name, "electron."):
							electronHits++
						case strings.HasPrefix(name, "webview2."):
							webview2Hits++
						}
						if ratio == 0 {
							loudFailures = append(loudFailures, name)
						}
					}
				}
				_ = webview2Hits // surface for potential future asserts; no failure today
				if len(loudFailures) > 0 {
					t.Errorf("[%s] dimensions with total>0 but ratio==0 (D-37 loud failure): %v",
						tc.name, loudFailures)
				}
				switch tc.name {
				case "UWP_WhatsApp":
					if uwpHits < 3 {
						t.Errorf("[UWP_WhatsApp] expected >=3 uwp.* dimensions with total>0, got %d",
							uwpHits)
					}
				case "ElectronMSIX_Teams":
					if uwpHits < 1 {
						t.Errorf("[ElectronMSIX_Teams] expected >=1 uwp.* dimension (hybrid), got %d",
							uwpHits)
					}
					if electronHits < 1 {
						t.Errorf("[ElectronMSIX_Teams] expected >=1 electron.* dimension (hybrid D-38), got %d",
							electronHits)
					}
				}
				// DotNet_Console: depth_covered may be empty (.NET wire-up
				// is v2.7+); no fail-loud assertion here.
			}
			// iOS_IPA: depth_covered may be empty (iOS wire-up is v2.7+).

			// kb timeline: 2 epoch rows.
			timeline := driveKbTimeline(t, ctx, db, kbID1)
			if len(timeline) != 2 {
				t.Errorf("[%s] kb timeline: got=%d epoch rows want=2", tc.name, len(timeline))
			}

			// kb diff: D-36-DIFF-ZERO-NOISE-BASELINE.
			diff := driveKbDiff(t, ctx, db, kbID1, 1, 2)
			cats, _ := diff["categories"].(map[string]any)
			for catName, raw := range cats {
				c, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				for _, change := range []string{"added", "removed", "modified"} {
					arr, _ := c[change].([]any)
					if len(arr) != 0 {
						t.Errorf("[%s] kb diff: D-36-DIFF-ZERO-NOISE-BASELINE violated; categories[%q].%s has %d items (want 0)",
							tc.name, catName, change, len(arr))
					}
				}
			}

			// kb search exact-package: D-36-SEARCH-STRICT-DUAL — empty = FAIL.
			searchExact := driveKbSearch(t, ctx, db, gotPkg, "exact-package")
			if len(searchExact) == 0 {
				t.Errorf("[%s] kb search exact-package(%q): zero hits (D-36-SEARCH-STRICT-DUAL violated)",
					tc.name, gotPkg)
			} else {
				topKbID, _ := searchExact[0]["app_kb_id"].(string)
				if topKbID != kbID1 {
					t.Errorf("[%s] kb search exact-package: top hit app_kb_id=%q want=%q",
						tc.name, topKbID, kbID1)
				}
			}

			// kb search substring-display: D-36-SEARCH-STRICT-DUAL — empty = FAIL.
			n := tc.displayNameSubstr
			if n <= 0 {
				n = 3
			}
			if len(displayName) >= n {
				query := displayName[:n]
				searchSub := driveKbSearch(t, ctx, db, query, "substring-display")
				if len(searchSub) == 0 {
					t.Errorf("[%s] kb search substring-display(%q): zero hits (D-36-SEARCH-STRICT-DUAL violated)",
						tc.name, query)
				} else {
					var anyMatch bool
					for _, hit := range searchSub {
						if appKbID, _ := hit["app_kb_id"].(string); appKbID == kbID1 {
							anyMatch = true
							break
						}
					}
					if !anyMatch {
						t.Errorf("[%s] kb search substring-display: no hit has app_kb_id == kbID1 (=%q)",
							tc.name, kbID1)
					}
				}
			}
		})
	}

	// Cross-subtest negative assertion: scan the shared kb_apps table
	// after all subtests have run; zero rows must have platform=='unknown'
	// (P34 fallback path provably unreachable for any P36 platform).
	apps := driveKbApps(t, ctx, db)
	for _, row := range apps {
		if p, _ := row["platform"].(string); p == "unknown" {
			t.Errorf("post-subtest sweep: kb_apps row with platform=unknown leaked through (P34 fallback; kb_id=%v)",
				row["kb_id"])
		}
	}
}
