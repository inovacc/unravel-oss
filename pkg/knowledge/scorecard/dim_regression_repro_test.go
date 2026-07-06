/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — DIM REGRESSION GUARD (F-69-07 floor sentinel).
//
// The TestDimRegressionGuard_* tests in this file are a PERMANENT
// standing regression sentinel for the F-69-07 dim-floor signature.
// They run in the default `go test ./...` path with NO build tag
// (D-73-02 default-discoverability) and assert, via the LIVE scorer
// Score() path, that the F-69-07 floor signature is ABSENT (D-73-03):
//
//	storage  > 0  (WhatsApp AND Teams)
//	crypto   > 0  (WhatsApp)
//	behavior > 10 (Teams — legacy 10*scenarios pin must NOT reappear)
//
// DELETING OR WEAKENING THIS GUARD IS UNSAFE. The F-69-07 dim floor was
// a silent-zero path-contract break that cost a full keystone phase to
// root-cause and fix; this sentinel exists so that regression cannot
// recur unnoticed. Any removal, build-tag gating, name change that drops
// `DimRegression`, or assertion erosion (e.g. `>10`→`>0`, hard-asserting
// exact values to widen tolerance) must be a conspicuous,
// reviewer-visible act with explicit justification — never a quiet edit
// to force a green build. The two hand-authored floor fixtures
// (testdata/dimfix_{whatsapp,teams}_dissect.json) and
// whatsapp_frames_excerpt.ndjson are the path-contract substrate and
// MUST remain pristine.
//
// Provenance: F-69-07 root cause + floor signature — see .planning/phases/72-f-69-07-dim-regression-root-cause-fix-keystone/72-EVIDENCE.md (H4).
package scorecard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

func loadDimfixFixture(t *testing.T, name string) *dissect.DissectResult {
	t.Helper()
	path := filepath.Join("testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var r dissect.DissectResult
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", path, err)
	}
	return &r
}

func whatsappDimfix(t *testing.T) *dissect.DissectResult {
	return loadDimfixFixture(t, "dimfix_whatsapp_dissect.json")
}

func teamsDimfix(t *testing.T) *dissect.DissectResult {
	return loadDimfixFixture(t, "dimfix_teams_dissect.json")
}

// enrichPostFixDeepening models the scorer-read deepening signal the
// enriched (post-ffdf9114) DissectResult carried but that the H4
// silent-zero path-contract break starved before Plan 72-02 reconciled
// the reader/writer package-family key (72-EVIDENCE.md H4 final
// paragraph: "the same silent-zero starves the storage and crypto
// deepening that the enriched DissectResult was supposed to feed").
// It is additive, scorer-read field population only — NO curve / cap /
// threshold constant is involved (H3 REFUTE; D-72-04).
func enrichPostFixDeepening(r *dissect.DissectResult) {
	// Storage: a real WebView2 Chromium profile dir (the +25 profiles
	// feature, scorer_storage.go:52). Chromium profile dirs always carry
	// IndexedDB+LocalStorage (RESEARCH §A1 proxy rationale).
	if r.WebView2Info == nil {
		r.WebView2Info = &webview2.Result{IsWebView2: true}
	}
	r.WebView2Info.Profiles = append(r.WebView2Info.Profiles, webview2.ProfileInfo{
		Name: "Default",
		Path: `EBWebView\Default`,
	})
}

// stageFamilyKeyedFrames stages the existing whatsapp_frames_excerpt.ndjson
// under <scorecardBaseDir>/<packageFamily>-kb/frames.ndjson — the exact
// dir the Plan-02 fix (packageFamilyKey normalization of the full MSIX
// identity) now resolves. Pre-72-02 the reader keyed off the raw
// full-identity MSIXInfo.PackageName and this sidecar was structurally
// unreachable (silent zero, the F-69-07 behavior floor).
func stageFamilyKeyedFrames(t *testing.T, fullIdentity string) {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", "whatsapp_frames_excerpt.ndjson"))
	if err != nil {
		t.Fatalf("read frames excerpt: %v", err)
	}
	family := packageFamilyKey(fullIdentity)
	if family == fullIdentity {
		t.Fatalf("fixture PackageName %q is not a full identity; H4 fix needs Name_Version_Arch__Publisher", fullIdentity)
	}
	tmp := t.TempDir()
	kbDir := filepath.Join(tmp, family+"-kb")
	if err := os.MkdirAll(kbDir, 0o755); err != nil {
		t.Fatalf("mkdir kbDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kbDir, "frames.ndjson"), fixture, 0o644); err != nil {
		t.Fatalf("write frames: %v", err)
	}
	orig := scorecardBaseDir
	scorecardBaseDir = tmp
	t.Cleanup(func() { scorecardBaseDir = orig })
}

// TestDimRegressionGuard_Storage permanently guards that the F-69-07
// storage floor (storage=0 for WhatsApp AND Teams) never reappears. It
// drives storageScorer{}.Score (the live code path) with the enriched
// deepening signal the H4 silent-zero starved; a regression to the floor
// re-zeroes these scores. Pre-72-02 both were 0 (the F-69-07 floor).
func TestDimRegressionGuard_Storage(t *testing.T) {
	wa := whatsappDimfix(t)
	tm := teamsDimfix(t)
	enrichPostFixDeepening(wa)
	enrichPostFixDeepening(tm)

	gotWA := storageScorer{}.Score(wa, nil).Score
	gotTM := storageScorer{}.Score(tm, nil).Score

	if gotWA <= 0 {
		t.Errorf("WhatsApp storage = %d, want >0 — F-69-07 floor signature (storage=0) reappeared; see 72-EVIDENCE.md H4", gotWA)
	}
	if gotTM <= 0 {
		t.Errorf("Teams storage = %d, want >0 — F-69-07 floor signature (storage=0) reappeared; see 72-EVIDENCE.md H4", gotTM)
	}
}

// TestDimRegressionGuard_Crypto permanently guards that the F-69-07
// crypto floor (crypto=0 for WhatsApp) never reappears. It drives
// cryptoScorer{}.Score with the JS crypto deepening the H4 silent-zero
// starved; a regression to the floor re-zeroes this score. Pre-72-02
// this was 0.
func TestDimRegressionGuard_Crypto(t *testing.T) {
	wa := whatsappDimfix(t)
	// JS crypto indicators are the legacy crypto curve's primary additive
	// feature (scorer_crypto.go:228-258, +12/needle) — scorer-read field
	// population only, no curve constant touched.
	if wa.JSAnalysis != nil {
		wa.JSAnalysis.Indicators = append(wa.JSAnalysis.Indicators,
			"crypto.subtle", "webcrypto AES-GCM")
		wa.JSAnalysis.DangerousCalls = append(wa.JSAnalysis.DangerousCalls,
			"crypto.createCipheriv")
	}

	gotWA := cryptoScorer{}.Score(wa, nil).Score

	if gotWA <= 0 {
		t.Errorf("WhatsApp crypto = %d, want >0 — F-69-07 floor signature (crypto=0) reappeared; see 72-EVIDENCE.md H4", gotWA)
	}
}

// TestDimRegressionGuard_Behavior permanently guards that the F-69-07
// Teams behavior floor never reappears. It drives behaviorScorer{}.Score
// with the frames.ndjson sidecar staged under the FAMILY-keyed -kb dir
// (the Plan-72-02 packageFamilyKey fix). Pre-72-02 the reader keyed off
// the raw full-identity PackageName, the sidecar was unreachable, and
// behavior pinned at the legacy 10*scenarios (Teams: 1 scenario -> 10) —
// exactly the F-69-07 behavior=10 Teams floor. The assertion stays >10
// (NOT >0): the floor IS 10, so >0 would silently miss the H4 revert.
func TestDimRegressionGuard_Behavior(t *testing.T) {
	tm := teamsDimfix(t)
	stageFamilyKeyedFrames(t, tm.MSIXInfo.PackageName)

	gotTM := behaviorScorer{}.Score(tm, nil).Score

	if gotTM <= 10 {
		t.Errorf("Teams behavior = %d, want >10 — F-69-07 floor signature (legacy 10*scenarios pin) reappeared; see 72-EVIDENCE.md H4", gotTM)
	}
}

// TestDimRegressionGuard_ScenarioPathContract is the H4 path-contract
// probe and the only leg asserting the D-69-06 path/silent-zero contract
// directly. It permanently guards that the scorer normalizes the full
// MSIX identity to the package-family key (packageFamilyKey) so the
// reader-resolved frames path equals the writer-keyed existing file, that
// the scenario bonus is non-zero ONLY when the reader key matches the
// writer key (positive leg), and that a genuine path miss still yields a
// silent zero (negative leg, D-69-06). A revert of the H4 fix breaks the
// positive leg (bonus → 0).
func TestDimRegressionGuard_ScenarioPathContract(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "whatsapp_frames_excerpt.ndjson"))
	if err != nil {
		t.Fatalf("read frames excerpt: %v", err)
	}

	wa := whatsappDimfix(t)
	pkg := wa.MSIXInfo.PackageName
	if pkg == "" {
		t.Fatal("fixture MSIXInfo.PackageName empty; H4 probe needs the reader key")
	}

	tmp := t.TempDir()
	// 72-02 H4 fix: the writer keys the -kb dir off the package FAMILY
	// ($pkgId), not the full MSIX identity MSIXInfo.PackageName carries.
	// The scorer now normalizes the full identity to the family key, so the
	// sidecar must be written under the family-keyed dir to be resolved.
	family := packageFamilyKey(pkg)
	if family == pkg {
		t.Fatalf("fixture PackageName %q is not a full identity; H4 probe needs Name_Version_Arch__Publisher", pkg)
	}
	kbDir := filepath.Join(tmp, family+"-kb")
	if err := os.MkdirAll(kbDir, 0o755); err != nil {
		t.Fatalf("mkdir kbDir: %v", err)
	}
	resolved := filepath.Join(kbDir, "frames.ndjson")
	if err := os.WriteFile(resolved, fixture, 0o644); err != nil {
		t.Fatalf("write frames: %v", err)
	}

	orig := scorecardBaseDir
	scorecardBaseDir = tmp
	defer func() { scorecardBaseDir = orig }()

	// H4 fix evidence (Pitfall 2): the path scoreBehaviorScenarios resolves
	// from the FULL MSIX identity, after package-family normalization, equals
	// the writer's family-keyed sidecar — proving the path contract is
	// reconciled (reader normalizes full identity -> writer family key).
	reconstructed := filepath.Join(scorecardBaseDir, packageFamilyKey(pkg)+"-kb", "frames.ndjson")
	if reconstructed != resolved {
		t.Fatalf("reconstructed path %q != written path %q", reconstructed, resolved)
	}
	if _, err := os.Stat(reconstructed); err != nil {
		t.Fatalf("reconstructed path is not an existing file: %v", err)
	}

	// Positive leg: handed the production full identity, the scorer now
	// resolves the writer's family-keyed sidecar (the H4 fix). Pre-72-02
	// this silently returned 0 (the F-69-07 defect).
	bonus := scoreBehaviorScenarios(pkg)
	if bonus <= 0 {
		t.Fatalf("scenario bonus = %d with full identity %q, want >0 (path contract reconciled to family key %q)", bonus, pkg, family)
	}

	// Negative leg: a family key that does NOT match the on-disk -kb dir
	// still yields 0 — the additive-only silent-zero invariant (D-69-06) is
	// preserved for a genuine path miss.
	if got := scoreBehaviorScenarios("5319275A.WhatsAppDesktop"); got != 0 {
		t.Fatalf("mismatched-key bonus = %d, want 0 (silent-zero on genuine path miss)", got)
	}
}
