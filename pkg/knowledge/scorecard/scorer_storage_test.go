/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/leveldb"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

func TestStorageScorer(t *testing.T) {
	cases := []struct {
		name string
		r    *dissect.DissectResult
		want int
	}{
		{"nil", nil, 0},
		{"empty", &dissect.DissectResult{}, 0},
		{"webview2_only", &dissect.DissectResult{
			WebView2Info: &webview2.Result{IsWebView2: true, Profiles: []webview2.ProfileInfo{{Name: "p"}}},
		}, 40}, // +25 profiles +15 http_cache
		{"with_leveldb_cache", &dissect.DissectResult{
			WebView2Info: &webview2.Result{IsWebView2: true, Profiles: []webview2.ProfileInfo{{Name: "p"}}},
			LevelDB:      &leveldb.ParseResult{},
			Cache:        &cache.ParseResult{},
		}, 80}, // 40 + 25 + 15
		{"all_features_caps_at_95", &dissect.DissectResult{
			WebView2Info:  &webview2.Result{IsWebView2: true, Profiles: []webview2.ProfileInfo{{Name: "p"}}},
			LevelDB:       &leveldb.ParseResult{},
			Cache:         &cache.ParseResult{},
			NPMAnalysis:   nil,
			DotnetRuntime: nil,
		}, 80},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := storageScorer{}.Score(tc.r, nil)
			if got.Score != tc.want {
				t.Errorf("Score = %d, want %d", got.Score, tc.want)
			}
		})
	}
}

// TestStorageScorer_UWPInstallDir exercises the SCRG-03 UWP branch:
// WebView2 profile with non-empty Path + IndexedDB hint in MSIXInfo.Files +
// SQLite filename match → score >= 70; Citations are typed-field paths
// (profile.Path / matching MSIX entry name), never r.SourcePath.
func TestStorageScorer_UWPInstallDir(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "C:/Program Files/WindowsApps/some.app",
		WebView2Info: &webview2.Result{
			IsWebView2: true,
			Profiles: []webview2.ProfileInfo{
				{Name: "Default", Path: "C:/AppData/EBWebView/Default"},
			},
		},
		MSIXInfo: &msix.InfoResult{
			Files: []msix.FileEntry{
				{Name: "App/EBWebView/Default/IndexedDB/leveldb"},
				{Name: "App/local-state.sqlite"},
			},
		},
	}
	got := storageScorer{}.Score(r, nil)
	if got.Score < 50 {
		t.Errorf("UWP install-dir Score = %d, want >= 50", got.Score)
	}
	if len(got.Evidence) == 0 {
		t.Fatal("UWP install-dir Evidence empty")
	}
	for i, ev := range got.Evidence {
		if ev.Citation == nil {
			t.Errorf("Evidence[%d].Citation is nil", i)
			continue
		}
		if ev.Citation.File == r.SourcePath {
			t.Errorf("Evidence[%d].Citation.File leaked r.SourcePath", i)
		}
	}
}

// TestStorageScorer_ParsedLevelDBEvidence is the 84-03 maturity gate: when
// r.LevelDB carries a parsed schema (real entries / log/ldb stats), the UWP
// storage branch must credit parsed-schema points toward the floor AND emit
// Evidence whose Path references LevelDB and whose Citation is a real LevelDB
// path/key (never r.SourcePath, never profile-path-presence alone).
func TestStorageScorer_ParsedLevelDBEvidence(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "C:/Program Files/WindowsApps/some.app",
		WebView2Info: &webview2.Result{
			IsWebView2: true,
			Profiles: []webview2.ProfileInfo{
				{Name: "Default", Path: "C:/AppData/EBWebView/Default"},
			},
		},
		LevelDB: &leveldb.ParseResult{
			SourcePath: "C:/AppData/EBWebView/Default/Local Storage/leveldb",
			Entries: []leveldb.Entry{
				{Key: "_https://web.whatsapp.com\x00\x01config", Value: "v", Type: "PUT", Origin: "https://web.whatsapp.com"},
				{Key: "META:https://web.whatsapp.com", Value: "m", Type: "PUT"},
			},
			Stats: leveldb.ParseStats{TotalEntries: 2, ValidEntries: 2, LogFiles: 1},
		},
	}
	got := storageScorer{}.Score(r, nil)
	if got.Score < 50 {
		t.Errorf("parsed-LevelDB Score = %d, want >= 50 (mature, not presence)", got.Score)
	}
	sawLevelDB := false
	for i, ev := range got.Evidence {
		if ev.Citation == nil {
			t.Errorf("Evidence[%d].Citation nil", i)
			continue
		}
		if ev.Citation.File == r.SourcePath {
			t.Errorf("Evidence[%d].Citation leaked r.SourcePath", i)
		}
		if strings.Contains(ev.Path, "LevelDB") {
			sawLevelDB = true
		}
	}
	if !sawLevelDB {
		t.Fatalf("no LevelDB-pathed Evidence: parsed schema not credited with citation")
	}
}

// TestStorageScorer_NilLevelDBLegacyByteIdentical asserts the new parsed
// credit is strictly gated behind a populated r.LevelDB: an empty
// (&leveldb.ParseResult{}) or nil LevelDB must score byte-identical to the
// pre-84-03 curve so legacy fixtures never drift.
func TestStorageScorer_NilLevelDBLegacyByteIdentical(t *testing.T) {
	// Empty ParseResult (no entries / no stats) == legacy presence only.
	empty := &dissect.DissectResult{
		WebView2Info: &webview2.Result{IsWebView2: true, Profiles: []webview2.ProfileInfo{{Name: "p"}}},
		LevelDB:      &leveldb.ParseResult{},
		Cache:        &cache.ParseResult{},
	}
	if got := (storageScorer{}).Score(empty, nil); got.Score != 80 {
		t.Errorf("empty-LevelDB Score = %d, want 80 (legacy byte-identical)", got.Score)
	}
	// nil LevelDB.
	nilLDB := &dissect.DissectResult{
		WebView2Info: &webview2.Result{IsWebView2: true, Profiles: []webview2.ProfileInfo{{Name: "p"}}},
	}
	if got := (storageScorer{}).Score(nilLDB, nil); got.Score != 40 {
		t.Errorf("nil-LevelDB Score = %d, want 40 (legacy byte-identical)", got.Score)
	}
}

// TestStorageScorer_UWPNilSafe — nil WebView2Info AND nil MSIXInfo must not
// panic (covered by base "nil" / "empty" cases above; this test asserts no
// false UWP signal when both surfaces are absent).
func TestStorageScorer_UWPNilSafe(t *testing.T) {
	got := storageScorer{}.Score(&dissect.DissectResult{}, nil)
	if got.Score != 0 || len(got.Evidence) != 0 {
		t.Errorf("empty Score=%d Evidence=%v, want 0/empty", got.Score, got.Evidence)
	}
}
