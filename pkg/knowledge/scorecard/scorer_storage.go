/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-06-storage.ps1:108-118):
//
//	additive boolean features:
//	  webview2_profile present  +25  (WebView2Info.Profiles non-empty)
//	  indexeddb / leveldb hint  +25  (LevelDB parse result present)
//	  local_storage / cache hint+15  (Cache parse result present)
//	  http_cache (webview2 cache)+15  (WebView2Info.IsWebView2 + profiles)
//	  sqlite (apk extract)      +10  (APKExtract or IPAInfo present)
//	  preferences hint          +10  (NPMAnalysis or DotnetRuntime)
//	cap 95
//
// Notes: WebView2.Result does not expose granular Has* booleans (RESEARCH §A1
// was assumed). We use Profiles non-empty as the primary IndexedDB/LocalStorage
// proxy because Chromium profile dirs always carry both.
package scorecard

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func init() { Register(storageScorer{}) }

type storageScorer struct{}

func (storageScorer) ID() string   { return "storage" }
func (storageScorer) Name() string { return "Storage schemas" }

func (storageScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "storage", Name: "Storage schemas"}
	if r == nil {
		return out
	}
	// SCRG-03 — UWP install-dir branch: when WebView2 profiles or MSIX file
	// enumeration carries storage-relevant hints, score with typed-field
	// Citations rather than the legacy r.SourcePath cite.
	if (r.WebView2Info != nil && len(r.WebView2Info.Profiles) > 0) ||
		(r.MSIXInfo != nil && len(r.MSIXInfo.Files) > 0 && r.WebView2Info == nil &&
			r.LevelDB == nil && r.Cache == nil && r.APKExtract == nil && r.IPAInfo == nil) {
		if uwp := scoreStorageUWP(r, out); uwp.Score > 0 {
			return uwp
		}
	}
	cite := newCitation("", r.SourcePath, 0) // P58
	s := 0
	if r.WebView2Info != nil && len(r.WebView2Info.Profiles) > 0 {
		s += 25
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "WebView2Info.Profiles", Citation: cite})
	}
	if r.LevelDB != nil {
		s += 25
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "LevelDB", Citation: cite})
	}
	if r.Cache != nil {
		s += 15
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "Cache", Citation: cite})
	}
	if r.WebView2Info != nil && r.WebView2Info.IsWebView2 && len(r.WebView2Info.Profiles) > 0 {
		s += 15
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "WebView2Info.IsWebView2", Citation: cite})
	}
	if r.APKExtract != nil || r.IPAInfo != nil {
		s += 10
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "APKExtract|IPAInfo", Citation: cite})
	}
	if r.NPMAnalysis != nil || r.DotnetRuntime != nil {
		s += 10
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "NPMAnalysis|DotnetRuntime", Citation: cite})
	}
	if s > 95 {
		s = 95
	}
	out.Score = s
	return out
}

// scoreStorageUWP scores the storage dim from a UWP install-dir surface:
//   - WebView2Info.Profiles[i].Path → +25 base + +15 IndexedDB/Local Storage
//     subdir hint (when matched by name in MSIXInfo.Files); Citation.File =
//     profile path / matching MSIX entry name.
//   - SQLite filename match in MSIXInfo.Files (.sqlite/.db) → +10.
//
// All Citations are typed fields — never r.SourcePath.
func scoreStorageUWP(r *dissect.DissectResult, out DimScore) DimScore {
	s := 0
	if r.WebView2Info != nil {
		for i := range r.WebView2Info.Profiles {
			p := r.WebView2Info.Profiles[i]
			if p.Path == "" {
				continue
			}
			s += 25
			out.Evidence = append(out.Evidence, Evidence{
				Kind:     "field",
				Path:     "WebView2Info.Profiles[].Path",
				Detail:   p.Name,
				Citation: &Citation{File: p.Path},
			})
			if s >= 70 {
				break
			}
		}
	}
	// 84-03 maturity gate: a parsed LevelDB schema (real entries / log/ldb
	// stats) is genuine analysis depth, not shallow profile-path presence.
	// Strictly gated behind a populated r.LevelDB so legacy fixtures
	// (r.LevelDB==nil OR an empty &leveldb.ParseResult{}) stay byte/score-
	// identical (mirror scorer_state_machines.go:65-93 legacy-safe
	// discipline). Each credited point cites a real parsed LevelDB
	// path/key — never r.SourcePath, never profile-path presence alone.
	if ldb := r.LevelDB; ldb != nil &&
		(len(ldb.Entries) > 0 || ldb.Stats.LogFiles > 0 || ldb.Stats.LDBFiles > 0) {
		ldbCite := &Citation{File: ldb.SourcePath}
		if ldbCite.File == "" {
			ldbCite.File = "LevelDB (parsed schema)"
		}
		// Parsed-presence: a real LevelDB store was parsed (log/ldb files).
		s += 25
		out.Evidence = append(out.Evidence, Evidence{
			Kind:     "field",
			Path:     "LevelDB.Stats (parsed log/ldb files)",
			Detail:   ldb.StorageType,
			Citation: ldbCite,
		})
		// Schema depth: enumerated key/value entries (the actual schema).
		if len(ldb.Entries) > 0 {
			s += 25
			keyCite := &Citation{File: ldb.SourcePath}
			if keyCite.File == "" {
				keyCite.File = "LevelDB (parsed schema)"
			}
			out.Evidence = append(out.Evidence, Evidence{
				Kind:     "field",
				Path:     "LevelDB.Entries (parsed key enumeration)",
				Detail:   ldb.Entries[0].Key,
				Citation: keyCite,
			})
		}
		// Origin partitioning: per-origin schema is deeper still.
		if len(ldb.ByOrigin) > 0 {
			s += 10
			out.Evidence = append(out.Evidence, Evidence{
				Kind:     "field",
				Path:     "LevelDB.ByOrigin (per-origin schema)",
				Citation: &Citation{File: ldb.SourcePath},
			})
		}
	}
	if r.MSIXInfo != nil {
		for _, f := range r.MSIXInfo.Files {
			lower := strings.ToLower(f.Name)
			if strings.Contains(lower, "indexeddb/") || strings.Contains(lower, "local storage/") ||
				strings.Contains(lower, "ebwebview/") {
				s += 15
				out.Evidence = append(out.Evidence, Evidence{
					Kind:     "field",
					Path:     "MSIXInfo.Files[].Name (storage-hint)",
					Citation: &Citation{File: f.Name},
				})
				break
			}
		}
		for _, f := range r.MSIXInfo.Files {
			lower := strings.ToLower(f.Name)
			if strings.HasSuffix(lower, ".sqlite") || strings.HasSuffix(lower, ".db") {
				s += 10
				out.Evidence = append(out.Evidence, Evidence{
					Kind:     "field",
					Path:     "MSIXInfo.Files[].Name (sqlite)",
					Citation: &Citation{File: f.Name},
				})
				break
			}
		}
	}
	if s > 95 {
		s = 95
	}
	out.Score = s
	return out
}
