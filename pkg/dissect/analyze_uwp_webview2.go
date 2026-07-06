/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/leveldb"
	"github.com/inovacc/unravel-oss/pkg/webview2"
	"github.com/inovacc/unravel-oss/pkg/webview2/analyze"
)

// maxRecoveredJSConcatBytes bounds the concatenated recovered-JS buffer fed
// to analyzeJS so a hostile cache cannot exhaust memory (T-84-05).
const maxRecoveredJSConcatBytes = 32 * 1024 * 1024

// collectEBWebViewLevelDB is the 84-03 regression-of-omission fix: the P83
// webview2 dispatch already parses each profile's Local Storage / Session
// Storage / IndexedDB LevelDB (analyze.analyzeProfile:157-211, pure-Go
// unravel/pkg/leveldb — A2, no CGO, no hand-rolled SST/log reader), but the
// parsed *leveldb.ParseResult was never surfaced onto r.LevelDB, so
// scorer_storage.go only ever saw r.LevelDB==nil and credited shallow
// profile-path presence. This merges the parsed schema/key enumeration from
// every resolved profile block into a single *leveldb.ParseResult.
//
// No synthesis: when no profile carried a parsed LevelDB result with real
// entries, the return is nil and r.LevelDB stays nil (honest-empty, the
// &webview2.Result{Analyzed:true} sentinel still distinguishes analyzed-empty
// from never-analyzed). The webview2 parse is read-only and bounded; its
// non-fatal errors are already collected onto the ProfileBlock.
func collectEBWebViewLevelDB(res *webview2.Result) *leveldb.ParseResult {
	if res == nil || len(res.ProfileData) == 0 {
		return nil
	}
	merged := &leveldb.ParseResult{StorageType: "ebwebview-merged"}
	found := false
	addPR := func(v any) {
		pr, ok := v.(*leveldb.ParseResult)
		if !ok || pr == nil {
			return
		}
		if len(pr.Entries) == 0 && pr.Stats.LogFiles == 0 && pr.Stats.LDBFiles == 0 {
			return // analyzed-empty parse — no real schema/keys, skip
		}
		found = true
		if merged.SourcePath == "" {
			merged.SourcePath = pr.SourcePath
			merged.ParsedAt = pr.ParsedAt
		}
		merged.Entries = append(merged.Entries, pr.Entries...)
		if len(pr.ByOrigin) > 0 {
			if merged.ByOrigin == nil {
				merged.ByOrigin = make(map[string][]leveldb.Entry)
			}
			for k, v := range pr.ByOrigin {
				merged.ByOrigin[k] = append(merged.ByOrigin[k], v...)
			}
		}
		merged.Errors = append(merged.Errors, pr.Errors...)
		merged.Stats.TotalEntries += pr.Stats.TotalEntries
		merged.Stats.ValidEntries += pr.Stats.ValidEntries
		merged.Stats.DeletedEntries += pr.Stats.DeletedEntries
		merged.Stats.ParseErrors += pr.Stats.ParseErrors
		merged.Stats.LogFiles += pr.Stats.LogFiles
		merged.Stats.LDBFiles += pr.Stats.LDBFiles
	}
	for _, b := range res.ProfileData {
		blk, ok := b.(analyze.ProfileBlock)
		if !ok {
			continue
		}
		addPR(blk.LocalStorage)
		addPR(blk.SessionStorage)
		for _, idb := range blk.IndexedDBs {
			addPR(idb)
		}
	}
	if !found {
		return nil // honest-empty: no parsed schema/keys, never synthesize
	}
	return merged
}

// wireEBWebViewJSAndSecrets is the 84-02 regression-of-omission fix: after
// the P83 webview2 dispatch adopts r.WebView2Info, feed the recovered
// EBWebView Code Cache / Service Worker JS *source* through the existing
// analyzeJS (reuse — no hand-rolled beautifier, RESEARCH §Don't Hand-Roll)
// into r.JSAnalysis, and run the existing pure-Go secrets scanner over the
// recovered source into r.Secrets. scorer_crypto.go / scorer_source_layer.go
// are byte-UNCHANGED — they light up only because real input now reaches
// them (CONTEXT D-03/D-05).
//
// No synthesis: when res carries no recovered JS, r.JSAnalysis / r.Secrets
// stay nil and the &webview2.Result{Analyzed:true} sentinel still
// distinguishes analyzed-empty from never-analyzed. All failures are
// non-fatal (mirror analyze_web.go:55-78): collected to r.Errors, never
// fatal, never panic.
func wireEBWebViewJSAndSecrets(r *DissectResult, res *webview2.Result, sr *debug.StepRecorder) {
	if res == nil {
		return // never-analyzed: nothing to surface
	}
	wireEBWebViewJS(r, res, sr)
	wireEBWebViewCSS(r, res, sr)

	// 84-fix (Task B): additively bridge the attach-time CDP source sidecar.
	// The cache/iterate paths above ran first; this only fills JSAnalysis /
	// RecoveredCSS when they are STILL empty (never clobbers a populated
	// value). Honest-empty / non-fatal when the sidecar is absent or stale.
	applyCDPSourceSidecar(r)
}

// wireEBWebViewJS feeds recovered EBWebView Code Cache / Service Worker JS
// source through the existing analyzeJS / secrets scanner. Honest-empty when
// res carries no recovered JS (JS-specific bail localized here so CSS-only
// inputs are still surfaced by wireEBWebViewCSS).
func wireEBWebViewJS(r *DissectResult, res *webview2.Result, sr *debug.StepRecorder) {
	if len(res.RecoveredJS) == 0 {
		return // analyzed-empty: nothing recovered, never synthesize
	}
	// Element type is analyze.RecoveredJSEntry, carried as []any so the
	// webview2 types stay dependency-free (mirrors ProfileData).
	recovered := make([]analyze.RecoveredJSEntry, 0, len(res.RecoveredJS))
	for _, v := range res.RecoveredJS {
		if e, ok := v.(analyze.RecoveredJSEntry); ok {
			recovered = append(recovered, e)
		}
	}
	if len(recovered) == 0 {
		return // nothing typed-recoverable — analyzed-empty, no synthesis
	}

	// Materialize the recovered source into a temp dir as .js files so the
	// existing path-based analyzeJS and the existing pure-Go secrets
	// scanner (which both key on a real file path / .js extension) operate
	// over genuine recovered bytes — no scanner/beautifier is hand-rolled.
	tmpDir, err := os.MkdirTemp("", "uwp-ebwv-js-")
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("uwp ebwebview js: temp dir: %v", err))
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	var combined strings.Builder
	total := 0
	for i, e := range recovered {
		if e.Source == "" {
			continue
		}
		if total+len(e.Source) > maxRecoveredJSConcatBytes {
			break
		}
		total += len(e.Source)
		// Header banner anchors the forensic citation to the on-disk entry.
		combined.WriteString("// recovered-from: ")
		combined.WriteString(e.Path)
		combined.WriteString("\n")
		combined.WriteString(e.Source)
		combined.WriteString("\n")
		// One file per entry for precise per-artifact secret citations.
		fn := filepath.Join(tmpDir, fmt.Sprintf("recovered_%04d.js", i))
		if werr := os.WriteFile(fn, []byte(e.Source), 0o600); werr != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("uwp ebwebview js: write %s: %v", fn, werr))
		}
	}
	if total == 0 {
		return // recovered entries were all empty — analyzed-empty, no synthesis
	}

	// Materialize the combined buffer into tmpDir so the secrets scan below
	// sees it alongside the per-entry files (byte-identical to the original
	// cache-path behavior — the banner-joined buffer is part of the scanned
	// corpus).
	combinedPath := filepath.Join(tmpDir, "ebwebview_combined.js")
	if werr := os.WriteFile(combinedPath, []byte(combined.String()), 0o600); werr != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("uwp ebwebview js: write combined: %v", werr))
		return
	}

	// JSAnalysis — delegate the combined-buffer→analyzeJS→r.JSAnalysis core
	// to applyCombinedJS so the CDP source path (ApplyPulledJS) feeds the
	// identical logic. The secrets scan below stays cache-path only.
	applyCombinedJS(r, combined.String(), sr)

	// Secrets — reuse the existing pure-Go scanner over the recovered .js
	// files (it keys on .js extension; raw cache entries have no extension).
	scan, serr := secret.ScanDirectory(tmpDir)
	if serr != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("uwp ebwebview secrets: %v", serr))
	} else if scan != nil && scan.TotalFindings > 0 {
		r.Secrets = scan
		if sr != nil {
			sr.RecordOutput(scan)
		}
	}
}

// wireEBWebViewCSS is the 84-fix: surface recovered CSS (HTTP-cache, decoded)
// as a clean-room artifact. No analyzeJS — CSS is not script; record
// presence/bytes/origins so analysts can map style. Honest-empty when nothing
// recovered (r.RecoveredCSS stays nil, never synthesized).
func wireEBWebViewCSS(r *DissectResult, res *webview2.Result, sr *debug.StepRecorder) {
	if len(res.RecoveredCSS) == 0 {
		return
	}
	entries := make([]CSSEntry, 0, len(res.RecoveredCSS))
	for _, v := range res.RecoveredCSS {
		e, ok := v.(analyze.RecoveredCSSEntry)
		if !ok {
			continue
		}
		entries = append(entries, CSSEntry{Path: e.Path, Source: e.Source})
	}
	applyCSSEntries(r, entries, sr)
}

// CSSEntry is a source-agnostic recovered-CSS record so the cache path
// (analyze.RecoveredCSSEntry) and the CDP source path share applyCSSEntries.
type CSSEntry struct {
	Path   string
	Source string
}

// applyCombinedJS is the shared JS core: an already-combined JS string is
// written to a temp file and run through the existing analyzeJS, setting
// r.JSAnalysis on success (re-anchored to the EBWebView origin like the
// cache path). Honest-empty when combined=="" (r.JSAnalysis stays nil, no
// synthesis). The buffer is clamped at maxRecoveredJSConcatBytes (32MiB) so
// a hostile source cannot exhaust memory even if the caller did not bound it.
// All failures are non-fatal (r.Errors), never panic. The secrets scan is
// NOT performed here — it remains cache-path only.
func applyCombinedJS(r *DissectResult, combined string, sr *debug.StepRecorder) {
	if combined == "" {
		return // honest-empty: no input, never synthesize
	}
	if len(combined) > maxRecoveredJSConcatBytes {
		combined = combined[:maxRecoveredJSConcatBytes]
	}
	tmpDir, err := os.MkdirTemp("", "uwp-ebwv-combined-js-")
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("uwp ebwebview js: temp dir: %v", err))
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	combinedPath := filepath.Join(tmpDir, "ebwebview_combined.js")
	if werr := os.WriteFile(combinedPath, []byte(combined), 0o600); werr != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("uwp ebwebview js: write combined: %v", werr))
		return
	}

	// Mirror analyze_web.go:55-78 (non-fatal err, RecordOutput).
	jsResult, jerr := analyzeJS(combinedPath)
	if jerr != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("uwp ebwebview js analyze: %v", jerr))
		return
	}
	if jsResult == nil {
		return
	}
	// Re-anchor the reported file to the EBWebView origin (the temp path is
	// an implementation detail; the forensic anchor is the recovered entry).
	jsResult.File = "EBWebView Code Cache / Service Worker (recovered)"
	r.JSAnalysis = jsResult
	if sr != nil {
		sr.RecordOutput(jsResult)
	}
}

// applyCSSEntries is the shared CSS core: counts Files/TotalBytes over every
// non-empty entry (even with a repeated Path), dedupes Origins by Path, and
// sets r.RecoveredCSS only when Files>0. Honest-empty otherwise (stays nil,
// never synthesized).
func applyCSSEntries(r *DissectResult, entries []CSSEntry, sr *debug.StepRecorder) {
	if len(entries) == 0 {
		return
	}
	cssRes := &RecoveredCSSResult{}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Source == "" {
			continue
		}
		cssRes.Files++
		cssRes.TotalBytes += len(e.Source)
		if e.Path != "" && !seen[e.Path] {
			seen[e.Path] = true
			cssRes.Origins = append(cssRes.Origins, e.Path)
		}
	}
	if cssRes.Files > 0 {
		r.RecoveredCSS = cssRes
		if sr != nil {
			sr.RecordOutput(cssRes)
		}
	}
}

// ApplyPulledJS feeds CDP-pulled JS (already concatenated) through the
// same analyzeJS path as cache-recovered JS. Honest-empty when "".
func ApplyPulledJS(r *DissectResult, combined string) {
	applyCombinedJS(r, combined, nil)
}

// ApplyPulledCSS surfaces CDP-pulled CSS via the same aggregation as the
// cache path. Honest-empty when len(entries)==0.
func ApplyPulledCSS(r *DissectResult, entries []CSSEntry) {
	applyCSSEntries(r, entries, nil)
}
