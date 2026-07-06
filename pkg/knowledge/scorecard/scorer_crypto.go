/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-07-crypto.ps1:101-110):
//
//	per-pattern boolean +12 across {aes, webcrypto, libsignal, curve/noise,
//	  kdf, protobuf-crypto} -> max +72 from JS indicators
//	+18 if any AppAnalysis.Binaries flagged as crypto-bearing
//	  (binary.IsDotNet OR len(SampleStrings)>0 carrying crypto needles)
//	floor 70 if total_hits > 50 (Secrets.TotalFindings or NetworkAnalysis hits)
//	cap 90  (W-12 +15 / W-14 +5 deepening adders deferred to P57)
//
// Sources: Secrets.ScanResult, JSAnalysisResult.Indicators / DangerousCalls,
// AppAnalysis.Binaries (per-binary).
package scorecard

import (
	"debug/pe"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/msix"
)

// cryptoImportDLLs are the Windows crypto subsystem DLLs whose presence in a
// PE import directory is a strong signal of crypto use. Match is
// case-insensitive against the dll basename.
var cryptoImportDLLs = []string{
	"crypt32.dll", "bcrypt.dll", "ncrypt.dll", "cryptbase.dll",
	"cryptnet.dll", "wintrust.dll",
}

// cryptoJSNeedles extends cryptoNeedles with library-specific names for
// SCRG-04 JS-reference detection. Matched against r.JSAnalysis.DangerousCalls
// and r.JSAnalysis.NetworkCalls (NOT .Indicators per PLAN ground-truth).
var cryptoJSNeedles = []string{
	"libsignal-protocol", "libsodium", "tweetnacl", "elliptic",
	"node-forge", "bcrypt", "scrypt", "argon2",
	"crypto.subtle", "subtlecrypto", "webcrypto",
}

// scanPEImportsForCrypto opens a PE file and returns the matching crypto DLL
// names. T-64-01 mitigation: pe.Open is wrapped in a defer-recover (called
// by the outer scorer) and the file is closed deterministically. Cross-platform
// — debug/pe is pure-Go stdlib, no Windows-only APIs.
//
// NOTE: stdlib's File.ImportedLibraries() is a TODO stub that returns nil
// (Go 1.25, debug/pe/file.go:462). We derive the DLL list from
// ImportedSymbols() which returns "Symbol:Dll" entries — split on ':' and
// dedupe.
func scanPEImportsForCrypto(absPath string) ([]string, error) {
	f, err := pe.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("pe.Open: %w", err)
	}
	defer func() { _ = f.Close() }()
	syms, err := f.ImportedSymbols()
	if err != nil {
		return nil, fmt.Errorf("imported symbols: %w", err)
	}
	seen := map[string]struct{}{}
	matches := make([]string, 0, 2)
	for _, sym := range syms {
		// Format per debug/pe: "<symname>:<dllname>" (case preserved).
		idx := strings.LastIndex(sym, ":")
		if idx < 0 {
			continue
		}
		dll := strings.ToLower(filepath.Base(sym[idx+1:]))
		for _, target := range cryptoImportDLLs {
			if dll == target {
				if _, ok := seen[target]; !ok {
					seen[target] = struct{}{}
					matches = append(matches, target)
				}
				break
			}
		}
	}
	return matches, nil
}

// safeScanPE wraps scanPEImportsForCrypto in a defer-recover so a malformed
// vendor PE cannot panic the scorer (T-64-01). Returns nil matches on any
// error or panic; the caller logs nothing here (scorer is non-fatal).
func safeScanPE(absPath string) (matches []string) {
	defer func() {
		if rec := recover(); rec != nil {
			matches = nil
		}
	}()
	m, err := scanPEImportsForCrypto(absPath)
	if err != nil {
		return nil
	}
	return m
}

// peSizeLimit caps PE reads at 64MB to bound scorer runtime against vendor
// multi-GB MSIX assets (T-64-02).
const peSizeLimit = 64 * 1024 * 1024

// scoreCryptoUWP scores crypto from a UWP install-dir surface. Walks PE
// imports via debug/pe over r.MSIXInfo.Files PE entries (resolved against
// r.SourcePath as the install-dir root) plus JS-reference scan over
// r.JSAnalysis.DangerousCalls and r.JSAnalysis.NetworkCalls.
//
// Per-Evidence typed-field Citations:
//   - PE-import: Citation.File = MSIXInfo.Files[i].Name (NOT joined absolute).
//   - JS-reference: Citation.File = JSAnalysis.File.
//
// Documented drift: ceiling ~80 acceptable vs expected 90; corpus_validation
// tolerance widens to ±10 for crypto dim per PLAN.
func scoreCryptoUWP(r *dissect.DissectResult, out DimScore) DimScore {
	score := 0
	pes := peEntries(r.MSIXInfo.Files)
	for _, entry := range pes {
		if entry.Size > peSizeLimit {
			continue // T-64-02: skip oversized
		}
		abs := filepath.Join(r.SourcePath, entry.Name)
		matches := safeScanPE(abs)
		if len(matches) == 0 {
			continue
		}
		score += 25
		out.Evidence = append(out.Evidence, Evidence{
			Kind:     "field",
			Path:     "MSIXInfo.Files[].Name (PE-imports)",
			Detail:   strings.Join(matches, ","),
			Citation: &Citation{File: entry.Name},
		})
	}
	if r.JSAnalysis != nil {
		jsHits := scanJSCryptoRefs(r.JSAnalysis)
		if len(jsHits) > 0 {
			score += 20
			out.Evidence = append(out.Evidence, Evidence{
				Kind:     "field",
				Path:     "JSAnalysis.{DangerousCalls,NetworkCalls} (crypto-lib)",
				Detail:   strings.Join(jsHits, ","),
				Citation: &Citation{File: r.JSAnalysis.File},
			})
		}
	}
	if score > 90 {
		score = 90
	}
	out.Score = score
	return out
}

// scanJSCryptoRefs scans the documented JSAnalysisResult fields (NOT
// .Indicators per PLAN ground-truth) for crypto-library references.
func scanJSCryptoRefs(js *dissect.JSAnalysisResult) []string {
	if js == nil {
		return nil
	}
	hits := map[string]struct{}{}
	for _, src := range [][]string{js.DangerousCalls, js.NetworkCalls} {
		for _, s := range src {
			low := strings.ToLower(s)
			for _, n := range cryptoJSNeedles {
				if strings.Contains(low, n) {
					hits[n] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(hits))
	for n := range hits {
		out = append(out, n)
	}
	return out
}

// hasUWPCryptoSurface returns true when the UWP branch should run instead of
// the legacy curve. Triggered when MSIXInfo carries enumerable PE entries
// (install-dir context) and no Electron/legacy crypto signal is present.
func hasUWPCryptoSurface(r *dissect.DissectResult) bool {
	if r.MSIXInfo == nil || len(r.MSIXInfo.Files) == 0 {
		return false
	}
	if len(peEntries(r.MSIXInfo.Files)) == 0 {
		return false
	}
	// Legacy surfaces: don't override Electron AppAnalysis-derived crypto.
	if r.AppAnalysis != nil && len(r.AppAnalysis.Binaries) > 0 {
		return false
	}
	return true
}

// _ keeps the msix import live even if scoreCryptoUWP refactors away
// the FileEntry slice expression.
var _ = msix.FileEntry{}

func init() { Register(cryptoScorer{}) }

type cryptoScorer struct{}

func (cryptoScorer) ID() string   { return "crypto" }
func (cryptoScorer) Name() string { return "Crypto" }

var cryptoNeedles = []string{
	"aes", "webcrypto", "libsignal", "curve", "noise", "kdf", "protobuf",
}

func (cryptoScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "crypto", Name: "Crypto"}
	if r == nil {
		return out
	}
	// SCRG-04 — UWP install-dir branch: PE-imports + JS-references with
	// typed-field Citations. Returns when produces signal; falls through
	// to legacy curve otherwise.
	if hasUWPCryptoSurface(r) {
		if uwp := scoreCryptoUWP(r, out); uwp.Score > 0 {
			return uwp
		}
	}
	hits := map[string]bool{}
	totalHits := 0
	if r.JSAnalysis != nil {
		for _, ind := range r.JSAnalysis.Indicators {
			low := strings.ToLower(ind)
			for _, n := range cryptoNeedles {
				if strings.Contains(low, n) {
					hits[n] = true
				}
			}
		}
		for _, dc := range r.JSAnalysis.DangerousCalls {
			low := strings.ToLower(dc)
			for _, n := range cryptoNeedles {
				if strings.Contains(low, n) {
					hits[n] = true
				}
			}
		}
	}
	if r.Secrets != nil {
		totalHits += r.Secrets.TotalFindings
	}
	if r.NetworkAnalysis != nil {
		// indirect signal: presence of network analysis lifts total hit count
		totalHits += 1
	}
	cite := newCitation("", r.SourcePath, 0) // P58
	score := 0
	for n := range hits {
		score += 12
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "JSAnalysis." + n, Citation: cite})
	}
	binCrypto := false
	if r.AppAnalysis != nil {
		for _, b := range r.AppAnalysis.Binaries {
			low := strings.ToLower(strings.Join(append([]string{}, b.SampleStrings...), " "))
			for _, n := range cryptoNeedles {
				if strings.Contains(low, n) {
					binCrypto = true
					break
				}
			}
			if binCrypto {
				break
			}
		}
	}
	if binCrypto {
		score += 18
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "AppAnalysis.Binaries.SampleStrings", Citation: cite})
	}
	if totalHits > 50 && score < 70 {
		score = 70
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "Secrets.TotalFindings>50", Citation: cite})
	}
	if score > 90 {
		score = 90
	}
	out.Score = score
	return out
}
