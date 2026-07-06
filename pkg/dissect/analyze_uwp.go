/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/uwp"
	uwpdetect "github.com/inovacc/unravel-oss/pkg/uwp/detect"
	_ "github.com/inovacc/unravel-oss/pkg/uwp/runtime" // wire orchestrator into uwp.Analyze
	"github.com/inovacc/unravel-oss/pkg/webview2"
	"github.com/inovacc/unravel-oss/pkg/webview2/analyze"
	"github.com/inovacc/unravel-oss/pkg/winui"
	_ "github.com/inovacc/unravel-oss/pkg/winui/runtime" // wire orchestrator into winui.Analyze (uwp.Analyze delegates XAML/PRI walk to winui.Analyze)
)

func init() {
	RegisterAnalyzer(analyzeUWP, detect.TypeUWPApp)
	RegisterSupplementalAnalyzer(analyzeUWPSupplemental, detect.TypeMSIX)
}

// maxAppxManifestRead bounds the manifest entry read in archive (zip-toc)
// peek mode. Matches uwp/detect.maxManifestSize (T-04-02).
const maxAppxManifestRead int64 = 2 * 1024 * 1024

// analyzeUWP is the PRIMARY UWP analyzer (registered on TypeUWPApp).
// Plan 05 upgrade: full uwp.Analyze pipeline (manifest + capability
// scoring + XAML walk + DPAPI flag-only). Falls back to the cheap-path
// peek when the full pipeline cannot run (e.g. missing AppxManifest in
// a directory mode).
func analyzeUWP(r *DissectResult, path string, _ Options) {
	full, err := uwp.Analyze(path, uwp.Options{
		ExtractIfArchive:  true,
		ScoreCapabilities: true,
		AnalyzeXAML:       true,
		DPAPIFlagOnly:     true,
		RejectSymlinks:    true,
	})
	if err != nil || full == nil {
		// Fall back to cheap-path peek for the framework signals.
		res := &uwp.Result{}
		frameworks, derr := detectUWPFromPath(path)
		if derr != nil {
			res.Errors = append(res.Errors, derr.Error())
		}
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("uwp full analysis: %v", err))
		}
		res.Frameworks = frameworks
		for _, fi := range frameworks {
			if fi.Name == "UWP" {
				res.IsUWP = true
				break
			}
		}
		r.UWPInfo = res
		r.Frameworks = winui.MergeFrameworksDedup(r.Frameworks, frameworks)
		return
	}
	r.UWPInfo = full
	r.Frameworks = winui.MergeFrameworksDedup(r.Frameworks, full.Frameworks)
	populateMSIXFromDir(r, path)
	// 83-02 half-A: after the UWP pipeline confirms an installed-MSIX dir,
	// run the existing WebView2/Chromium analyzer over the SAME install-dir
	// path. udf.resolveUWPCandidates (discover.go:144-192) derives the PFN
	// (discover.go:203-263) and walks %LOCALAPPDATA%\Packages\<PFN>\LocalCache
	// (depth<=3) for EBWebView dirs — no udf.DiscoverOptions.Override needed
	// (A1 spike VERDICT: INSTALL_DIR_RESOLVES).
	uwpWebView2Step := func(sr *debug.StepRecorder) error {
		res, err := webview2.Analyze(path, analyze.Options{
			ExtractCache:      true,
			ExtractLevelDB:    true,
			ExtractCookies:    true,
			RejectSymlinks:    true,
			MaxProfilesToScan: 8,
		})
		if err != nil {
			// Non-fatal: honest-empty per D-08, no fabrication. Mirror the
			// fallback error pattern (analyze_uwp.go:48-60).
			r.Errors = append(r.Errors, fmt.Sprintf("uwp webview2 analysis: %v", err))
			return nil
		}
		// Guard: only adopt a result that actually resolved on-disk profiles
		// so an empty capture never clobbers a populated WebView2Info and we
		// never synthesize profiles (T-83-02-01).
		if res != nil && len(res.Profiles) > 0 {
			res.Analyzed = true
			r.WebView2Info = res
			if sr != nil {
				sr.RecordOutput(res)
			}
			// 84-02: feed the recovered EBWebView Code Cache / Service
			// Worker JS source into r.JSAnalysis and run the pure-Go
			// secrets scanner over it into r.Secrets. This is the
			// upstream regression-of-omission fix; scorer_crypto.go /
			// scorer_source_layer.go stay byte-unchanged and light up
			// only because real input now reaches them (D-03/D-05).
			wireEBWebViewJSAndSecrets(r, res, sr)
			// 84-03: surface the already-parsed (P83 webview2.Analyze,
			// pure-Go pkg/leveldb) EBWebView Local Storage / IndexedDB
			// LevelDB schema/keys onto r.LevelDB so scorer_storage.go can
			// credit parsed evidence instead of shallow profile-path
			// presence. nil when no profile carried a real parse
			// (honest-empty, no synthesis — D-03/D-08).
			if ldb := collectEBWebViewLevelDB(res); ldb != nil {
				r.LevelDB = ldb
				if sr != nil {
					sr.RecordOutput(ldb)
				}
			}
		} else if r.WebView2Info == nil {
			// CR-01: honest-empty per D-08 — no EBWebView tree resolved (or
			// the analyzer returned a profile-less result). Stamp a non-nil
			// sentinel with Analyzed=true so the cache-staleness gate can
			// distinguish "analyzed post-83, nothing found" from
			// "never analyzed (pre-83, WebView2Info==nil)". Makes the
			// re-analysis one-time instead of an unbounded per-run loop.
			// No profiles are synthesized (D-08, no fabrication).
			r.WebView2Info = &webview2.Result{Analyzed: true}
		}
		return nil
	}
	if r.debugRec != nil {
		r.runStep("uwp webview2 analyze", uwpWebView2Step)
	} else {
		// Direct-construction callers (e.g. unit tests with a bare
		// DissectResult and no debug recorder) still get the dispatch
		// without the runStep recorder plumbing.
		_ = uwpWebView2Step(nil)
	}
	populateCertFromEntryPoint(r, path)
	populatePRIFallback(r, path)
	populatePEFileSigning(r, path)
	populateURLs(r, path)
}

// urlPattern is intentionally tight: scheme + host (alnum / dot / dash) +
// optional path bytes that are not whitespace, control chars, or quote marks.
// Avoids matching XML schemas and W3C URIs by requiring TLD-ish hostname or
// localhost form.
var urlPattern = regexp.MustCompile(`https?://[A-Za-z0-9][A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?:[A-Za-z0-9./?&=_%~+#:\-]*)?`)

const (
	maxURLScanFiles  = 60
	maxURLScanBytes  = 5 * 1024 * 1024
	maxURLsCollected = 200
	maxURLLen        = 300
)

func populateURLs(r *DissectResult, path string) {
	if r.MSIXInfo == nil || len(r.MSIXInfo.Files) == 0 {
		return
	}
	seen := make(map[string]struct{})
	scanned := 0
	for _, f := range r.MSIXInfo.Files {
		if scanned >= maxURLScanFiles || len(seen) >= maxURLsCollected {
			break
		}
		if !shouldScanForURLs(f.Name) {
			continue
		}
		full := filepath.Join(path, f.Name)
		data, err := readBoundedFile(full, maxURLScanBytes)
		if err != nil {
			continue
		}
		scanned++
		for _, m := range urlPattern.FindAll(data, -1) {
			if len(m) > maxURLLen {
				continue
			}
			s := string(m)
			if isLowSignalURL(s) {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			r.MSIXInfo.URLs = append(r.MSIXInfo.URLs, s)
			if len(r.MSIXInfo.URLs) >= maxURLsCollected {
				return
			}
		}
	}
}

func shouldScanForURLs(name string) bool {
	lower := strings.ToLower(name)
	switch filepath.Ext(lower) {
	case ".exe", ".dll":
		return true
	case ".js", ".mjs":
		return true
	case ".json":
		return true
	case ".html", ".htm":
		return true
	}
	return false
}

func readBoundedFile(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, max)
	n, rerr := io.ReadFull(f, buf)
	// WR-03: io.EOF (empty file) and io.ErrUnexpectedEOF (file smaller than
	// max — the common case) are expected and yield a valid partial buffer.
	// Any other error (mid-stream I/O fault, truncated network mount) means
	// the buffer is corrupt — surface it so the caller skips the file
	// rather than scanning a truncated buffer (honest-empty, no fabrication).
	if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
		return nil, rerr
	}
	return buf[:n], nil
}

// isLowSignalURL filters URLs that are XML schema declarations, W3C
// boilerplate, or localhost-like noise. These add file size without forensic
// value.
func isLowSignalURL(u string) bool {
	lower := strings.ToLower(u)
	switch {
	case strings.HasPrefix(lower, "http://www.w3.org/"),
		strings.HasPrefix(lower, "https://www.w3.org/"),
		strings.HasPrefix(lower, "http://schemas.microsoft.com/"),
		strings.HasPrefix(lower, "https://schemas.microsoft.com/"),
		strings.HasPrefix(lower, "http://schemas.openxmlformats.org/"),
		strings.HasPrefix(lower, "http://docs.oasis-open.org/"),
		strings.HasPrefix(lower, "http://www.ietf.org/"),
		strings.Contains(lower, "://schemas."),
		strings.HasPrefix(lower, "http://localhost"),
		strings.HasPrefix(lower, "https://localhost"):
		return true
	}
	return false
}

// populatePEFileSigning scans up to maxPESigningScan PE files captured by
// InfoFromDir and stamps each FileEntry with Authenticode signature presence
// + signer subject. Lets the knowledge layer flag unsigned native modules
// without re-walking the directory. No-op when MSIXInfo / Files is nil.
const maxPESigningScan = 50

func populatePEFileSigning(r *DissectResult, path string) {
	if r.MSIXInfo == nil || len(r.MSIXInfo.Files) == 0 {
		return
	}
	scanned := 0
	for i := range r.MSIXInfo.Files {
		f := &r.MSIXInfo.Files[i]
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext != ".exe" && ext != ".dll" {
			continue
		}
		if scanned >= maxPESigningScan {
			break
		}
		full := filepath.Join(path, f.Name)
		ci, err := cert.ExtractCertificates(full)
		scanned++
		if err != nil || ci == nil {
			no := false
			f.Signed = &no
			continue
		}
		signed := ci.HasSignature
		f.Signed = &signed
		if ci.Signer != nil {
			f.Signer = ci.Signer.CommonName
			if f.Signer == "" {
				f.Signer = ci.Signer.Subject
			}
		}
	}
}

// populatePRIFallback adds entries for any *.pri file at the dir root that
// the winui PRI parser did not surface. Teams ships ~10 scaled PRI files
// (resources.scale-100.pri ... resources.scale-200.pri) that the parser
// either rejects or produces zero entries from. The fallback indexes them
// as references so downstream consumers know the resources exist; full
// content extraction stays the parser's responsibility.
func populatePRIFallback(r *DissectResult, path string) {
	if r.UWPInfo == nil {
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return
	}
	matches, err := filepath.Glob(filepath.Join(path, "*.pri"))
	if err != nil || len(matches) == 0 {
		return
	}
	if r.UWPInfo.XAMLIndex == nil {
		r.UWPInfo.XAMLIndex = &winui.XAMLIndex{}
	}
	// Track existing PRI paths to avoid double-counting parser output.
	existing := make(map[string]struct{}, len(r.UWPInfo.XAMLIndex.Entries))
	for _, e := range r.UWPInfo.XAMLIndex.Entries {
		if e.Kind == "pri" {
			existing[filepath.Base(e.Path)] = struct{}{}
		}
	}
	for _, m := range matches {
		base := filepath.Base(m)
		if _, ok := existing[base]; ok {
			continue
		}
		r.UWPInfo.XAMLIndex.Entries = append(r.UWPInfo.XAMLIndex.Entries, winui.XAMLEntry{
			Path: base,
			Kind: "pri",
		})
	}
}

// populateCertFromEntryPoint runs Authenticode extraction on the first
// entry-point .exe declared by the UWP manifest. Installed UWP dirs lack the
// .msix archive's signature blob, so signing surfaces only via the PE
// Authenticode of the executable itself. No-op when r.CertInfo is already
// set, when path is not a dir, or when no entry-point .exe is readable.
func populateCertFromEntryPoint(r *DissectResult, path string) {
	if r.CertInfo != nil || r.UWPInfo == nil || r.UWPInfo.Manifest == nil {
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return
	}
	for _, ep := range r.UWPInfo.Manifest.EntryPoints {
		if ep.Executable == "" {
			continue
		}
		exe := filepath.Join(path, ep.Executable)
		if _, err := os.Stat(exe); err != nil {
			continue
		}
		ci, err := cert.ExtractCertificates(exe)
		if err != nil || ci == nil {
			continue
		}
		r.CertInfo = ci
		return
	}
}

// populateMSIXFromDir fills r.MSIXInfo for installed UWP directories so the
// downstream Packaging extractor (FileCount, Dependencies, Description) has a
// source. No-op when r.MSIXInfo is already set (.msix archive path) or when
// path is not a directory containing AppxManifest.xml.
func populateMSIXFromDir(r *DissectResult, path string) {
	if r.MSIXInfo != nil {
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return
	}
	if !msix.IsInstalledUWPDir(path) {
		return
	}
	mi, err := msix.InfoFromDir(path)
	if err != nil {
		return
	}
	r.MSIXInfo = mi
}

// analyzeUWPSupplemental is the cheap-path tier for TypeMSIX inputs. It
// peeks the AppxManifest.xml entry from the archive's zip TOC without
// extracting the rest of the package. Skips when the primary analyzer
// already populated r.UWPInfo.
func analyzeUWPSupplemental(r *DissectResult, path string, _ Options) {
	if r.UWPInfo != nil {
		return
	}
	frameworks, err := peekManifestFromArchive(path)
	if err != nil || len(frameworks) == 0 {
		return
	}
	res := &uwp.Result{Frameworks: frameworks}
	for _, fi := range frameworks {
		if fi.Name == "UWP" {
			res.IsUWP = true
			break
		}
	}
	r.UWPInfo = res
	r.Frameworks = winui.MergeFrameworksDedup(r.Frameworks, frameworks)
}

// detectUWPFromPath inspects path which may be either a directory containing
// AppxManifest.xml or an .msix/.appx archive. Tries the directory case first
// (D-14: already-extracted input), then falls back to archive peek.
func detectUWPFromPath(path string) ([]uwp.FrameworkInfo, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if info.IsDir() {
		manifestPath := filepath.Join(path, "AppxManifest.xml")
		return uwpdetect.DetectFromManifest(manifestPath)
	}
	return peekManifestFromArchive(path)
}

// peekManifestFromArchive opens path as a zip and reads the AppxManifest.xml
// entry only. The read is bounded by maxAppxManifestRead (T-04-02).
func peekManifestFromArchive(path string) ([]uwp.FrameworkInfo, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	for _, zf := range zr.File {
		if !strings.EqualFold(zf.Name, "AppxManifest.xml") {
			continue
		}
		// Reject suspicious uncompressed-size declarations up front.
		if zf.UncompressedSize64 > uint64(maxAppxManifestRead) {
			return nil, fmt.Errorf("AppxManifest.xml exceeds %d byte cap", maxAppxManifestRead)
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, fmt.Errorf("open manifest entry: %w", err)
		}
		data, rerr := io.ReadAll(io.LimitReader(rc, maxAppxManifestRead+1))
		_ = rc.Close()
		if rerr != nil {
			return nil, fmt.Errorf("read manifest entry: %w", rerr)
		}
		if int64(len(data)) > maxAppxManifestRead {
			return nil, fmt.Errorf("AppxManifest.xml exceeds %d byte cap", maxAppxManifestRead)
		}
		return uwpdetect.DetectFromManifestBytes(data)
	}
	return nil, nil
}
