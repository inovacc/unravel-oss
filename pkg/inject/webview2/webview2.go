/*
Copyright (c) 2026 Security Research
*/

// Package webview2 implements the inject.Scanner contract for WebView2-host
// applications. It detects via PE imports / AppxManifest (delegating to
// pkg/webview2/detect) and walks .cs/.cpp/.h/.hpp source files for the four
// known WebView2 injection seams (D-02):
//
//   - webview2-add-script
//   - webview2-resource-handler
//   - webview2-web-message
//   - webview2-additional-browser-args
package webview2

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/inject"
	pkgwv2 "github.com/inovacc/unravel-oss/pkg/webview2"
	wv2analyze "github.com/inovacc/unravel-oss/pkg/webview2/analyze"
)

// kind constants — single source of truth (see 16-CONTEXT D-02).
const (
	kindAddScript       = "webview2-add-script"
	kindResourceHandler = "webview2-resource-handler"
	kindWebMessage      = "webview2-web-message"
	kindBrowserArgs     = "webview2-additional-browser-args"
	kindDefaultRuntime  = "webview2-add-script:default-runtime"
	maxWalkDepth        = 6
	maxSnippet          = 200
)

// scanner is the WebView2 implementation of inject.Scanner.
type scanner struct{}

// Framework returns the constant identifier for this scanner.
func (scanner) Framework() inject.Framework { return inject.FrameworkWebView2 }

// Detect returns true when WebView2 evidence is present in appDir. Phase 18
// (INJ-FOL-01) broadens this from the narrow pkg/webview2/detect.DetectFromDirectory
// path (PE-imports only) to the composite signal pkg/webview2.Analyze
// produces — UDF presence (uwp-localcache), AppxManifest WV2 dependency,
// AND PE-imports of WebView2Loader.dll. This lights up the scanner on
// UWP-packaged WV2 hybrids (WhatsApp, Teams) that the narrow detector misses.
//
// Cheap options: skip LevelDB/cache/cookies extraction. We only need the
// IsWebView2 verdict; MaxProfilesToScan:1 avoids walking every profile dir.
func (scanner) Detect(appDir string) bool {
	if appDir == "" {
		return false
	}
	res, err := pkgwv2.Analyze(appDir, wv2analyze.Options{
		ExtractCache:      false,
		ExtractLevelDB:    false,
		ExtractCookies:    false,
		MaxProfilesToScan: 1,
		RejectSymlinks:    true,
	})
	if err != nil || res == nil {
		return false
	}
	return res.IsWebView2
}

// pattern bundles a kind with its detection regexp.
type pattern struct {
	kind string
	re   *regexp.Regexp
}

var (
	// AddScriptToExecuteOnDocumentCreated[Async] — both native + managed.
	reAddScript = regexp.MustCompile(`AddScriptToExecuteOnDocumentCreated(?:Async)?\b`)
	// AddWebResourceRequestedFilter — high.
	reResourceHandler = regexp.MustCompile(`AddWebResourceRequestedFilter\b`)
	// WebMessageReceived event subscription — `+= …WebMessageReceived` or
	// `WebMessageReceived +=` (avoids matching `WebMessageReceivedHandler` types
	// or arbitrary strings).
	reWebMessage = regexp.MustCompile(`WebMessageReceived\s*\+=|\+=\s*[^;]*WebMessageReceived\b|PostWebMessage[A-Za-z]*\b`)
	// AdditionalBrowserArguments — only when assigned a value containing one
	// of the known dangerous flags.
	reBrowserArgs = regexp.MustCompile(`AdditionalBrowserArguments`)
)

// argFlags are the substrings that elevate an AdditionalBrowserArguments
// assignment to a high-confidence seam (D-02).
var argFlags = []string{"--remote-debugging-port=", "--enable-features="}

// skipDirs are directories not walked for source patterns.
var skipDirs = map[string]struct{}{
	"node_modules": {},
	"bin":          {},
	"obj":          {},
	".git":         {},
	".vs":          {},
	"Debug":        {},
	"Release":      {},
}

// sourceExts is the set of extensions scanned for seam patterns.
var sourceExts = map[string]struct{}{
	".cs":  {},
	".cpp": {},
	".h":   {},
	".hpp": {},
}

// Scan walks appDir for source files and emits seams per D-02. When the
// runtime is detected but no source files were scanned, emits one
// low-confidence default-runtime seam.
func (scanner) Scan(ctx context.Context, appDir string) ([]inject.Seam, error) {
	if appDir == "" {
		return nil, nil
	}
	root := filepath.Clean(appDir)

	var seams []inject.Seam
	sourceFilesSeen := 0

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		// Bound depth.
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil && rel != "." {
			depth := 1 + strings.Count(rel, string(filepath.Separator))
			if depth > maxWalkDepth {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if _, ok := sourceExts[ext]; !ok {
			return nil
		}
		sourceFilesSeen++
		fileSeams := scanFile(path)
		seams = append(seams, fileSeams...)
		return nil
	})
	if walkErr != nil {
		return seams, walkErr
	}

	// No-seam fallback: runtime detected upstream (Detect=true) but Scan
	// found no concrete call-sites — either no source files at all, OR
	// source files that didn't match any seam pattern (e.g. vendored C
	// headers in a UWP install). Either way, emit one low-confidence
	// default-runtime seam so the report still reflects the surface.
	// Phase 18 INJ-FOL-01: gate widened from `sourceFilesSeen == 0` to
	// `len(seams) == 0` so vendored source trees don't suppress the
	// fallback.
	if len(seams) == 0 {
		seams = append(seams, inject.Seam{
			Kind:       kindDefaultRuntime,
			Confidence: inject.ConfidenceLow,
			Framework:  inject.FrameworkWebView2,
			Notes:      "WebView2 runtime present; no concrete call-sites in source — analyze decompiled output via pkg/dotnet/decompile if available",
		})
	}

	return seams, nil
}

// scanFile reads one source file line-by-line and returns matched seams.
// Errors (unreadable file, etc.) yield no seams — never fatal.
func scanFile(path string) []inject.Seam {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var out []inject.Seam
	scanner := bufio.NewScanner(f)
	// Allow long source lines (minified vendor headers etc.).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if reAddScript.MatchString(line) {
			out = append(out, mkSeam(kindAddScript, path, trimmed))
		}
		if reResourceHandler.MatchString(line) {
			out = append(out, mkSeam(kindResourceHandler, path, trimmed))
		}
		if reWebMessage.MatchString(line) {
			out = append(out, mkSeam(kindWebMessage, path, trimmed))
		}
		if reBrowserArgs.MatchString(line) {
			for _, flag := range argFlags {
				if strings.Contains(line, flag) {
					out = append(out, mkSeam(kindBrowserArgs, path, trimmed))
					break
				}
			}
		}
	}
	return out
}

// mkSeam constructs a high-confidence seam with file-content evidence.
func mkSeam(kind, path, snippet string) inject.Seam {
	if len(snippet) > maxSnippet {
		snippet = snippet[:maxSnippet]
	}
	return inject.Seam{
		Kind:       kind,
		Confidence: inject.ConfidenceHigh,
		Framework:  inject.FrameworkWebView2,
		Evidence: []inject.Evidence{{
			Type:    inject.EvidenceFileContent,
			Path:    path,
			Snippet: snippet,
		}},
	}
}

func init() { inject.RegisterScanner(scanner{}) }
