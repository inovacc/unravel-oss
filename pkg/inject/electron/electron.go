/*
Copyright (c) 2026 Security Research
*/

// Package electron implements the Electron seam scanner registered into the
// pkg/inject orchestrator. It enumerates code-injection seams (preload-script,
// browser-window-pref:*, command-line-switch:remote-debugging,
// executejavascript-call) by static analysis of an installed/extracted
// Electron app directory.
//
// Pure scan-only per phase 16 D-05. No process spawn, no network attach.
package electron

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/inject"
)

// scanner is the package-private Scanner implementation. It is wired into the
// global registry in init().
type scanner struct{}

// Framework returns the framework token this scanner emits.
func (scanner) Framework() inject.Framework { return inject.FrameworkElectron }

// Detect returns true when appDir looks like an Electron app:
//   - resources/app.asar exists, OR
//   - resources/app/package.json or package.json declares an `electron` dep.
func (scanner) Detect(appDir string) bool {
	if appDir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(appDir, "resources", "app.asar")); err == nil {
		return true
	}
	candidates := []string{
		filepath.Join(appDir, "package.json"),
		filepath.Join(appDir, "resources", "app", "package.json"),
	}
	return slices.ContainsFunc(candidates, hasElectronDep)
}

// hasElectronDep checks a package.json for an `electron` entry under
// dependencies, devDependencies, or peerDependencies.
func hasElectronDep(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var pkg struct {
		Dependencies     map[string]string `json:"dependencies"`
		DevDependencies  map[string]string `json:"devDependencies"`
		PeerDependencies map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return false
	}
	for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies} {
		if _, ok := m["electron"]; ok {
			return true
		}
	}
	return false
}

// Scan walks the Electron app dir, locates main.js (filesystem or ASAR),
// and emits seams via static regex matching. Per-call errors are returned but
// never panic; the orchestrator (16-01) swallows them gracefully.
func (scanner) Scan(ctx context.Context, appDir string) ([]inject.Seam, error) {
	if appDir == "" {
		return nil, errors.New("electron: empty appDir")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	source, err := loadMainJS(appDir)
	if err != nil {
		return nil, err
	}
	if source.content == "" {
		return nil, nil
	}

	return analyzeMainJS(appDir, source), nil
}

// mainSource carries the main.js content plus the on-disk path used for
// evidence reporting.
type mainSource struct {
	content      string
	evidencePath string
	// fromASAR signals the source was extracted from an ASAR archive — used
	// by the obfuscation heuristic since webpacked bundles are common there.
	fromASAR bool
}

// loadMainJS attempts to locate and read main.js from common Electron layouts.
//
// Lookup order:
//  1. resources/app/main.js, resources/app/index.js, resources/app/app.js
//  2. resources/app.asar — extract main.js / index.js / app.js entries
//  3. main.js / index.js / app.js at appDir root (some unpacked builds)
func loadMainJS(appDir string) (mainSource, error) {
	candidates := []string{"main.js", "index.js", "app.js"}

	// 1. resources/app/<candidate>
	for _, name := range candidates {
		p := filepath.Join(appDir, "resources", "app", name)
		if data, err := os.ReadFile(p); err == nil {
			return mainSource{content: string(data), evidencePath: p}, nil
		}
	}

	// 2. resources/app.asar
	asarPath := filepath.Join(appDir, "resources", "app.asar")
	if _, err := os.Stat(asarPath); err == nil {
		if src, ok := readMainFromASAR(asarPath, candidates); ok {
			return src, nil
		}
	}

	// 3. appDir root
	for _, name := range candidates {
		p := filepath.Join(appDir, name)
		if data, err := os.ReadFile(p); err == nil {
			return mainSource{content: string(data), evidencePath: p}, nil
		}
	}

	return mainSource{}, nil
}

// readMainFromASAR opens an ASAR archive and returns the first matching
// candidate's contents. Errors are non-fatal — the caller falls through to
// next lookup tier.
func readMainFromASAR(asarPath string, candidates []string) (mainSource, bool) {
	file, header, _, dataOffset, err := asar.OpenAndParse(asarPath)
	if err != nil {
		return mainSource{}, false
	}
	defer func() { _ = file.Close() }()

	flat := asar.CollectFiles(header.Files, "")
	wanted := map[string]struct{}{}
	for _, c := range candidates {
		wanted[c] = struct{}{}
	}
	for _, ef := range flat {
		if ef.IsDir {
			continue
		}
		base := filepath.Base(ef.Path)
		if _, ok := wanted[base]; !ok {
			continue
		}
		// Prefer a top-level entry over nested ones; CollectFiles returns
		// sorted order so first hit is fine.
		data, rerr := asar.ReadFileContent(file, dataOffset, ef.Offset, ef.Size)
		if rerr != nil {
			continue
		}
		return mainSource{
			content:      string(data),
			evidencePath: asarPath + "!" + ef.Path,
			fromASAR:     true,
		}, true
	}
	return mainSource{}, false
}

// Pre-compiled regex set for static seam detection. Each is intentionally
// permissive enough to survive minor minification / re-quoting.
var (
	// preload: "..." or preload: '...' — captures the path string.
	rePreload = regexp.MustCompile(`preload\s*:\s*(['"\x60])([^'"\x60]+)['"\x60]`)
	// preload: path.join(__dirname, "preload.js") — captures last string arg.
	rePreloadJoin = regexp.MustCompile(`preload\s*:\s*[A-Za-z_$][\w$]*\.join\([^)]*['"\x60]([^'"\x60]+\.js)['"\x60]\s*\)`)

	// webPreferences boolean fields with literal value.
	reNodeIntegration   = regexp.MustCompile(`nodeIntegration\s*:\s*(true|false|!0|!1)`)
	reContextIsolation  = regexp.MustCompile(`contextIsolation\s*:\s*(true|false|!0|!1)`)
	reSandbox           = regexp.MustCompile(`sandbox\s*:\s*(true|false|!0|!1)`)
	reNodeIntegrationKW = regexp.MustCompile(`\bnodeIntegration\b`)
	reContextIsolKW     = regexp.MustCompile(`\bcontextIsolation\b`)
	reSandboxKW         = regexp.MustCompile(`\bsandbox\b`)

	// BrowserWindow constructor / webPreferences object literal.
	reWebPreferences = regexp.MustCompile(`webPreferences\s*[:=]\s*\{`)
	// `new BrowserWindow(...)` constructor — used to detect framework-default
	// inference cases (constructor present, no webPreferences anchor).
	reBrowserWindowCtor = regexp.MustCompile(`\bnew\s+BrowserWindow\s*\(`)

	// app.commandLine.appendSwitch("remote-debugging-port", ...) and
	// appendArgument variants. Also catches abbreviated/minified accessors.
	reRemoteDebug = regexp.MustCompile(`(?i)appendSwitch\s*\(\s*['"\x60]remote-debugging-port['"\x60]`)
	reInspectFlag = regexp.MustCompile(`--inspect(?:-brk)?(?:=\d+)?`)

	// webContents.executeJavaScript("...") call sites.
	reExecuteJS = regexp.MustCompile(`\.executeJavaScript\s*\(`)
)

// analyzeMainJS runs the regex set over the source and produces seams.
func analyzeMainJS(appDir string, src mainSource) []inject.Seam {
	var seams []inject.Seam
	hasWebPref := reWebPreferences.MatchString(src.content)
	bundleObfuscated := looksObfuscated(src.content)

	// --- preload-script ---
	if m := rePreload.FindStringSubmatch(src.content); m != nil {
		seams = append(seams, makePreloadSeam(appDir, src, m[2], false))
	} else if m := rePreloadJoin.FindStringSubmatch(src.content); m != nil {
		seams = append(seams, makePreloadSeam(appDir, src, m[1], true))
	}

	// --- browser-window-pref:nodeIntegration ---
	if m := reNodeIntegration.FindStringSubmatch(src.content); m != nil {
		conf := inject.ConfidenceHigh
		if bundleObfuscated {
			conf = inject.ConfidenceMedium
		}
		seams = append(seams, prefSeam("browser-window-pref:nodeIntegration",
			conf, src, "nodeIntegration:"+m[1]))
	} else if (hasWebPref || bundleObfuscated) && reNodeIntegrationKW.MatchString(src.content) {
		seams = append(seams, prefSeam("browser-window-pref:nodeIntegration",
			inject.ConfidenceMedium, src, "nodeIntegration (value not pinned)"))
	}

	// --- browser-window-pref:contextIsolation ---
	if m := reContextIsolation.FindStringSubmatch(src.content); m != nil {
		conf := inject.ConfidenceHigh
		if bundleObfuscated {
			conf = inject.ConfidenceMedium
		}
		seams = append(seams, prefSeam("browser-window-pref:contextIsolation",
			conf, src, "contextIsolation:"+m[1]))
	} else if (hasWebPref || bundleObfuscated) && reContextIsolKW.MatchString(src.content) {
		seams = append(seams, prefSeam("browser-window-pref:contextIsolation",
			inject.ConfidenceMedium, src, "contextIsolation (value not pinned)"))
	}

	// --- browser-window-pref:sandbox ---
	if m := reSandbox.FindStringSubmatch(src.content); m != nil {
		conf := inject.ConfidenceHigh
		if bundleObfuscated {
			conf = inject.ConfidenceMedium
		}
		seams = append(seams, prefSeam("browser-window-pref:sandbox",
			conf, src, "sandbox:"+m[1]))
	} else if (hasWebPref || bundleObfuscated) && reSandboxKW.MatchString(src.content) {
		seams = append(seams, prefSeam("browser-window-pref:sandbox",
			inject.ConfidenceMedium, src, "sandbox (value not pinned)"))
	}

	// --- framework-default inference (D-03 low) ---
	// BrowserWindow constructed without an explicit webPreferences block:
	// reviewers should know the seams exist by virtue of framework defaults.
	if !hasWebPref && reBrowserWindowCtor.MatchString(src.content) {
		seams = append(seams, prefSeam("browser-window-pref:nodeIntegration",
			inject.ConfidenceLow, src, "no webPreferences; framework default applies"))
		seams = append(seams, prefSeam("browser-window-pref:contextIsolation",
			inject.ConfidenceLow, src, "no webPreferences; framework default applies"))
		seams = append(seams, prefSeam("browser-window-pref:sandbox",
			inject.ConfidenceLow, src, "no webPreferences; framework default applies"))
	}

	// --- command-line-switch:remote-debugging ---
	if reRemoteDebug.MatchString(src.content) {
		seams = append(seams, inject.Seam{
			Kind:       "command-line-switch:remote-debugging",
			Confidence: inject.ConfidenceHigh,
			Framework:  inject.FrameworkElectron,
			Evidence: []inject.Evidence{{
				Type: inject.EvidenceFileContent, Path: src.evidencePath,
				Snippet: "appendSwitch(\"remote-debugging-port\", ...)",
			}},
			ReachableRuntime: true,
			Notes:            "explicit remote debugging port",
		})
	} else if reInspectFlag.MatchString(src.content) {
		seams = append(seams, inject.Seam{
			Kind:       "command-line-switch:remote-debugging",
			Confidence: inject.ConfidenceMedium,
			Framework:  inject.FrameworkElectron,
			Evidence: []inject.Evidence{{
				Type: inject.EvidenceFileContent, Path: src.evidencePath,
				Snippet: "--inspect/--inspect-brk literal",
			}},
			ReachableRuntime: true,
			Notes:            "inspector flag literal in main",
		})
	}

	// --- executejavascript-call ---
	if reExecuteJS.MatchString(src.content) {
		conf := inject.ConfidenceHigh
		notes := "executeJavaScript call site"
		if bundleObfuscated {
			conf = inject.ConfidenceMedium
			notes = "executeJavaScript call site in obfuscated bundle"
		}
		seams = append(seams, inject.Seam{
			Kind:       "executejavascript-call",
			Confidence: conf,
			Framework:  inject.FrameworkElectron,
			Evidence: []inject.Evidence{{
				Type: inject.EvidenceFileContent, Path: src.evidencePath,
				Snippet: ".executeJavaScript(",
			}},
			ReachableRuntime: true,
			Notes:            notes,
		})
	}

	return seams
}

// makePreloadSeam builds the preload-script seam. When the resolved path can
// be stat'd inside appDir, confidence is bumped to high; otherwise medium.
func makePreloadSeam(appDir string, src mainSource, preloadPath string, joined bool) inject.Seam {
	conf := inject.ConfidenceMedium
	notes := "preload path string only"

	resolved := resolvePreloadPath(appDir, src, preloadPath)
	if resolved != "" {
		if _, err := os.Stat(resolved); err == nil {
			conf = inject.ConfidenceHigh
			notes = "preload path verified on disk"
		}
	}

	snippet := fmt.Sprintf("preload: %q", preloadPath)
	if joined {
		snippet = fmt.Sprintf("preload: path.join(..., %q)", preloadPath)
	}

	return inject.Seam{
		Kind:       "preload-script",
		Confidence: conf,
		Framework:  inject.FrameworkElectron,
		Evidence: []inject.Evidence{{
			Type:    inject.EvidenceFileContent,
			Path:    src.evidencePath,
			Snippet: snippet,
		}},
		ReachableRuntime: true,
		Notes:            notes,
	}
}

// resolvePreloadPath turns the in-source preload string into a candidate
// on-disk path. Absolute paths are returned as-is; relative paths are
// resolved against likely main.js base directories.
func resolvePreloadPath(appDir string, src mainSource, preloadPath string) string {
	if filepath.IsAbs(preloadPath) {
		return preloadPath
	}
	if src.fromASAR {
		// ASAR-embedded preload — we can't stat without extraction. Caller
		// stays at medium confidence. Return empty so Stat below fails.
		return ""
	}
	base := filepath.Dir(src.evidencePath)
	return filepath.Join(base, preloadPath)
}

// prefSeam constructs a webPreferences-derived seam.
func prefSeam(kind string, conf inject.Confidence, src mainSource, snippet string) inject.Seam {
	return inject.Seam{
		Kind:       kind,
		Confidence: conf,
		Framework:  inject.FrameworkElectron,
		Evidence: []inject.Evidence{{
			Type:    inject.EvidenceFileContent,
			Path:    src.evidencePath,
			Snippet: snippet,
		}},
		ReachableRuntime: true,
	}
}

// looksObfuscated is a tiny heuristic: average line length > 200 chars suggests
// a webpack/minified bundle. Used to demote confidence when only regex hits
// are available.
func looksObfuscated(content string) bool {
	if len(content) < 400 {
		return false
	}
	lines := strings.Count(content, "\n") + 1
	avg := len(content) / lines
	return avg > 200
}

// silence unused-import warnings for io / strconv if a future refactor drops
// uses; cheap insurance for a security-research package that grows often.
var _ = io.EOF
var _ = strconv.Itoa

func init() { inject.RegisterScanner(scanner{}) }
