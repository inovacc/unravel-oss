/*
Copyright (c) 2026 Security Research
*/

package analyze

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/leveldb"
	"github.com/inovacc/unravel-oss/pkg/webview2/udf"
)

// ProfileInfo is a local alias-compatible shape for a Chromium profile
// (Name + Path). It avoids an import cycle with the parent webview2 package.
type ProfileInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// ProfileBlock holds per-profile extraction summaries produced by the
// analyze orchestrator. Payloads are stored as opaque values to avoid
// forcing callers into transitive CGO dependencies (via pkg/chromium).
type ProfileBlock struct {
	Profile        ProfileInfo `json:"profile"`
	CachePath      string      `json:"cache_path,omitempty"`
	CacheSummary   any         `json:"cache_summary,omitempty"`
	LocalStorage   any         `json:"local_storage,omitempty"`
	SessionStorage any         `json:"session_storage,omitempty"`
	IndexedDBs     []any       `json:"indexed_dbs,omitempty"`
	Cookies        any         `json:"cookies,omitempty"`
	Preferences    any         `json:"preferences,omitempty"`
	SecurePrefs    any         `json:"secure_prefs,omitempty"`
	Errors         []string    `json:"errors,omitempty"`
}

// UDFResult is the output of AnalyzeUDF: enumerated profiles plus per-profile
// extraction blocks. It is a local shape so this package does not import
// pkg/webview2 (avoiding an import cycle with the root package which
// composes these results into a webview2.Result).
type UDFResult struct {
	Profiles    []ProfileInfo
	ProfileData []ProfileBlock
	// RecoveredJS holds JS *source* recovered from each profile's V8 Code
	// Cache / Service Worker ScriptCache (header skipped, never bytecode).
	// Empty when no cache tree is present (analyzed-empty, never synthesized).
	RecoveredJS []RecoveredJSEntry
	// RecoveredCSS holds CSS source recovered from the HTTP cache (decoded).
	RecoveredCSS []RecoveredCSSEntry
}

// Options tunes Analyze behavior. Zero value yields conservative defaults
// (all extractors on; symlinks rejected).
type Options struct {
	// ExtractCache toggles HTTP cache parsing via pkg/cache. Default: true.
	ExtractCache bool
	// ExtractLevelDB toggles LevelDB (Local Storage, Session Storage,
	// IndexedDB) parsing via pkg/leveldb. Default: true.
	ExtractLevelDB bool
	// ExtractCookies toggles Cookies SQLite parsing. Default: true.
	// (Actual SQLite decryption requires CGO and is delegated to pkg/chromium.)
	ExtractCookies bool
	// MaxProfilesToScan limits how many profiles the orchestrator visits.
	// Zero means "all".
	MaxProfilesToScan int
	// RejectSymlinks makes the orchestrator skip any sub-path that is a
	// symlink, appending a warning to Result.Errors (V12 ASVS, T-03-07).
	// Default: true.
	RejectSymlinks bool
	// UDFOverride, when non-empty, forces the resolver to prepend this path
	// as a "override"-source candidate. If the override exists on disk, the
	// default-candidate resolution is short-circuited (D-02). Caller must
	// pre-sanitize against path traversal.
	UDFOverride string
}

// DefaultOptions returns the recommended orchestrator options.
func DefaultOptions() Options {
	return Options{
		ExtractCache:   true,
		ExtractLevelDB: true,
		ExtractCookies: true,
		RejectSymlinks: true,
	}
}

// Analyze orchestrates WebView2 data extraction against a single EBWebView
// directory by delegating to the existing Chromium parsers. It never
// re-implements any binary format (D-06/D-07/D-08, FRM-02, anti-pattern).
//
// Soft failures (missing subpaths, unreadable files) are appended to
// Result.Errors so the caller can see what happened. A hard error is only
// returned when the input ebWebViewDir itself cannot be traversed.
func Analyze(ebWebViewDir string, opts Options) (*UDFResult, error) {
	res := &UDFResult{}

	udfProfiles, err := udf.EnumerateProfiles(ebWebViewDir)
	if err != nil {
		return nil, err
	}
	for _, up := range udfProfiles {
		res.Profiles = append(res.Profiles, ProfileInfo{Name: up.Name, Path: up.Path})
	}

	limit := opts.MaxProfilesToScan
	for i, p := range res.Profiles {
		if limit > 0 && i >= limit {
			break
		}
		block := analyzeProfile(p, opts)
		res.ProfileData = append(res.ProfileData, block)
		// Code Cache / Service Worker ScriptCache JS-source recovery is
		// gated behind ExtractCache (already plumbed by analyze_uwp.go).
		// Read-only, bounded; absent tree => no entries (never synthesized).
		if opts.ExtractCache {
			if rec := recoverProfileCachedJS(p.Path); len(rec) > 0 {
				res.RecoveredJS = append(res.RecoveredJS, rec...)
			}
			hjs, hcss := recoverProfileHTTPCacheSource(p.Path)
			if len(hjs) > 0 {
				res.RecoveredJS = append(res.RecoveredJS, hjs...)
			}
			if len(hcss) > 0 {
				res.RecoveredCSS = append(res.RecoveredCSS, hcss...)
			}
		}
	}
	return res, nil
}

// analyzeProfile runs every enabled extractor against a single profile
// directory. All errors are captured in the returned ProfileBlock.Errors.
func analyzeProfile(p ProfileInfo, opts Options) ProfileBlock {
	block := ProfileBlock{Profile: p}

	if opts.RejectSymlinks {
		if isSymlink(p.Path) {
			block.Errors = append(block.Errors, fmt.Sprintf("symlink rejected: %s", p.Path))
			return block
		}
	}

	// HTTP cache
	if opts.ExtractCache {
		cachePath := filepath.Join(p.Path, filepath.FromSlash(udf.CacheSubdir))
		block.CachePath = cachePath
		if exists(cachePath) {
			if opts.RejectSymlinks && containsSymlink(cachePath) {
				block.Errors = append(block.Errors, fmt.Sprintf("symlink rejected in cache: %s", cachePath))
			} else {
				pr, err := cache.Parse(cachePath, "")
				if err != nil {
					block.Errors = append(block.Errors, fmt.Sprintf("cache parse: %v", err))
				} else {
					block.CacheSummary = pr
				}
			}
		}
	}

	// LevelDB: Local Storage, Session Storage, IndexedDB
	if opts.ExtractLevelDB {
		lsPath := filepath.Join(p.Path, filepath.FromSlash(udf.LocalStorageSubdir))
		if exists(lsPath) {
			if opts.RejectSymlinks && containsSymlink(lsPath) {
				block.Errors = append(block.Errors, fmt.Sprintf("symlink rejected in local storage: %s", lsPath))
			} else {
				pr, err := leveldb.ParseDirectory(lsPath)
				if err != nil {
					block.Errors = append(block.Errors, fmt.Sprintf("local storage parse: %v", err))
				} else {
					block.LocalStorage = pr
				}
			}
		}
		ssPath := filepath.Join(p.Path, filepath.FromSlash(udf.SessionStorageSubdir))
		if exists(ssPath) {
			if opts.RejectSymlinks && containsSymlink(ssPath) {
				block.Errors = append(block.Errors, fmt.Sprintf("symlink rejected in session storage: %s", ssPath))
			} else {
				pr, err := leveldb.ParseDirectory(ssPath)
				if err != nil {
					block.Errors = append(block.Errors, fmt.Sprintf("session storage parse: %v", err))
				} else {
					block.SessionStorage = pr
				}
			}
		}
		// IndexedDB: iterate <origin>.leveldb subfolders
		idbRoot := filepath.Join(p.Path, udf.IndexedDBSubdir)
		if exists(idbRoot) {
			entries, err := os.ReadDir(idbRoot)
			if err == nil {
				for _, e := range entries {
					if !e.IsDir() {
						continue
					}
					if !strings.HasSuffix(e.Name(), ".leveldb") {
						continue
					}
					idbPath := filepath.Join(idbRoot, e.Name())
					if opts.RejectSymlinks && isSymlink(idbPath) {
						block.Errors = append(block.Errors, fmt.Sprintf("symlink rejected in indexeddb: %s", idbPath))
						continue
					}
					pr, perr := leveldb.ParseDirectory(idbPath)
					if perr != nil {
						block.Errors = append(block.Errors, fmt.Sprintf("indexeddb parse %s: %v", e.Name(), perr))
						continue
					}
					block.IndexedDBs = append(block.IndexedDBs, pr)
				}
			}
		}
	}

	// Cookies SQLite: just record its presence and path; decryption is
	// deferred to pkg/chromium + pkg/dpapi (CGO-gated, D-06/D-14).
	if opts.ExtractCookies {
		cookiesPath := filepath.Join(p.Path, udf.NetworkSubdir, udf.CookiesFile)
		if exists(cookiesPath) {
			block.Cookies = map[string]any{
				"path":    cookiesPath,
				"present": true,
				"note":    "SQLite cookies DB; extract via pkg/chromium (CGO) + pkg/dpapi",
			}
		}
	}

	// Preferences + Secure Preferences
	prefPath := filepath.Join(p.Path, udf.PreferencesFile)
	if exists(prefPath) {
		doc, err := ParsePreferences(prefPath)
		if err != nil {
			block.Errors = append(block.Errors, fmt.Sprintf("preferences: %v", err))
		} else {
			block.Preferences = doc
		}
	}
	secPrefPath := filepath.Join(p.Path, udf.SecurePreferencesFile)
	if exists(secPrefPath) {
		doc, err := ParsePreferences(secPrefPath)
		if err != nil {
			block.Errors = append(block.Errors, fmt.Sprintf("secure preferences: %v", err))
		} else {
			block.SecurePrefs = doc
		}
	}

	return block
}

// exists returns true if path exists (via Lstat).
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// isSymlink returns true if path is itself a symbolic link.
func isSymlink(path string) bool {
	st, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return st.Mode()&fs.ModeSymlink != 0
}

// containsSymlink reports whether root or any descendant is a symlink
// (bounded to depth 6 to avoid runaway walks on huge LevelDB dirs).
func containsSymlink(root string) bool {
	if isSymlink(root) {
		return true
	}
	var hit bool
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			hit = true
			return fs.SkipAll
		}
		if rel, relErr := filepath.Rel(root, path); relErr == nil && rel != "." {
			depth := 1 + strings.Count(rel, string(filepath.Separator))
			if depth > 6 {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		return nil
	})
	return hit
}
