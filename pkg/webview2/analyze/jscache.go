/*
Copyright (c) 2026 Security Research
*/

package analyze

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/webview2/udf"
)

// RecoveredJSEntry is a single JS *source* blob recovered from a Chromium
// V8 Code Cache or Service Worker ScriptCache entry. It is the original
// script text (header skipped) — never decompiled V8 bytecode (Research A1
// / §Don't Hand-Roll).
type RecoveredJSEntry struct {
	// Path is the on-disk cache-entry path the source was recovered from
	// (forensic citation anchor).
	Path string `json:"path"`
	// Source is the recovered JavaScript source text.
	Source string `json:"source"`
}

// RecoveredCSSEntry is a single CSS *source* blob recovered from the
// EBWebView HTTP cache (brotli/gzip-decoded). Forensic clean-room artifact.
type RecoveredCSSEntry struct {
	Path   string `json:"path"`
	Source string `json:"source"`
}

const (
	// maxRecoveredJSWalkDepth bounds the cache walk, mirroring the depth-6
	// bound used elsewhere in this package (analyze.go containsSymlink).
	maxRecoveredJSWalkDepth = 6
	// maxRecoveredJSEntryBytes bounds a single cache-entry read so a
	// hostile/huge file cannot exhaust memory (T-84-05).
	maxRecoveredJSEntryBytes = 8 * 1024 * 1024
	// maxRecoveredJSEntries bounds the total recovered set per profile.
	maxRecoveredJSEntries = 512
	// minRecoveredJSSourceBytes filters trivially small/garbage payloads
	// that carry no forensic JS value.
	minRecoveredJSSourceBytes = 8
)

// recoverProfileCachedJS performs a bounded, read-only walk of the profile's
// "Code Cache/js" and "Service Worker/ScriptCache" trees and extracts the
// cached JS *source*. Chromium stores the script source alongside the V8
// bytecode in these entries; we surface the source bytes and skip the V8
// code-cache header — we never decompile bytecode (Research A1).
//
// All failures are non-fatal: a malformed/garbage entry is skipped (a
// recover() guards each entry) and never panics or fabricates content. An
// absent tree yields zero entries (analyzed-empty, never synthesized).
func recoverProfileCachedJS(profilePath string) []RecoveredJSEntry {
	var out []RecoveredJSEntry
	for _, sub := range []string{
		filepath.FromSlash(udf.ServiceWorkerScriptCacheSubdir),
	} {
		root := filepath.Join(profilePath, sub)
		if !exists(root) {
			continue
		}
		if isSymlink(root) {
			slog.Warn("webview2 jscache: symlink rejected", "path", root)
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if len(out) >= maxRecoveredJSEntries {
				return fs.SkipAll
			}
			// Bound walk depth (mirror analyze.go depth-6 bound).
			if rel, relErr := filepath.Rel(root, path); relErr == nil && rel != "." {
				depth := 1 + strings.Count(rel, string(filepath.Separator))
				if depth > maxRecoveredJSWalkDepth {
					if d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
			}
			if d.IsDir() {
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				slog.Warn("webview2 jscache: symlink entry skipped", "path", path)
				return nil
			}
			// Skip Chromium cache index/journal bookkeeping files.
			base := d.Name()
			if base == "index" || base == "index-dir" ||
				strings.HasPrefix(base, "the-real-index") {
				return nil
			}
			if e, ok := extractCachedJSSource(path); ok {
				out = append(out, e)
				// DEBUG: one line per recovered JS source, reusing the
				// size already known here. Gated behind slog DEBUG level
				// so it is silent unless --debug is on. No behavior change.
				if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
					slog.Debug("webview2 jscache: recovered JS source",
						"path", e.Path,
						"source_bytes", len(e.Source),
					)
				}
			}
			return nil
		})
	}
	return out
}

// extractCachedJSSource reads a single cache entry, skips the V8 code-cache
// header, and returns the recovered JS source. A defer-recover guards
// malformed inputs (safeScan discipline) so a hostile file is non-fatal.
func extractCachedJSSource(path string) (entry RecoveredJSEntry, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("webview2 jscache: recovered from panic parsing cache entry",
				"path", path, "panic", r)
			ok = false
		}
	}()

	data, rerr := readBoundedFile(path, maxRecoveredJSEntryBytes)
	if rerr != nil || len(data) == 0 {
		return RecoveredJSEntry{}, false
	}
	src := skipV8CodeCacheHeader(data)
	if len(src) < minRecoveredJSSourceBytes {
		return RecoveredJSEntry{}, false
	}
	if !looksLikeJSSource(src) {
		return RecoveredJSEntry{}, false
	}
	return RecoveredJSEntry{Path: path, Source: string(src)}, true
}

// skipV8CodeCacheHeader strips the leading V8 code-cache framing so the
// returned slice begins at the JS source text. The cache entry layout is
// version-specific binary framing followed by the UTF-8 source; rather than
// parse the (unstable) V8 header we locate the first plausible JS source
// offset. We never decompile bytecode (Research A1 / §Don't Hand-Roll).
func skipV8CodeCacheHeader(data []byte) []byte {
	// Find the first run of printable ASCII that looks like JS source. The
	// header is a short binary preamble; the source follows verbatim.
	for i := range data {
		b := data[i]
		if b == '\t' || b == '\n' || b == '\r' || (b >= 0x20 && b < 0x7f) {
			// Require a minimal printable run to avoid false starts on a
			// stray printable byte inside the binary header.
			run := 0
			for j := i; j < len(data) && run < minRecoveredJSSourceBytes; j++ {
				c := data[j]
				if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) {
					run++
					continue
				}
				break
			}
			if run >= minRecoveredJSSourceBytes {
				return data[i:]
			}
		}
	}
	return nil
}

// readBoundedFile reads at most max bytes from path. A file smaller than
// max (the common case) yields a valid partial buffer; a mid-stream I/O
// fault is surfaced so the caller skips a truncated read (honest-empty).
func readBoundedFile(path string, max int) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // forensic read of a resolved cache path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, max)
	n, rerr := io.ReadFull(f, buf)
	if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
		return nil, rerr
	}
	return buf[:n], nil
}

// jsSourceMarkers are conservative tokens that indicate the recovered bytes
// are genuine JS source (not arbitrary printable binary). Recovery is
// evidence-based, never speculative.
var jsSourceMarkers = []string{
	"function", "=>", "var ", "let ", "const ", "return", "self.",
	"window.", "document.", "addEventListener", "require(", "import ",
	"=function", "){", "});",
}

// looksLikeJSSource is a cheap structural gate so binary garbage that
// happens to contain a printable run is not surfaced as "recovered JS".
func looksLikeJSSource(b []byte) bool {
	s := string(b)
	for _, m := range jsSourceMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}
