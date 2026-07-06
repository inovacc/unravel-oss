/*
Copyright (c) 2026 Security Research
*/

package analyze

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/andybalholm/brotli"

	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/webview2/udf"
)

// maxDecodedBodyBytes bounds a single decompressed cache body (T-84-05).
const maxDecodedBodyBytes = 8 * 1024 * 1024

type srcKind int

const (
	srcNone srcKind = iota
	srcJS
	srcCSS
)

// decodeCacheBody returns the decompressed body. Chromium blockfile stores the
// transport body verbatim (Content-Encoding not stripped); EBWebView bodies
// are predominantly brotli, sometimes gzip, occasionally identity. Try brotli,
// then gzip, then raw. Bounded; never panics.
func decodeCacheBody(body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return nil, false
	}
	if br := brotli.NewReader(bytes.NewReader(body)); br != nil {
		if out, err := io.ReadAll(io.LimitReader(br, maxDecodedBodyBytes)); err == nil && len(out) > 0 {
			return out, true
		}
	}
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		if gz, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if out, rerr := io.ReadAll(io.LimitReader(gz, maxDecodedBodyBytes)); rerr == nil && len(out) > 0 {
				return out, true
			}
		}
	}
	if len(body) > maxDecodedBodyBytes {
		return body[:maxDecodedBodyBytes], true
	}
	return body, true
}

// sniffSource classifies decoded bytes as JS or CSS by conservative content
// markers (blockfile entries carry no URL/Content-Type). Binary or ambiguous
// payloads return srcNone (never speculative).
func sniffSource(b []byte) srcKind {
	if len(b) < minRecoveredJSSourceBytes {
		return srcNone
	}
	lim := min(len(b), 4096)
	n := 0
	for _, c := range b[:lim] {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) {
			n++
		}
	}
	if n*100/lim < 85 {
		return srcNone
	}
	s := string(b[:lim])
	if looksLikeJSSource(b[:lim]) {
		return srcJS
	}
	cssScore := strings.Count(s, "@media") + strings.Count(s, "{display") +
		strings.Count(s, "px;") + strings.Count(s, "rgba(") +
		strings.Count(s, "@font-face") + strings.Count(s, "!important")
	if cssScore >= 2 {
		return srcCSS
	}
	return srcNone
}

// recoverProfileHTTPCacheSource parses the profile's HTTP blockfile cache via
// the existing pkg/cache parser (no binary-format hand-roll), decodes each
// saved body, and content-sniffs JS/CSS source. Absent cache or zero decodable
// source => empty slices (honest-empty, never synthesized).
func recoverProfileHTTPCacheSource(profilePath string) ([]RecoveredJSEntry, []RecoveredCSSEntry) {
	cacheDir := filepath.Join(profilePath, filepath.FromSlash(udf.CacheSubdir))
	if !exists(cacheDir) {
		return nil, nil
	}
	if isSymlink(cacheDir) {
		slog.Warn("webview2 httpcache: symlink rejected", "path", cacheDir)
		return nil, nil
	}
	tmp, err := os.MkdirTemp("", "wv2-httpcache-")
	if err != nil {
		return nil, nil
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	pr, perr := cache.Parse(cacheDir, tmp)
	if perr != nil || pr == nil || len(pr.Entries) == 0 {
		return nil, nil
	}

	var js []RecoveredJSEntry
	var css []RecoveredCSSEntry
	bodiesDir := filepath.Join(tmp, "bodies")
	_ = filepath.Walk(bodiesDir, func(p string, fi os.FileInfo, werr error) error {
		if werr != nil || fi == nil || fi.IsDir() {
			return nil
		}
		if len(js)+len(css) >= maxRecoveredJSEntries {
			return filepath.SkipAll
		}
		raw, rerr := readBoundedFile(p, maxRecoveredJSEntryBytes)
		if rerr != nil || len(raw) == 0 {
			return nil
		}
		dec, ok := decodeCacheBody(raw)
		if !ok {
			return nil
		}
		switch sniffSource(dec) {
		case srcJS:
			js = append(js, RecoveredJSEntry{Path: p, Source: string(dec)})
		case srcCSS:
			css = append(css, RecoveredCSSEntry{Path: p, Source: string(dec)})
		case srcNone:
		}
		if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			slog.Debug("webview2 httpcache: classified body", "path", p, "bytes", len(dec))
		}
		return nil
	})
	return js, css
}
