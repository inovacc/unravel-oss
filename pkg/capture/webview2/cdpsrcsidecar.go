/*
Copyright (c) 2026 Security Research
*/

// Package webview2 — CDP source sidecar.
//
// The webview2-attach command verifies a live CDP session but exits before
// the slow knowledge/dissect pipeline runs (by which time the true-UWP app
// may have idle-exited). To bridge that gap the attach command pulls the
// live JS/CSS while the session is still up and persists it here, keyed by
// the resolved package id, for a later dissect run to consume.
//
// This file is intentionally pure: it MUST NOT import pkg/knowledge/scorecard
// (scorecard imports pkg/capture/cdp; importing scorecard here would cycle).
// The PullSourcesOverCDP call lives in the cmd attach file, not here.
package webview2

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// cdpSidecarMaxBytes bounds the total marshaled sidecar at 32 MiB. The JS
// then CSS source set is truncated in order until the encoded payload fits.
const cdpSidecarMaxBytes = 32 << 20

// CDPSrcEntry is one recovered script or stylesheet.
type CDPSrcEntry struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

// CDPSourceSidecar is the persisted, deterministic on-disk shape.
type CDPSourceSidecar struct {
	PulledAt time.Time     `json:"pulled_at"`
	PkgKey   string        `json:"pkg_key"`
	JS       []CDPSrcEntry `json:"js"`
	CSS      []CDPSrcEntry `json:"css"`
}

// sanitizePkgKey strips path separators and unsafe characters so a hostile
// or odd package id can never produce traversal or escape the base dir.
func sanitizePkgKey(pkgKey string) string {
	var b strings.Builder
	for _, r := range pkgKey {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	s = strings.Trim(s, ".")
	if s == "" {
		s = "unknown"
	}
	return s
}

// cdpSidecarBaseLocal mirrors store.CacheDir's fallback chain but resolves
// LOCALAPPDATA → os.UserCacheDir() → os.TempDir() per the sidecar contract.
func cdpSidecarBaseLocal() string {
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return local
	}
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return dir
	}
	return os.TempDir()
}

// CDPSourceSidecarPath returns the deterministic sidecar file path for a
// package key:
//
//	<LOCALAPPDATA>/Unravel/cdp-src/<sanitized pkgKey>/sources.json
func CDPSourceSidecarPath(pkgKey string) string {
	return filepath.Join(cdpSidecarBaseLocal(), "Unravel", "cdp-src",
		sanitizePkgKey(pkgKey), "sources.json")
}

// WriteCDPSourceSidecar atomically persists the recovered JS/CSS for pkgKey.
//
// Honest-empty: if both slices are empty no file is written and ("", nil) is
// returned. The total encoded payload is bounded to 32 MiB by truncating the
// JS then CSS set in order; truncation never panics.
func WriteCDPSourceSidecar(pkgKey string, js []CDPSrcEntry, css []CDPSrcEntry) (string, error) {
	if len(js) == 0 && len(css) == 0 {
		return "", nil
	}

	sc := CDPSourceSidecar{
		PulledAt: time.Now().UTC(),
		PkgKey:   pkgKey,
		JS:       js,
		CSS:      css,
	}

	data, err := marshalBounded(sc)
	if err != nil {
		return "", fmt.Errorf("marshal cdp source sidecar: %w", err)
	}

	dst := CDPSourceSidecarPath(pkgKey)
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir cdp source sidecar dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "sources-*.json.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp cdp source sidecar: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", fmt.Errorf("write temp cdp source sidecar: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", fmt.Errorf("close temp cdp source sidecar: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		cleanup()
		return "", fmt.Errorf("rename cdp source sidecar: %w", err)
	}
	return dst, nil
}

// marshalBounded encodes sc as indented JSON, truncating JS then CSS entries
// in order until the payload is <= cdpSidecarMaxBytes. It always returns a
// valid (possibly truncated) encoding for a non-empty input.
func marshalBounded(sc CDPSourceSidecar) ([]byte, error) {
	for {
		data, err := json.MarshalIndent(sc, "", "  ")
		if err != nil {
			return nil, err
		}
		if len(data) <= cdpSidecarMaxBytes {
			return data, nil
		}
		switch {
		case len(sc.JS) > 0:
			sc.JS = sc.JS[:len(sc.JS)-1]
		case len(sc.CSS) > 0:
			sc.CSS = sc.CSS[:len(sc.CSS)-1]
		default:
			// Nothing left to drop; return the minimal (header-only) doc.
			return data, nil
		}
	}
}
