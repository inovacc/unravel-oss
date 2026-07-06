/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// metaSizeCap bounds the _meta.json sidecar to 256 KiB before unmarshal.
// T-07-01 (tampering): the sweep walker is reading attacker-influenced
// content from a teardown directory; a giant _meta.json could otherwise
// cause unbounded allocation.
const metaSizeCap = 256 << 10 // 262144

// metaSuffix is the per-source-file sidecar that carries beautify
// provenance (D-19/D-21). Sweep is provenance-driven: a beautified file
// only makes it into the KB if a sidecar is present (D-04).
const metaSuffix = "._meta.json"

// teardownMeta is the on-disk shape of a per-source _meta.json record.
// Only the two fields the sweep cares about are captured; the writer in
// 07-01 emits the full SourceMeta struct.
type teardownMeta struct {
	BeautifyProvenance string `json:"beautify_provenance"`
	RawSourcePath      string `json:"raw_source_path"`
}

// SweepTeardown walks teardownDir for every "*._meta.json" sidecar and
// emits one SourceFile per sidecar+payload pair. Files without a sidecar
// (raw decompiler output) are skipped per D-04 (KB carries beautified
// content only). Errors per-entry are logged via slog and do not abort
// the sweep — the caller may fall back to the raw-only KB shape.
//
// Default-cheap path (D-12): this function never invokes MCP and never
// triggers a beautifier. It only reads what 07-01's writer (or a prior
// --with-ai run) already produced.
func SweepTeardown(teardownDir string) ([]SourceFile, error) {
	if teardownDir == "" {
		return nil, errors.New("knowledge: empty teardown dir")
	}
	cleaned := filepath.Clean(teardownDir)
	info, err := os.Stat(cleaned)
	if err != nil {
		return nil, fmt.Errorf("stat teardown: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("teardown dir is not a directory: %s", cleaned)
	}

	var out []SourceFile
	walkErr := filepath.WalkDir(cleaned, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Per-path walk errors degrade to a warning so sweep is best-effort.
			slog.Warn("sweep walk error", "path", path, "error", walkErr)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), metaSuffix) {
			return nil
		}

		sf, ok, ferr := loadSweepEntry(cleaned, path)
		if ferr != nil {
			slog.Warn("sweep entry skipped", "meta", path, "error", ferr)
			return nil
		}
		if !ok {
			return nil
		}
		out = append(out, sf)
		return nil
	})
	if walkErr != nil {
		return out, fmt.Errorf("walk teardown: %w", walkErr)
	}
	return out, nil
}

// loadSweepEntry reads one *._meta.json sidecar plus its payload file.
// The returned bool reports whether the entry should be emitted; false +
// nil error means the entry was rejected by a soft policy (oversize meta,
// missing payload).
func loadSweepEntry(root, metaPath string) (SourceFile, bool, error) {
	// Bound _meta.json size before reading to mitigate T-07-01.
	st, err := os.Stat(metaPath)
	if err != nil {
		return SourceFile{}, false, fmt.Errorf("stat meta: %w", err)
	}
	if st.Size() > metaSizeCap {
		return SourceFile{}, false, fmt.Errorf("meta too large: %d bytes > cap %d", st.Size(), metaSizeCap)
	}
	mb, err := os.ReadFile(metaPath)
	if err != nil {
		return SourceFile{}, false, fmt.Errorf("read meta: %w", err)
	}
	var tm teardownMeta
	if err := json.Unmarshal(mb, &tm); err != nil {
		return SourceFile{}, false, fmt.Errorf("parse meta: %w", err)
	}

	payloadPath := strings.TrimSuffix(metaPath, metaSuffix)
	pSt, err := os.Stat(payloadPath)
	if err != nil {
		return SourceFile{}, false, fmt.Errorf("stat payload: %w", err)
	}
	if pSt.IsDir() {
		return SourceFile{}, false, errors.New("payload is a directory")
	}

	// Read full content. Files larger than 8 MiB still load atomically;
	// a future plan may stream them. The runWithAI orchestrator separately
	// caps any single source > 10 MiB before MCP delegation (T-07-06).
	content, err := os.ReadFile(payloadPath)
	if err != nil {
		return SourceFile{}, false, fmt.Errorf("read payload: %w", err)
	}

	rel, relErr := filepath.Rel(root, payloadPath)
	if relErr != nil {
		// Fall back to base name; absolute paths must not leak through.
		rel = filepath.Base(payloadPath)
	}

	sf := SourceFile{
		Path:               filepath.ToSlash(rel),
		Original:           filepath.ToSlash(rel),
		Size:               pSt.Size(),
		Content:            content,
		BeautifyProvenance: tm.BeautifyProvenance,
		RawSourcePath:      sanitizeRawSourcePath(tm.RawSourcePath),
	}
	return sf, true, nil
}

// sanitizeRawSourcePath enforces T-07-01 on the raw_source_path field that
// originates in attacker-influenced _meta.json. Any traversal segment or
// absolute path causes the field to be cleared rather than propagated into
// the manifest.
func sanitizeRawSourcePath(raw string) string {
	if raw == "" {
		return ""
	}
	slashed := filepath.ToSlash(raw)
	if filepath.IsAbs(slashed) || strings.HasPrefix(slashed, "/") {
		return ""
	}
	for _, seg := range strings.Split(slashed, "/") {
		if seg == ".." {
			return ""
		}
	}
	return slashed
}
