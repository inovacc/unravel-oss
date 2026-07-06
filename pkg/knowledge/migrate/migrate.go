/*
Copyright (c) 2026 Security Research

Package migrate generates lazy, per-component cross-framework migration hints
against a knowledge directory produced by `unravel knowledge`.

Plan 07-04 contract (CONTEXT D-05..D-08, D-25, D-26):
  - One hint per component cluster under <kbDir>/sources/<component>/.
  - Output: <kbDir>/migrations/<framework>/<component>/migration.json + summary.md.
  - Lazy: only `unravel knowledge migrate` triggers MCP. The default
    `unravel knowledge` path MUST NOT import this package.
  - Framework whitelist enforced via IsValid (frameworks.go).
  - Prompt-injection defence: sentinel boundaries around user-supplied source
    content (T-07-03).
  - DoS defence: at most 8 representative files per cluster (largest by size,
    deduped by content SHA-256); rendered prompt body capped at 64 KiB
    (T-07-06).
  - CSS / unknown buckets are skipped silently (D-16 — CSS migration deferred).
*/
package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxRepresentativeFiles caps the number of files passed into the migration
// prompt body per component cluster (T-07-06).
const MaxRepresentativeFiles = 8

// MaxPromptBodyBytes caps the rendered prompt body size before invoking MCP
// (T-07-06). 64 KiB matches the upper bound used by the daemon-bridge MCP
// surface and keeps us well below the per-call token ceiling.
const MaxPromptBodyBytes = 64 << 10

// skippedBuckets are component buckets that intentionally do not produce
// migration hints in this phase. CSS migration is deferred (D-16); `unknown`
// is skipped to avoid noisy hints on unclassified files.
var skippedBuckets = map[string]bool{
	"css":     true,
	"unknown": true,
}

// MCPClient is the package-local interface the migrate flow expects from
// callers. The cmd/ wiring supplies a real implementation; tests supply a
// stub. Defined here to keep the migrate package free of any direct MCP
// SDK import.
type MCPClient interface {
	GenerateHint(ctx context.Context, prompt string) (MigrationHint, error)
}

// componentCluster collects every source file under <kb>/sources/<component>/.
type componentCluster struct {
	component string
	files     []clusterFile
}

type clusterFile struct {
	abs     string // absolute path on disk
	rel     string // path relative to kbDir, slash-form, used in prompt
	size    int64
	content []byte
	hash    string
}

// GenerateForFramework writes per-component migration hints under
// <kbDir>/migrations/<framework>/. mcp may be nil — in which case every
// cluster errors and is logged (per-component, non-fatal). Returns the
// first hard error (path traversal, unknown framework). Per-component MCP
// errors are recorded via slog and do not abort the run.
func GenerateForFramework(ctx context.Context, kbDir, framework string, mcp MCPClient) error {
	if !IsValid(framework) {
		return fmt.Errorf("migrate: unknown target framework %q (valid: %s)",
			framework, strings.Join(ValidFrameworks(), ", "))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	abs, err := absKB(kbDir)
	if err != nil {
		return err
	}
	clusters, err := discoverClusters(abs)
	if err != nil {
		return fmt.Errorf("discover clusters: %w", err)
	}
	if len(clusters) == 0 {
		return nil
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for _, c := range clusters {
		if skippedBuckets[c.component] {
			continue
		}
		if err := generateOne(ctx, abs, framework, c, mcp); err != nil {
			logger.Warn("knowledge.migrate: cluster failed",
				"component", c.component,
				"framework", framework,
				"err", err)
			continue
		}
	}
	return nil
}

// absKB normalises kbDir to an absolute path and rejects `..` segments
// in the raw input (T-07-01 carry-forward).
func absKB(kbDir string) (string, error) {
	if kbDir == "" {
		return "", errors.New("migrate: kbDir is required")
	}
	for _, seg := range strings.Split(filepath.ToSlash(kbDir), "/") {
		if seg == ".." {
			return "", errPathTraversal
		}
	}
	abs, err := filepath.Abs(filepath.Clean(kbDir))
	if err != nil {
		return "", fmt.Errorf("resolve abs: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat kbDir: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("migrate: kbDir is not a directory: %s", abs)
	}
	return abs, nil
}

// discoverClusters walks <kb>/sources/<component>/ and returns one cluster
// per immediate subdirectory. Components are sorted by name for stable
// emission order.
func discoverClusters(kbAbs string) ([]componentCluster, error) {
	srcRoot := filepath.Join(kbAbs, "sources")
	info, err := os.Stat(srcRoot)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat sources/: %w", err)
	}
	if !info.IsDir() {
		return nil, nil
	}
	entries, err := os.ReadDir(srcRoot)
	if err != nil {
		return nil, fmt.Errorf("read sources/: %w", err)
	}
	var clusters []componentCluster
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Refuse to follow symlinked component dirs (T-07-02 carry-forward).
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		comp := e.Name()
		dir := filepath.Join(srcRoot, comp)
		files, err := collectClusterFiles(kbAbs, dir)
		if err != nil {
			continue
		}
		if len(files) == 0 {
			continue
		}
		clusters = append(clusters, componentCluster{
			component: comp,
			files:     files,
		})
	}
	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i].component < clusters[j].component
	})
	return clusters, nil
}

// collectClusterFiles reads every regular file under compDir, skipping
// _meta.json provenance and any dotfile.
func collectClusterFiles(kbAbs, compDir string) ([]clusterFile, error) {
	var out []clusterFile
	err := filepath.WalkDir(compDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, ".") {
			return nil
		}
		if name == "_meta.json" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(kbAbs, p)
		if err != nil {
			rel = p
		}
		sum := sha256.Sum256(body)
		out = append(out, clusterFile{
			abs:     p,
			rel:     filepath.ToSlash(rel),
			size:    info.Size(),
			content: body,
			hash:    hex.EncodeToString(sum[:]),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// generateOne renders the prompt for a single cluster, calls MCP, and writes
// the resulting hint pair under <kb>/migrations/<framework>/<component>/.
func generateOne(ctx context.Context, kbAbs, framework string, c componentCluster, mcp MCPClient) error {
	if mcp == nil {
		return errors.New("nil MCP client")
	}
	picked := pickRepresentativeFiles(c.files)
	prompt, picked, err := renderBoundedPrompt(framework, c.component, picked)
	if err != nil {
		return err
	}
	hint, err := mcp.GenerateHint(ctx, prompt)
	if err != nil {
		return fmt.Errorf("mcp.GenerateHint: %w", err)
	}
	// Force schema invariants regardless of what MCP returned.
	hint.SchemaVersion = 1
	hint.Component = c.component
	hint.Framework = framework
	if hint.Equivalents == nil {
		hint.Equivalents = map[string]string{}
	}
	if _, ok := hint.Equivalents[framework]; !ok {
		hint.Equivalents[framework] = ""
	}
	_ = picked // future: stash picked file paths in hint provenance
	dir := filepath.Join(kbAbs, "migrations", framework, c.component)
	return writeHint(hint, dir)
}

// pickRepresentativeFiles returns up to MaxRepresentativeFiles entries from
// files, deduplicated by content SHA-256 and sorted by descending size.
// Sorting is stable on (size desc, rel asc) for deterministic output.
func pickRepresentativeFiles(files []clusterFile) []clusterFile {
	if len(files) == 0 {
		return nil
	}
	sorted := make([]clusterFile, len(files))
	copy(sorted, files)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].size != sorted[j].size {
			return sorted[i].size > sorted[j].size
		}
		return sorted[i].rel < sorted[j].rel
	})
	seen := map[string]bool{}
	var out []clusterFile
	for _, f := range sorted {
		if seen[f.hash] {
			continue
		}
		seen[f.hash] = true
		out = append(out, f)
		if len(out) >= MaxRepresentativeFiles {
			break
		}
	}
	return out
}

// renderBoundedPrompt renders the prompt template and, if the body exceeds
// MaxPromptBodyBytes, drops the smallest files until it fits. Returns the
// rendered prompt and the actual file slice used (for diagnostics).
func renderBoundedPrompt(framework, component string, files []clusterFile) (string, []clusterFile, error) {
	cur := append([]clusterFile(nil), files...)
	for {
		rendered, err := renderPrompt(toTemplateData(framework, component, cur))
		if err != nil {
			return "", nil, err
		}
		if len(rendered) <= MaxPromptBodyBytes || len(cur) == 0 {
			return rendered, cur, nil
		}
		// Drop the smallest file. Files are size-desc, so pop the tail.
		cur = cur[:len(cur)-1]
	}
}

// toTemplateData converts the picked clusterFile slice into the template's
// view shape.
func toTemplateData(framework, component string, files []clusterFile) templateData {
	tf := make([]templateFile, 0, len(files))
	for _, f := range files {
		tf = append(tf, templateFile{Path: f.rel, Content: string(f.content)})
	}
	return templateData{
		Framework: framework,
		Component: component,
		Files:     tf,
	}
}
