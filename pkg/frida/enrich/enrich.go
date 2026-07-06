// Copyright (c) 2026 Security Research
//
// Package enrich orchestrates AI-driven enrichment of Frida instrumentation
// scripts (Phase 9 / FRIDA-01). Mirrors the per-language orchestrator pattern
// established by pkg/knowledge/migrate (Phase 7) and pkg/jsdeob/beautify_ai.go
// (Phase 6).
//
// Inputs:
//   - scriptPath: path to a generated .frida.js produced by pkg/frida/generate.go.
//   - sourceDir : optional directory containing decompiled Java source for the
//     target classes referenced in the script (Phase 9 D-03).
//
// Outputs:
//   - The script file is atomically rewritten with JSDoc-style per-hook comments
//   - a top-level header summary (D-01, D-02).
//   - A sibling <script>.criteria.json is atomically written (D-06).
//
// Wave-0 spike (Java decompiler per-method API — RESEARCH OQ#2, capped at
// 30 minutes): the in-tree pure-Go decompiler exposes per-class decompilation
// under pkg/java/decompiler/{classfile,pipeline,writer}; per-method extraction
// is achievable by filtering Methods on the parsed ClassFile and routing only
// the desired bytecode through pipeline.Decompile. For Phase 9 first ship we
// defer in-process per-method invocation and instead consume already-decompiled
// text from sourceDir (caller may seed it via "unravel java decompile"). This
// keeps the orchestrator free of Java-decompiler imports.
//
// Threat model touch-points addressed in this file:
//   - T-09-02: every input path is filepath.Clean'd, abs-resolved, and rejected
//     if it contains a ".." segment.
//   - T-09-05: the decompiled-source bundle fed to MCP is capped at
//     MaxSourceBundleBytes (64 KiB) before render; oversize input is truncated.
package enrich

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/frida"
)

// MaxSourceBundleBytes caps the decompiled-source payload fed into the
// frida.md prompt body. Mirrors pkg/knowledge/migrate.MaxPromptBodyBytes.
const MaxSourceBundleBytes = 64 << 10

// Orchestrator is the top-level handle. The MCPClient seam (mcp_client.go)
// is the only AI dependency — production wires a real client; tests pass a
// stub. Mirrors migrate.MCPClient.
type Orchestrator struct {
	MCP MCPClient
	// CacheDir, when non-empty, overrides the default cache path. Used by
	// tests to redirect cache I/O to t.TempDir().
	CacheDir string
}

// New returns an Orchestrator with a no-op MCP client. Production callers
// should set MCP explicitly via the field after construction.
func New() *Orchestrator {
	return &Orchestrator{MCP: nilClient{}}
}

// Enrich is the entry point. It:
//  1. Loads scriptPath and the optional sourceDir bundle.
//  2. Computes the cache key (script || sourceBundle) and short-circuits on hit.
//  3. Renders the prompt with sentinel boundaries around user content.
//  4. Calls MCPClient.EnrichScript exactly once.
//  5. Renders JSDoc into the script + criteria.json sidecar.
//  6. Parse-checks the rewritten script (D-19) and writes both atomically.
func (o *Orchestrator) Enrich(ctx context.Context, scriptPath, sourceDir string) (*frida.EnrichedScript, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if o == nil || o.MCP == nil {
		return nil, errors.New("enrich: nil orchestrator or MCP client")
	}
	scriptAbs, err := safeAbs(scriptPath)
	if err != nil {
		return nil, err
	}
	scriptBytes, err := os.ReadFile(scriptAbs)
	if err != nil {
		return nil, fmt.Errorf("read script: %w", err)
	}
	bundle, err := loadSourceBundle(sourceDir)
	if err != nil {
		return nil, err
	}
	cacheKey := computeCacheKey(scriptBytes, bundle)
	if cached, ok := o.cacheLookup(cacheKey); ok {
		if err := writeArtifacts(scriptAbs, cached.script, cached.criteria); err != nil {
			return nil, err
		}
		out := &frida.EnrichedScript{
			ScriptPath:    scriptAbs,
			CriteriaPath:  criteriaSiblingPath(scriptAbs),
			Hooks:         cached.criteria.Hooks,
			CacheHit:      true,
			SchemaVersion: cached.criteria.SchemaVersion,
		}
		return out, nil
	}
	prompt := renderPrompt(string(scriptBytes), bundle)
	resp, err := o.MCP.EnrichScript(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("mcp.EnrichScript: %w", err)
	}
	enrichedScript, criteria, err := renderArtifacts(string(scriptBytes), resp, filepath.Base(scriptAbs))
	if err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	if err := parseCheck(enrichedScript); err != nil {
		return nil, fmt.Errorf("parse-check: %w", err)
	}
	if err := writeArtifacts(scriptAbs, enrichedScript, criteria); err != nil {
		return nil, err
	}
	o.cacheStore(cacheKey, cachedPair{script: enrichedScript, criteria: criteria})
	return &frida.EnrichedScript{
		ScriptPath:    scriptAbs,
		CriteriaPath:  criteriaSiblingPath(scriptAbs),
		Hooks:         criteria.Hooks,
		CacheHit:      false,
		SchemaVersion: criteria.SchemaVersion,
	}, nil
}

// safeAbs is the T-09-02 path-traversal gate.
func safeAbs(p string) (string, error) {
	if p == "" {
		return "", errors.New("enrich: empty path")
	}
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return "", errors.New("enrich: path traversal rejected")
		}
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("resolve abs: %w", err)
	}
	return abs, nil
}

// loadSourceBundle reads up to MaxSourceBundleBytes of files under sourceDir,
// concatenated with `// === <relpath> ===` separators. Empty sourceDir is
// allowed and returns an empty string. Refuses to follow symlinks (T-09-03).
func loadSourceBundle(sourceDir string) (string, error) {
	if sourceDir == "" {
		return "", nil
	}
	abs, err := safeAbs(sourceDir)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("stat sourceDir: %w", err)
	}
	if !info.IsDir() {
		body, err := os.ReadFile(abs)
		if err != nil {
			return "", fmt.Errorf("read sourceFile: %w", err)
		}
		return capBundle(string(body)), nil
	}
	type entry struct {
		rel  string
		body []byte
	}
	var collected []entry
	walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		rel, _ := filepath.Rel(abs, p)
		body, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		collected = append(collected, entry{rel: filepath.ToSlash(rel), body: body})
		return nil
	})
	if walkErr != nil {
		return "", fmt.Errorf("walk sourceDir: %w", walkErr)
	}
	sort.Slice(collected, func(i, j int) bool { return collected[i].rel < collected[j].rel })
	var b strings.Builder
	for _, e := range collected {
		if b.Len() >= MaxSourceBundleBytes {
			break
		}
		b.WriteString("// === ")
		b.WriteString(e.rel)
		b.WriteString(" ===\n")
		b.Write(e.body)
		b.WriteString("\n\n")
	}
	return capBundle(b.String()), nil
}

func capBundle(s string) string {
	if len(s) <= MaxSourceBundleBytes {
		return s
	}
	return s[:MaxSourceBundleBytes]
}

// criteriaSiblingPath maps `<dir>/foo.frida.js` → `<dir>/foo.criteria.json`.
// Falls back to appending `.criteria.json` when the input doesn't carry the
// expected `.frida.js` suffix.
func criteriaSiblingPath(scriptAbs string) string {
	const suffix = ".frida.js"
	if strings.HasSuffix(scriptAbs, suffix) {
		return strings.TrimSuffix(scriptAbs, suffix) + ".criteria.json"
	}
	return scriptAbs + ".criteria.json"
}
