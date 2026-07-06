/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

// BeautifyFunc is the optional per-module beautification adapter
// (chains pkg/jsdeob.BeautifyAI from 06-02 when --beautify is set).
// Returning (bytes, frameworkJSON, err) keeps the orchestrator
// independent of jsdeob's package types.
type BeautifyFunc func(ctx context.Context, src []byte, modulePath string) (out []byte, frameworkJSON string, err error)

// RunOptions configures Run.
type RunOptions struct {
	// Input is the bundle file path. Sanitised via filepath.Abs +
	// path-traversal guard (T-06-01).
	Input string
	// Output is the directory under which modules/, _module_index.json
	// and manifest.json are written. Sanitised similarly.
	Output string
	// UseMCP enables Pass 2 MCP fallback (passed through to
	// Reconstruct).
	UseMCP bool
	// Beautify when true invokes Beautifier (per-module
	// jsdeob.BeautifyAI) on each recovered module.
	Beautify bool
	// AIClient is the Pass-2 Beautifier (boundary detection).
	AIClient Beautifier
	// BeautifierFn is the optional per-module beautifier adapter.
	BeautifierFn BeautifyFunc
	// Concurrency caps parallel per-module workers. Default
	// max(1, GOMAXPROCS/2).
	Concurrency int
}

// RunReport summarises one Run invocation.
type RunReport struct {
	BundleKind    Kind   `json:"bundle_kind"`
	ModulesCount  int    `json:"modules_count"`
	NamedCount    int    `json:"named_count"`
	UnnamedCount  int    `json:"unnamed_count"`
	UsedMCP       bool   `json:"used_mcp"`
	ManifestPath  string `json:"manifest_path"`
	IndexPath     string `json:"index_path"`
	OutputDir     string `json:"output_dir"`
	BeautifyCount int    `json:"beautify_count,omitempty"`
}

// Manifest is the schema written to <out>/manifest.json (D-25).
type Manifest struct {
	RunID                 string            `json:"run_id"`
	BundleKind            Kind              `json:"bundle_kind"`
	UsedMCP               bool              `json:"used_mcp"`
	ModulesCount          int               `json:"modules_count"`
	NamedCount            int               `json:"named_count"`
	UnnamedCount          int               `json:"unnamed_count"`
	ModuleIDRecoveredName map[string]string `json:"module_id_recovered_name"`
	FrameworkSummary      map[string]int    `json:"framework_summary,omitempty"`
	Errors                []string          `json:"errors,omitempty"`
}

// IndexEntry is one row of <out>/_module_index.json.
type IndexEntry struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path"`
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Source string `json:"source"`
}

var reSanitiseName = regexp.MustCompile(`[^A-Za-z0-9_]+`)

// Run is the top-level orchestrator: reads bundle, runs Reconstruct,
// writes the D-13 layout, optionally chains per-module beautification.
func Run(ctx context.Context, opts RunOptions) (rep *RunReport, err error) {
	defer func() {
		if r := recover(); r != nil {
			rep = nil
			err = fmt.Errorf("bundle_run_panic: %v", r)
		}
	}()

	// 1. Sanitise paths (T-06-01).
	if opts.Input == "" || opts.Output == "" {
		return nil, fmt.Errorf("input and output required")
	}
	inAbs, err := safePath(opts.Input)
	if err != nil {
		return nil, fmt.Errorf("input: %w", err)
	}
	outAbs, err := safePath(opts.Output)
	if err != nil {
		return nil, fmt.Errorf("output: %w", err)
	}

	// 2. Reject symlink input (T-06-06).
	if info, lerr := os.Lstat(inAbs); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("input is symlink, refusing")
		}
	}

	src, err := os.ReadFile(inAbs)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	// 3. Reconstruct.
	res, err := Reconstruct(ctx, src, Options{UseMCP: opts.UseMCP, AIClient: opts.AIClient})
	if err != nil {
		return nil, fmt.Errorf("reconstruct: %w", err)
	}

	// 4. Mkdir layout. Use atomic writes (D-24).
	modulesDir := filepath.Join(outAbs, "modules")
	unnamedDir := filepath.Join(modulesDir, "_unnamed")
	if err := os.MkdirAll(unnamedDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir output: %w", err)
	}
	var beautifyDir string
	if opts.Beautify {
		beautifyDir = filepath.Join(modulesDir, "_beautified")
		if err := os.MkdirAll(beautifyDir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir beautify: %w", err)
		}
		metaDir := filepath.Join(modulesDir, "_meta")
		if err := os.MkdirAll(metaDir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir meta: %w", err)
		}
	}

	// 5. Bounded parallel: walk proposals.
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = max(runtime.GOMAXPROCS(0)/2, 1)
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	type entry struct {
		idx           int
		entryRow      IndexEntry
		frameworkJSON string
		beautified    bool
	}
	var (
		mu         sync.Mutex
		entries    = make([]entry, 0, len(res.Modules))
		errs       []string
		idMapping  = make(map[string]string)
		fwSummary  = make(map[string]int)
		beautifyOK int
	)

	for i, p := range res.Modules {
		g.Go(func() error {
			if p.Start < 0 || p.End > len(src) || p.End <= p.Start {
				return nil
			}
			slice := src[p.Start:p.End]
			id := p.ModuleID
			if id == "" {
				id = strconv.Itoa(i)
			}
			row := IndexEntry{
				ID:     id,
				Name:   p.CandidateName,
				Start:  p.Start,
				End:    p.End,
				Source: p.Source,
			}
			var rel string
			if p.CandidateName != "" {
				name := sanitiseName(p.CandidateName)
				if name == "" {
					name = "unnamed_" + id
				}
				rel = filepath.Join("modules", name+".js")
			} else {
				rel = filepath.Join("modules", "_unnamed", id+".js")
			}
			full := filepath.Join(outAbs, rel)
			if werr := atomicWriteSafe(full, slice); werr != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("write %s: %v", rel, werr))
				mu.Unlock()
				return nil
			}
			row.Path = filepath.ToSlash(rel)

			ent := entry{idx: i, entryRow: row}

			// Optional beautify chain.
			if opts.Beautify && opts.BeautifierFn != nil {
				bbytes, fwJSON, berr := opts.BeautifierFn(gctx, slice, full)
				if berr != nil {
					mu.Lock()
					errs = append(errs, fmt.Sprintf("beautify %s: %v", rel, berr))
					mu.Unlock()
				} else {
					beautRel := filepath.Join("modules", "_beautified", filepath.Base(rel))
					if werr := atomicWriteSafe(filepath.Join(outAbs, beautRel), bbytes); werr == nil {
						ent.beautified = true
						ent.frameworkJSON = fwJSON
					}
					if fwJSON != "" {
						metaName := strings.TrimSuffix(filepath.Base(rel), ".js") + ".json"
						_ = atomicWriteSafe(filepath.Join(outAbs, "modules", "_meta", metaName), []byte(fwJSON))
					}
				}
			}

			mu.Lock()
			entries = append(entries, ent)
			if p.CandidateName != "" {
				idMapping[id] = p.CandidateName
			}
			if ent.frameworkJSON != "" {
				fwSummary[ent.frameworkJSON]++
			}
			if ent.beautified {
				beautifyOK++
			}
			mu.Unlock()
			return nil
		})
	}
	if werr := g.Wait(); werr != nil {
		errs = append(errs, werr.Error())
	}

	// 6. Build manifest + index.
	named := 0
	unnamed := 0
	indexRows := make([]IndexEntry, 0, len(entries))
	for _, e := range entries {
		indexRows = append(indexRows, e.entryRow)
		if e.entryRow.Name != "" {
			named++
		} else {
			unnamed++
		}
	}

	indexPath := filepath.Join(outAbs, "_module_index.json")
	if data, jerr := json.MarshalIndent(indexRows, "", "  "); jerr == nil {
		if werr := atomicWriteSafe(indexPath, data); werr != nil {
			errs = append(errs, fmt.Sprintf("write _module_index.json: %v", werr))
		}
	}

	for _, e := range res.Errors {
		errs = append(errs, e)
	}

	man := Manifest{
		RunID:                 randomRunID(),
		BundleKind:            res.Kind,
		UsedMCP:               res.UsedMCP,
		ModulesCount:          len(indexRows),
		NamedCount:            named,
		UnnamedCount:          unnamed,
		ModuleIDRecoveredName: idMapping,
		FrameworkSummary:      fwSummary,
		Errors:                errs,
	}
	manifestPath := filepath.Join(outAbs, "manifest.json")
	if data, jerr := json.MarshalIndent(man, "", "  "); jerr == nil {
		if werr := atomicWriteSafe(manifestPath, data); werr != nil {
			errs = append(errs, fmt.Sprintf("write manifest.json: %v", werr))
		}
	}

	rep = &RunReport{
		BundleKind:    res.Kind,
		ModulesCount:  len(indexRows),
		NamedCount:    named,
		UnnamedCount:  unnamed,
		UsedMCP:       res.UsedMCP,
		ManifestPath:  manifestPath,
		IndexPath:     indexPath,
		OutputDir:     outAbs,
		BeautifyCount: beautifyOK,
	}
	return rep, nil
}

// safePath rejects path-traversal segments and returns the absolute,
// cleaned path (T-06-01).
func safePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.Contains(p, "..") {
		// Coarse check — also enforced via filepath.Clean below.
		return "", fmt.Errorf("path contains '..': %q", p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// sanitiseName strips non-`[A-Za-z0-9_]` characters from a recovered
// module name so it is safe to use as a filename component.
func sanitiseName(in string) string {
	out := reSanitiseName.ReplaceAllString(in, "_")
	return strings.Trim(out, "_")
}

// atomicWriteSafe writes data to p via a temp file in the same dir,
// then renames (D-24). Refuses to follow a symlink at p (T-06-06).
func atomicWriteSafe(p string, data []byte) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(p); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink: %q", p)
		}
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

// randomRunID returns a 16-hex-char random run identifier.
func randomRunID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}
