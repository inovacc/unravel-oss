/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/inovacc/unravel-oss/internal/ai/prompts"
)

// BeautifyOptions configures Orchestrator.Run.
type BeautifyOptions struct {
	AIEnabled   bool
	Model       string
	Concurrency int
}

// RunOptions are the original run-level parameters forwarded into the
// manifest. They are independent of the decompile Run() options.
type RunOptions struct {
	Output           string
	Input            string
	Mode             string
	IncludeFramework bool
	Concurrency      int
}

// BeautifyReport is the orchestrator return value.
type BeautifyReport struct {
	RunID          string                  `json:"run_id"`
	OutputDir      string                  `json:"output_dir"`
	Assemblies     []AssemblyManifestEntry `json:"assemblies"`
	BeautifiedTree string                  `json:"beautified_tree,omitempty"`
	RawTree        string                  `json:"raw_tree"`
	Errors         []string                `json:"errors,omitempty"`
}

// Orchestrator drives the per-assembly walk → beautify → write pipeline.
type Orchestrator struct {
	ai         Beautifier
	opts       BeautifyOptions
	promptHash string
}

// NewOrchestrator constructs an Orchestrator. ai may be nil when
// opts.AIEnabled is false.
func NewOrchestrator(ai Beautifier, opts BeautifyOptions) *Orchestrator {
	return &Orchestrator{
		ai:         ai,
		opts:       opts,
		promptHash: prompts.PromptHash("csharp"),
	}
}

// Run walks every successfully-decompiled assembly's raw tree, runs
// BeautifyFile per .cs (when AIEnabled), writes a parallel beautified
// tree, and emits per-assembly _meta.json (in BOTH trees) plus run-level
// manifest.json.
func (o *Orchestrator) Run(ctx context.Context, dr *Result, runOpts RunOptions) (*BeautifyReport, error) {
	if dr == nil {
		return nil, fmt.Errorf("Orchestrator.Run: nil decompile result")
	}

	startedAt := time.Now().UTC()
	out, err := sanitizeOutPath("", runOpts.Output)
	if err != nil {
		return nil, fmt.Errorf("Run: output: %w", err)
	}
	rawRoot := filepath.Join(out, "raw")
	beautifiedRoot := filepath.Join(out, "beautified")

	conc := o.opts.Concurrency
	if conc <= 0 {
		conc = runtime.GOMAXPROCS(0) / 2
	}
	if conc < 1 {
		conc = 1
	}

	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, conc)

	mfEntries := make([]AssemblyManifestEntry, len(dr.Assemblies))
	var mu sync.Mutex

	for i, asm := range dr.Assemblies {
		i, asm := i, asm
		if !asm.Decompiled {
			mfEntries[i] = AssemblyManifestEntry{
				Name:      asm.Name,
				SHA256:    asm.SHA256,
				RawPath:   asm.OutDir,
				FileCount: asm.FileCount,
				Errors:    nonEmptyErr(asm.Err),
			}
			continue
		}

		g.Go(func() error {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-gctx.Done():
				return nil
			}

			entry, err := o.processAssembly(gctx, asm, dr.ILSpyVersion, rawRoot, beautifiedRoot)
			if err != nil {
				entry.Errors = append(entry.Errors, err.Error())
			}
			mu.Lock()
			mfEntries[i] = entry
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	// Build & write the run manifest.
	rm := RunManifest{
		RunID:            NewRunID(),
		StartedAt:        startedAt,
		EndedAt:          time.Now().UTC(),
		ILSpyCmdVersion:  dr.ILSpyVersion,
		AIModel:          o.opts.Model,
		PromptHash:       o.promptHash,
		PromptPath:       "pkg/ai/prompts/csharp.md",
		AIEnabled:        o.opts.AIEnabled,
		Input:            runOpts.Input,
		InputMode:        runOpts.Mode,
		IncludeFramework: runOpts.IncludeFramework,
		Concurrency:      runOpts.Concurrency,
		Assemblies:       mfEntries,
		Errors:           dr.Errors,
	}
	if err := WriteRunManifest(out, rm); err != nil {
		return nil, fmt.Errorf("write run manifest: %w", err)
	}

	report := &BeautifyReport{
		RunID:      rm.RunID,
		OutputDir:  out,
		Assemblies: mfEntries,
		RawTree:    rawRoot,
	}
	if o.opts.AIEnabled {
		report.BeautifiedTree = beautifiedRoot
	}
	return report, nil
}

// processAssembly handles a single decompiled assembly: walks its raw
// tree, beautifies each .cs (when AI enabled), writes parallel
// beautified tree, and emits per-assembly _meta.json in both trees.
func (o *Orchestrator) processAssembly(
	ctx context.Context,
	asm AssemblyResult,
	ilspyVersion string,
	rawRoot, beautifiedRoot string,
) (AssemblyManifestEntry, error) {
	entry := AssemblyManifestEntry{
		Name:       asm.Name,
		SHA256:     asm.SHA256,
		Decompiled: true,
		RawPath:    asm.OutDir,
		FileCount:  0,
	}

	rawAsmDir := asm.OutDir
	beautAsmDir := filepath.Join(beautifiedRoot, sanitizeAsmName(asm.Name))
	if o.opts.AIEnabled {
		entry.BeautifiedPath = beautAsmDir
	}

	rawMeta := AssemblyMeta{
		Assembly:           asm.Name,
		SHA256:             asm.SHA256,
		ILSpyCmdVersion:    ilspyVersion,
		DecompileStartedAt: time.Now().UTC(),
	}
	beautMeta := AssemblyMeta{
		Assembly:           asm.Name,
		SHA256:             asm.SHA256,
		ILSpyCmdVersion:    ilspyVersion,
		DecompileStartedAt: time.Now().UTC(),
	}

	// Walk the raw tree.
	type fileItem struct {
		fullPath string
		relPath  string
	}
	var files []fileItem
	_ = filepath.WalkDir(rawAsmDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(p), ".cs") {
			return nil
		}
		rel, rerr := filepath.Rel(rawAsmDir, p)
		if rerr != nil {
			return nil
		}
		files = append(files, fileItem{fullPath: p, relPath: rel})
		return nil
	})

	allBeautified := o.opts.AIEnabled
	for _, fi := range files {
		raw, rerr := os.ReadFile(fi.fullPath)
		if rerr != nil {
			rawMeta.Errors = append(rawMeta.Errors, fmt.Sprintf("%s: read: %v", fi.relPath, rerr))
			continue
		}

		entry.FileCount++
		fmRaw := FileMeta{
			Path:        fi.relPath,
			SizeRaw:     int64(len(raw)),
			Beautified:  false,
			NameQuality: "raw",
		}

		if !o.opts.AIEnabled {
			rawMeta.Files = append(rawMeta.Files, fmRaw)
			continue
		}

		// Run beautify.
		beautBytes, fr, berr := BeautifyFile(ctx, o.ai, raw)
		if berr != nil {
			fmRaw.Errors = append(fmRaw.Errors, berr.Error())
		}

		fmBeaut := FileMeta{
			Path:        fi.relPath,
			SizeRaw:     int64(len(raw)),
			NameQuality: "beautified",
		}
		if fr != nil {
			fmBeaut.ChunkCount = fr.ChunkCount
			fmRaw.ChunkCount = fr.ChunkCount
			fmBeaut.Beautified = fr.Beautified
			if !fr.Beautified {
				fmBeaut.Errors = append(fmBeaut.Errors, "fallback to raw: "+fr.Reason)
				allBeautified = false
			}
		}

		// Compose final beautified file: provenance header + body.
		header := HeaderInput{
			ILSpyVersion:  ilspyVersion,
			Model:         o.opts.Model,
			PromptName:    "csharp",
			PromptHash:    o.promptHash,
			RawRel:        filepath.ToSlash(filepath.Join("raw", sanitizeAsmName(asm.Name), fi.relPath)),
			BeautifiedRel: filepath.ToSlash(filepath.Join("beautified", sanitizeAsmName(asm.Name), fi.relPath)),
			Timestamp:     time.Now().UTC(),
		}

		dst := filepath.Join(beautAsmDir, fi.relPath)
		dstAbs, perr := sanitizeOutPath(beautifiedRoot, dst)
		if perr != nil {
			fmBeaut.Errors = append(fmBeaut.Errors, "sanitize: "+perr.Error())
			rawMeta.Files = append(rawMeta.Files, fmRaw)
			beautMeta.Files = append(beautMeta.Files, fmBeaut)
			allBeautified = false
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dstAbs), 0o755); err != nil {
			fmBeaut.Errors = append(fmBeaut.Errors, "mkdir: "+err.Error())
			rawMeta.Files = append(rawMeta.Files, fmRaw)
			beautMeta.Files = append(beautMeta.Files, fmBeaut)
			allBeautified = false
			continue
		}

		if err := writeWithHeader(dstAbs, header, beautBytes); err != nil {
			fmBeaut.Errors = append(fmBeaut.Errors, "write: "+err.Error())
			allBeautified = false
		} else {
			fmBeaut.SizeBeautified = int64(len(beautBytes))
		}

		rawMeta.Files = append(rawMeta.Files, fmRaw)
		beautMeta.Files = append(beautMeta.Files, fmBeaut)
	}

	rawMeta.DecompileEndedAt = time.Now().UTC()
	beautMeta.DecompileEndedAt = rawMeta.DecompileEndedAt

	// Always write the raw _meta.json.
	if err := WriteAssemblyMeta(rawAsmDir, rawMeta); err != nil {
		entry.Errors = append(entry.Errors, fmt.Sprintf("raw _meta.json: %v", err))
	}
	if o.opts.AIEnabled {
		if err := os.MkdirAll(beautAsmDir, 0o755); err == nil {
			if err := WriteAssemblyMeta(beautAsmDir, beautMeta); err != nil {
				entry.Errors = append(entry.Errors, fmt.Sprintf("beautified _meta.json: %v", err))
			}
		}
	}

	entry.Beautified = allBeautified && o.opts.AIEnabled
	return entry, nil
}

// writeWithHeader prepends the provenance header to body and atomically
// writes the result to path.
func writeWithHeader(path string, h HeaderInput, body []byte) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := WriteHeader(&buf, h); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	buf.Write(body)

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cs-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}

func nonEmptyErr(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// sha256Hex returns lowercase hex sha256 of b. Helper kept here to
// avoid leaking into other files.
//
//nolint:unused // referenced by tests
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
