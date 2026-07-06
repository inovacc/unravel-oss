/*
Copyright (c) 2026 Security Research
*/
package beautify

import (
	"bytes"
	"context"
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

// RunOptions are the run-level parameters forwarded into the manifest.
type RunOptions struct {
	Output      string
	Input       string
	Mode        string
	Concurrency int
}

// JarOutput is one entry in DecompileResult.Jars: a JAR/AAR that the
// upstream decompiler (pkg/java/decompiler) has already extracted into
// <RunOptions.Output>/raw/<jar>/. The orchestrator only consumes this —
// it never invokes the decompiler itself, honouring D-02
// (wrap-don't-extend).
type JarOutput struct {
	Path              string `json:"path"`
	Name              string `json:"name"`
	OutDir            string `json:"out_dir"` // <Output>/raw/<jar>
	Sha256            string `json:"sha256,omitempty"`
	DecompilerVersion string `json:"decompiler_version"`
	FileCount         int    `json:"file_count"`
	Decompiled        bool   `json:"decompiled"`
	Err               string `json:"err,omitempty"`
}

// DecompileResult is the input to Orchestrator.Run: a thin local struct
// (per D-21) describing what the upstream decompile pass produced. The
// caller is responsible for populating it before invoking Run.
type DecompileResult struct {
	DecompilerVersion string      `json:"decompiler_version"`
	Jars              []JarOutput `json:"jars"`
	Errors            []string    `json:"errors,omitempty"`
}

// BeautifyReport is the orchestrator return value.
type BeautifyReport struct {
	RunID          string             `json:"run_id"`
	OutputDir      string             `json:"output_dir"`
	Jars           []JarManifestEntry `json:"jars"`
	BeautifiedTree string             `json:"beautified_tree,omitempty"`
	RawTree        string             `json:"raw_tree"`
	Errors         []string           `json:"errors,omitempty"`
}

// Orchestrator drives the per-JAR walk → beautify → write pipeline.
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
		promptHash: prompts.PromptHash("java"),
	}
}

// Run walks every successfully-decompiled JAR's raw tree, runs
// BeautifyFile per .java (when AIEnabled), writes a parallel beautified
// tree, and emits per-JAR _meta.json (in BOTH trees) plus run-level
// manifest.json. ZERO modifications to pkg/java/decompiler/ — D-02.
func (o *Orchestrator) Run(ctx context.Context, dr *DecompileResult, runOpts RunOptions) (rep *BeautifyReport, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Orchestrator.Run panic: %v", r)
		}
	}()

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

	mfEntries := make([]JarManifestEntry, len(dr.Jars))
	var mu sync.Mutex

	for i, jar := range dr.Jars {
		i, jar := i, jar
		if !jar.Decompiled {
			mfEntries[i] = JarManifestEntry{
				Name:      jar.Name,
				SHA256:    jar.Sha256,
				RawPath:   jar.OutDir,
				FileCount: jar.FileCount,
				Errors:    nonEmptyErr(jar.Err),
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

			entry, perr := o.processJar(gctx, jar, dr.DecompilerVersion, rawRoot, beautifiedRoot)
			if perr != nil {
				entry.Errors = append(entry.Errors, perr.Error())
			}
			mu.Lock()
			mfEntries[i] = entry
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	rm := RunManifest{
		RunID:             NewRunID(),
		StartedAt:         startedAt,
		EndedAt:           time.Now().UTC(),
		Decompiler:        "java-decompiler",
		DecompilerVersion: dr.DecompilerVersion,
		AIModel:           o.opts.Model,
		PromptHash:        prompts.PromptHash("java"),
		PromptPath:        "pkg/ai/prompts/java.md",
		AIEnabled:         o.opts.AIEnabled,
		Input:             runOpts.Input,
		InputMode:         runOpts.Mode,
		Concurrency:       runOpts.Concurrency,
		Jars:              mfEntries,
		Errors:            dr.Errors,
	}
	if err := WriteRunManifest(out, rm); err != nil {
		return nil, fmt.Errorf("write run manifest: %w", err)
	}

	rep = &BeautifyReport{
		RunID:     rm.RunID,
		OutputDir: out,
		Jars:      mfEntries,
		RawTree:   rawRoot,
	}
	if o.opts.AIEnabled {
		rep.BeautifiedTree = beautifiedRoot
	}
	return rep, nil
}

// processJar handles a single decompiled JAR: walks its raw tree,
// beautifies each .java (when AI enabled), writes parallel beautified
// tree, and emits per-JAR _meta.json in both trees.
func (o *Orchestrator) processJar(
	ctx context.Context,
	jar JarOutput,
	decompilerVersion string,
	rawRoot, beautifiedRoot string,
) (JarManifestEntry, error) {
	entry := JarManifestEntry{
		Name:       jar.Name,
		SHA256:     jar.Sha256,
		Decompiled: true,
		RawPath:    jar.OutDir,
	}

	rawJarDir := jar.OutDir
	beautJarDir := filepath.Join(beautifiedRoot, sanitizeJarName(jar.Name))
	if o.opts.AIEnabled {
		entry.BeautifiedPath = beautJarDir
	}

	rawMeta := AssemblyMeta{
		Jar:                jar.Name,
		SHA256:             jar.Sha256,
		DecompilerVersion:  decompilerVersion,
		DecompileStartedAt: time.Now().UTC(),
	}
	beautMeta := AssemblyMeta{
		Jar:                jar.Name,
		SHA256:             jar.Sha256,
		DecompilerVersion:  decompilerVersion,
		DecompileStartedAt: time.Now().UTC(),
	}

	type fileItem struct {
		fullPath string
		relPath  string
	}
	var files []fileItem
	_ = filepath.WalkDir(rawJarDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(p), ".java") {
			return nil
		}
		rel, rerr := filepath.Rel(rawJarDir, p)
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

		header := HeaderInput{
			DecompilerVersion: decompilerVersion,
			Model:             o.opts.Model,
			PromptName:        "java",
			PromptHash:        o.promptHash,
			RawRel:            filepath.ToSlash(filepath.Join("raw", sanitizeJarName(jar.Name), fi.relPath)),
			BeautifiedRel:     filepath.ToSlash(filepath.Join("beautified", sanitizeJarName(jar.Name), fi.relPath)),
			Timestamp:         time.Now().UTC(),
		}

		dst := filepath.Join(beautJarDir, fi.relPath)
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

	if err := WriteAssemblyMeta(rawJarDir, rawMeta); err != nil {
		entry.Errors = append(entry.Errors, fmt.Sprintf("raw _meta.json: %v", err))
	}
	if o.opts.AIEnabled {
		if err := os.MkdirAll(beautJarDir, 0o755); err == nil {
			if err := WriteAssemblyMeta(beautJarDir, beautMeta); err != nil {
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
	tmp, err := os.CreateTemp(dir, ".java-*.tmp")
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
