/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// Decompiler is the engine-selecting decompiler facade. For EngineILSpy it is
// the bounded-parallel orchestrator over ilspycmd; for EngineNative it drives
// the pure-Go clr reader.
type Decompiler struct {
	engine Engine
	bin    string // ilspy path; empty for native

	// onAcquire / onRelease are test-only hooks invoked after the semaphore
	// slot is acquired / released. nil in production. Used by
	// TestDecompiler_BoundedParallel to observe max-in-flight without
	// depending on inter-process counter files.
	onAcquire func()
	onRelease func()
}

// New constructs the default (native) Decompiler. Native is always available,
// so this never returns the ilspy install-hint error.
func New() (*Decompiler, error) {
	return NewWithEngine(EngineNative)
}

// NewWithEngine constructs a Decompiler for the requested engine. EngineILSpy
// resolves ilspycmd on PATH and returns the loud install-hint (D-03) on miss.
func NewWithEngine(e Engine) (*Decompiler, error) {
	switch e {
	case EngineNative:
		return &Decompiler{engine: EngineNative}, nil
	case EngineILSpy:
		bin, err := locateILSpy()
		if err != nil {
			return nil, err
		}

		return &Decompiler{engine: EngineILSpy, bin: bin}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownEngine, int(e))
	}
}

// Engine reports the configured backend.
func (d *Decompiler) Engine() Engine { return d.engine }

// Run decompiles either a single assembly or every eligible assembly in a
// full-app deps.json tree, writing raw .cs files under <opts.Output>/raw/<asm>/.
//
// Per-assembly errors are collected into Result.Errors and Result.Assemblies[i].Err
// (D-08); the run is never aborted by a single failure. Path traversal is
// rejected before any subprocess is spawned (D-04 / T-05-01).
func (d *Decompiler) Run(ctx context.Context, opts Options) (*Result, error) {
	res := &Result{StartedAt: time.Now().UTC()}

	defer func() {
		res.EndedAt = time.Now().UTC()
	}()

	// 1. Sanitize input + output before any subprocess work.
	inAbs, err := sanitizeOutPath("", opts.Input)
	if err != nil {
		return nil, fmt.Errorf("run: input: %w", err)
	}

	outAbs, err := sanitizeOutPath("", opts.Output)
	if err != nil {
		return nil, fmt.Errorf("run: output: %w", err)
	}

	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return nil, fmt.Errorf("run: mkdir output: %w", err)
	}

	// 2. Resolve mode.
	mode := opts.Mode
	if mode == ModeAuto {
		st, statErr := os.Stat(inAbs)
		if statErr != nil {
			return nil, fmt.Errorf("run: stat input: %w", statErr)
		}

		if st.IsDir() {
			mode = ModeFullApp
		} else {
			mode = ModeSingle
		}
	}

	// 2b. Native FullApp/capture must stream via a Sink (buffering a
	// LinkedIn-scale tree OOMs). Fail loudly before any walk work (INT-4).
	if d.engine == EngineNative && mode == ModeFullApp && opts.Sink == nil {
		return nil, fmt.Errorf("run: %w", ErrSinkRequired)
	}

	// 3. Walk.
	var assemblies []Assembly
	switch mode {
	case ModeSingle:
		assemblies, err = WalkSingle(inAbs)
	case ModeFullApp:
		assemblies, err = WalkFullApp(inAbs, opts.IncludeFramework)
	default:
		return nil, fmt.Errorf("run: unknown mode %d", mode)
	}
	if err != nil {
		return nil, fmt.Errorf("run: walk: %w", err)
	}

	// 3b. Native engine: pure-Go clr reader, no subprocess, no .cs output.
	if d.engine == EngineNative {
		return d.runNative(ctx, opts, mode, assemblies)
	}

	// 4. Detect ilspycmd version once.
	versionCtx, versionCancel := context.WithTimeout(ctx, 10*time.Second)
	res.ILSpyVersion = detectVersion(versionCtx, d.bin)
	versionCancel()

	// 5. Bounded parallel decompile.
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.GOMAXPROCS(0) / 2
	}
	if concurrency < 1 {
		concurrency = 1
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, concurrency)

	results := make([]AssemblyResult, len(assemblies))
	var mu sync.Mutex

	rawRoot := filepath.Join(outAbs, "raw")
	if err := os.MkdirAll(rawRoot, 0o755); err != nil {
		return nil, fmt.Errorf("run: mkdir raw: %w", err)
	}

	for i, asm := range assemblies {
		i, asm := i, asm

		g.Go(func() error {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-gctx.Done():
				return nil
			}

			if d.onAcquire != nil {
				d.onAcquire()
			}
			if d.onRelease != nil {
				defer d.onRelease()
			}

			ar := AssemblyResult{
				Name: asm.Name,
				Path: asm.Path,
			}

			// Per-assembly out dir under <out>/raw/<asmname>/ — sanitize again
			// to defend against pathological asm names (Pitfall #5 + T-05-06).
			candidate := filepath.Join(rawRoot, sanitizeAsmName(asm.Name))
			asmOut, err := sanitizeOutPath(rawRoot, candidate)
			if err != nil {
				ar.Err = fmt.Sprintf("sanitize out dir: %v", err)
				mu.Lock()
				results[i] = ar
				mu.Unlock()

				return nil
			}

			ar.OutDir = asmOut

			if err := os.MkdirAll(asmOut, 0o755); err != nil {
				ar.Err = fmt.Sprintf("mkdir out: %v", err)
				mu.Lock()
				results[i] = ar
				mu.Unlock()

				return nil
			}

			ar.SHA256 = hashFile(asm.Path)

			// Per-assembly timeout wraps the run.
			callCtx, cancel := context.WithTimeout(gctx, timeout)
			defer cancel()

			if err := runILSpyCmd(callCtx, d.bin, asm.Path, asmOut); err != nil {
				ar.Err = err.Error()
				mu.Lock()
				results[i] = ar
				mu.Unlock()

				return nil
			}

			// Count emitted .cs files.
			ar.FileCount = countCSFiles(asmOut)
			ar.Decompiled = true

			mu.Lock()
			results[i] = ar
			mu.Unlock()

			return nil
		})
	}

	_ = g.Wait()

	for _, ar := range results {
		res.Assemblies = append(res.Assemblies, ar)
		if ar.Err != "" {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %s", ar.Name, ar.Err))
		}
	}

	return res, nil
}

func sanitizeAsmName(name string) string {
	// Strip any path separators / traversal markers; keep only the basename.
	cleaned := filepath.Base(name)
	cleaned = strings.ReplaceAll(cleaned, "..", "_")

	if cleaned == "" || cleaned == "." {
		return "_unnamed"
	}

	return cleaned
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}

	return hex.EncodeToString(h.Sum(nil))
}

func countCSFiles(root string) int {
	count := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".cs") {
			count++
		}
		return nil
	})
	return count
}
