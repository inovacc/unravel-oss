/*
Copyright (c) 2026 Security Research

Phase 5 (FRM-04 + RECON-02): supplemental analyzer that fires on TypePE when
the binary turns out to be a managed .NET assembly. Per D-07 user resolution,
the supplemental triggers the FULL ilspycmd + AI beautify pipeline by default
(no flag-only mode).

Cost note (T-05-05, accepted): every managed PE encountered during dissect
invokes ilspycmd plus an AI beautification round per emitted .cs file when
AI credentials are configured. On batch dissect runs this is substantial.
Operators with cost concerns should run the standalone CLI with --no-ai or
skip the supplemental by avoiding TypePE dispatch (e.g., dissect single
non-PE inputs). The cheap IsManagedPE pre-check ensures non-managed PE
binaries are a no-op.
*/
package dissect

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/dotnet/decompile"
)

func init() {
	RegisterSupplementalAnalyzer(analyzeDotNetDecompile, detect.TypePE)
}

// analyzeDotNetDecompile is the supplemental TypePE analyzer that, when the
// binary is a managed .NET assembly, runs the full Phase 5 pipeline (raw
// decompile + AI beautification + provenance manifests) writing results into
// a workspace under the dissect output dir.
//
// Failures are recorded into r.Errors and never abort the dissect run. A
// defer/recover guards against panics from external decoder boundaries
// (D-20).
func analyzeDotNetDecompile(r *DissectResult, path string, opts Options) {
	defer func() {
		if rec := recover(); rec != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("dotnet decompile panic: %v", rec))
		}
	}()

	// Cheap pre-check (T-05-02 mitigation). Non-managed PEs return immediately.
	if !decompile.IsManagedPE(path) {
		return
	}

	// Native pure-Go CLR capture (FIX #1): read one TypeModule per TypeDef and
	// attach to the result so KB ingest can persist lang='cil' modules. This is
	// independent of the ilspy beautify track below — a native error MUST NOT
	// break the supplemental, so we warn and continue. Runs before outDir
	// derivation so it succeeds even when ilspycmd / the workspace is missing.
	if mods := nativeCLRModules(path); len(mods) > 0 {
		r.CLRModules = mods
	}

	// Derive a workspace dir under the teardown / temp dir.
	outDir := deriveDotNetDecompileOutDir(r, path, opts)
	if outDir == "" {
		r.Errors = append(r.Errors, "dotnet decompile: could not derive output dir")
		return
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("dotnet decompile: mkdir %s: %v", outDir, err))
		return
	}

	d, err := decompile.NewWithEngine(decompile.EngineILSpy)
	if err != nil {
		// ilspycmd missing → record actionable error and continue (the native
		// capture path is unaffected; this supplemental only feeds AI-beautify).
		r.Errors = append(r.Errors, fmt.Sprintf("dotnet decompile (ilspy supplemental): %v", err))
		return
	}

	ctx := context.Background()

	result, err := d.Run(ctx, decompile.Options{
		Input:  path,
		Output: outDir,
		Mode:   decompile.ModeSingle,
	})
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("dotnet decompile: %v", err))
		return
	}
	r.DotNetDecompile = result

	// D-07 full-decompile-by-default: invoke beautification when AI client
	// is constructible. Missing credentials downgrade to no-AI manifest.
	bopts := decompile.BeautifyOptions{AIEnabled: true}
	var beautifier decompile.Beautifier
	if client, cerr := ai.NewClient(); cerr == nil {
		beautifier = &dissectAIBeautifier{c: client}
	} else {
		bopts.AIEnabled = false
	}

	orch := decompile.NewOrchestrator(beautifier, bopts)
	report, err := orch.Run(ctx, result, decompile.RunOptions{
		Output: outDir,
		Input:  path,
		Mode:   "single",
	})
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("dotnet beautify: %v", err))
		return
	}
	r.DotNetBeautify = report
}

// dissectAIBeautifier adapts an *ai.Client to decompile.Beautifier.
type dissectAIBeautifier struct {
	c *ai.Client
}

func (a *dissectAIBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

// deriveDotNetDecompileOutDir picks a per-binary workspace under the dissect
// teardown dir if available, else under os.TempDir(). The result is rooted
// at <base>/dotnet-decompile/<basename>.
func deriveDotNetDecompileOutDir(r *DissectResult, path string, opts Options) string {
	base := opts.TeardownDir
	if base == "" {
		base = filepath.Join(os.TempDir(), "unravel-dotnet-decompile")
	}
	stem := filepath.Base(path)
	if stem == "" || stem == "." || stem == string(filepath.Separator) {
		stem = "assembly"
	}
	if r != nil && r.FileName != "" {
		stem = r.FileName
	}
	return filepath.Join(base, "dotnet-decompile", stem)
}

// nativeCLRModules runs the pure-Go CLR reader over a managed PE and returns
// one TypeModule per TypeDef. Any error (unreadable image, malformed metadata)
// is logged at WARN and yields nil — the caller treats an empty result as a
// no-op so the ilspy beautify track and the overall dissect run are unaffected.
func nativeCLRModules(path string) []clr.TypeModule {
	img, err := clr.Open(path)
	if err != nil {
		slog.Warn("native CLR open failed; skipping cil module capture", "path", path, "err", err)
		return nil
	}

	mods, _, _, _, err := clr.ExtractModules(img)
	if err != nil {
		slog.Warn("native CLR extract failed; skipping cil module capture", "path", path, "err", err)
		return nil
	}
	return mods
}
