/*
Copyright (c) 2026 Security Research

Phase 6 (RECON-01) supplemental analyzer that auto-triggers Java
beautification on TypeJAR / TypeAPK / TypeWAR / TypeEAR during dissect
runs. Mirrors Phase 5's analyze_dotnet_decompile.go pattern.

COST WARNING: this analyzer auto-triggers on every TypeJAR / TypeAPK
encountered during dissect and may invoke MCP for AI beautification per
.java file emitted by pkg/java/decompiler. On batch dissect runs this
is substantial token spend.

Per D-18 (Phase 6 CONTEXT): Bundle reconstruction (RECON-07) and JS
beautification (RECON-03) are explicit-only and NOT auto-triggered
here. Operators with cost concerns should disable AI by configuring
the AI client to fail (NewClient returning err) — the orchestrator
honours opts.AIEnabled=false and writes a raw-only manifest.
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
	javaarchive "github.com/inovacc/unravel-oss/pkg/java/archive"
	javabeautify "github.com/inovacc/unravel-oss/pkg/java/beautify"
	javadecompiler "github.com/inovacc/unravel-oss/pkg/java/decompiler"
)

func init() {
	// D-18: Java auto-triggers on JAR + APK (Android JARs inside the APK
	// are surfaced via TypeAPK). DO NOT register a TypeJS handler. DO
	// NOT register a bundle-reconstruct handler.
	RegisterSupplementalAnalyzer(analyzeJavaBeautify,
		detect.TypeJAR, detect.TypeWAR, detect.TypeEAR, detect.TypeAPK)
}

// analyzeJavaBeautify runs the Java beautification orchestrator on the
// dissect-supplied JAR/APK, writing a parallel raw/+beautified/ tree
// under the teardown dir. Failures are recorded into r.Errors and
// never abort the dissect run. defer/recover guards the external
// decompiler boundary (D-22).
func analyzeJavaBeautify(r *DissectResult, path string, opts Options) {
	defer func() {
		if rec := recover(); rec != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("java beautify panic: %v", rec))
		}
	}()

	// Derive a workspace dir under the teardown / temp dir.
	outDir := deriveJavaBeautifyOutDir(r, path, opts)
	if outDir == "" {
		r.Errors = append(r.Errors, "java beautify: could not derive output dir")
		return
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("java beautify: mkdir %s: %v", outDir, err))
		return
	}

	rawDir := filepath.Join(outDir, "raw")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("java beautify: mkdir raw: %v", err))
		return
	}

	// Decompile JAR/APK classes into rawDir. We do not use opts.AIClient
	// here — the dotnet supplemental constructs ai.NewClient() inline.
	ctx := context.Background()
	a := javaarchive.New(slog.Default())
	info, err := a.Extract(ctx, path)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("java beautify: extract: %v", err))
		return
	}
	defer func() { _ = info.Cleanup() }()

	jarRaw := filepath.Join(rawDir, sanitiseFilename(info.Path))
	if err := os.MkdirAll(jarRaw, 0o755); err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("java beautify: mkdir jarRaw: %v", err))
		return
	}

	dec := javadecompiler.NewHybridDecompiler()
	fileCount := 0
	for _, classRel := range info.ClassFiles {
		classPath := filepath.Join(info.ExtractDir, filepath.FromSlash(classRel))
		data, rerr := os.ReadFile(classPath)
		if rerr != nil {
			continue
		}
		source, derr := dec.DecompileBytes(data)
		if derr != nil {
			continue
		}
		dst := filepath.Join(jarRaw, filepath.FromSlash(classRel[:len(classRel)-len(".class")]+".java"))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			continue
		}
		if err := os.WriteFile(dst, []byte(source), 0o644); err != nil {
			continue
		}
		fileCount++
	}

	dr := &javabeautify.DecompileResult{
		DecompilerVersion: "unravel-java-decompiler",
		Jars: []javabeautify.JarOutput{{
			Name:              filepath.Base(path),
			Path:              path,
			OutDir:            jarRaw,
			FileCount:         fileCount,
			DecompilerVersion: "unravel-java-decompiler",
			Decompiled:        fileCount > 0,
		}},
	}

	// AI client: try-and-downgrade pattern (mirrors dotnet supplemental).
	bopts := javabeautify.BeautifyOptions{AIEnabled: true}
	var beautifier javabeautify.Beautifier
	if client, cerr := ai.NewClient(); cerr == nil {
		beautifier = &javaBeautifyDissectAdapter{c: client}
	} else {
		bopts.AIEnabled = false
	}

	orch := javabeautify.NewOrchestrator(beautifier, bopts)
	report, oerr := orch.Run(ctx, dr, javabeautify.RunOptions{
		Output: outDir,
		Input:  path,
		Mode:   "dissect-supplemental",
	})
	if oerr != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("java beautify orchestrator: %v", oerr))
		return
	}
	_ = report // metadata captured via outDir/manifest.json
}

// javaBeautifyDissectAdapter adapts an *ai.Client to javabeautify.Beautifier.
type javaBeautifyDissectAdapter struct {
	c *ai.Client
}

func (a *javaBeautifyDissectAdapter) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

// deriveJavaBeautifyOutDir picks a per-binary workspace under the
// dissect teardown dir if available, else under os.TempDir(). Mirrors
// deriveDotNetDecompileOutDir.
func deriveJavaBeautifyOutDir(r *DissectResult, path string, opts Options) string {
	base := opts.TeardownDir
	if base == "" {
		base = filepath.Join(os.TempDir(), "unravel-java-beautify")
	}
	stem := filepath.Base(path)
	if stem == "" || stem == "." || stem == string(filepath.Separator) {
		stem = "archive"
	}
	if r != nil && r.FileName != "" {
		stem = r.FileName
	}
	return filepath.Join(base, "java-beautify", stem)
}

// sanitiseFilename strips path separators from a basename so it's safe
// to use as a directory component.
func sanitiseFilename(p string) string {
	out := filepath.Base(p)
	if out == "" || out == "." {
		return "archive"
	}
	return out
}
