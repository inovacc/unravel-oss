/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	javaarchive "github.com/inovacc/unravel-oss/pkg/java/archive"
	javadecompiler "github.com/inovacc/unravel-oss/pkg/java/decompiler"
)

func init() {
	RegisterAnalyzer(analyzeJavaArchive, detect.TypeJAR, detect.TypeWAR, detect.TypeEAR)
	RegisterAnalyzer(analyzeJavaClass, detect.TypeJavaClass)
}

func analyzeJavaArchive(r *DissectResult, path string, opts Options) {
	r.runStep("java archive info", func(sr *debug.StepRecorder) error {
		a := javaarchive.New(slog.Default())
		ctx := context.Background()

		info, err := a.Extract(ctx, path)
		if err != nil {
			return err
		}

		defer func() { _ = info.Cleanup() }()

		sr.RecordOutput(info)
		return nil
	})

	if opts.OutputDir != "" {
		r.runStep("java decompile", func(sr *debug.StepRecorder) error {
			a := javaarchive.New(slog.Default())
			ctx := context.Background()

			info, err := a.Extract(ctx, path)
			if err != nil {
				return err
			}

			defer func() { _ = info.Cleanup() }()

			dec := javadecompiler.NewHybridDecompiler()
			outDir := filepath.Join(opts.OutputDir, "java-source")
			_ = os.MkdirAll(outDir, 0o755)

			var decompiled, errCount int

			for _, classRel := range info.ClassFiles {
				classPath := filepath.Join(info.ExtractDir, filepath.FromSlash(classRel))

				data, readErr := os.ReadFile(classPath)
				if readErr != nil {
					errCount++

					continue
				}

				source, decErr := dec.DecompileBytes(data)
				if decErr != nil {
					errCount++

					continue
				}

				javaPath := strings.TrimSuffix(classRel, ".class") + ".java"
				outPath := filepath.Join(outDir, filepath.FromSlash(javaPath))
				_ = os.MkdirAll(filepath.Dir(outPath), 0o755)

				if writeErr := os.WriteFile(outPath, []byte(source), 0o644); writeErr != nil {
					errCount++

					continue
				}

				decompiled++
			}

			sr.RecordOutput(map[string]any{
				"decompiled": decompiled,
				"errors":     errCount,
				"total":      len(info.ClassFiles),
				"output_dir": outDir,
			})
			return nil
		})
	}
}

func analyzeJavaClass(r *DissectResult, path string, opts Options) {
	r.runStep("java class decompile", func(sr *debug.StepRecorder) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		dec := javadecompiler.NewHybridDecompiler()

		source, err := dec.DecompileBytes(data)
		if err != nil {
			return err
		}

		sr.RecordOutput(map[string]any{"source": source})

		if opts.OutputDir != "" {
			baseName := strings.TrimSuffix(filepath.Base(path), ".class") + ".java"
			outPath := filepath.Join(opts.OutputDir, baseName)

			if writeErr := os.WriteFile(outPath, []byte(source), 0o644); writeErr != nil {
				return writeErr
			}
		}

		return nil
	})
}
