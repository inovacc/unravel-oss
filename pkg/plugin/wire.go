/*
Copyright (c) 2026 Security Research
*/
package plugin

import (
	"context"
	"log/slog"

	"github.com/inovacc/unravel-oss/pkg/advinstaller"
	"github.com/inovacc/unravel-oss/pkg/android/apk"
	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/deb"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/ios"
	"github.com/inovacc/unravel-oss/pkg/java/archive"
	"github.com/inovacc/unravel-oss/pkg/leveldb"
	"github.com/inovacc/unravel-oss/pkg/msi"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/npm"
	"github.com/inovacc/unravel-oss/pkg/nsis"
	"github.com/inovacc/unravel-oss/pkg/rpm"
)

// WireBuiltins creates a registry with all built-in analyzers wired to their
// real Analyze/Extract implementations. This replaces the nil-func stubs.
func WireBuiltins() *Registry {
	r := NewRegistry()

	for _, def := range builtins {
		def.AnalyzeFunc = makeAnalyzeFunc(def.Name)
		def.ExtractFunc = makeExtractFunc(def.Name)
		if err := RegisterBuiltin(r, def); err != nil {
			panic("wire builtin " + def.Name + ": " + err.Error())
		}
	}

	return r
}

// makeAnalyzeFunc returns a universal analyze function that delegates to
// dissect.Run for the given format. Dissect already handles type dispatch.
func makeAnalyzeFunc(name string) func(string, AnalyzeOpts) (any, error) {
	return func(path string, opts AnalyzeOpts) (any, error) {
		return dissect.Run(path, dissect.Options{
			Verbose:   opts.Verbose,
			OutputDir: opts.OutputDir,
		})
	}
}

// makeExtractFunc returns a format-specific extract function.
func makeExtractFunc(name string) func(string, string) error {
	switch name {
	case "android":
		return func(path, outputDir string) error {
			_, err := apk.Extract(path, outputDir, false)
			return err
		}
	case "ios":
		return func(path, outputDir string) error {
			_, err := ios.Extract(path, outputDir)
			return err
		}
	case "npm":
		return func(path, outputDir string) error {
			// npm analyze operates on directories, not extraction
			_, err := npm.Analyze(path)
			return err
		}
	case "java":
		return func(path, outputDir string) error {
			ext := archive.New(slog.Default(), archive.WithNativeDecompiler())
			_, err := ext.Extract(context.Background(), path)
			return err
		}
	case "electron":
		return func(path, outputDir string) error {
			return extractASAR(path, outputDir)
		}
	case "tauri":
		return func(path, outputDir string) error {
			// Tauri apps are analyzed via dissect, no separate extraction
			_, err := dissect.Run(path, dissect.Options{OutputDir: outputDir})
			return err
		}
	case "msi":
		return func(path, outputDir string) error {
			result, dErr := detect.Detect(path)
			if dErr == nil && result.FileType == detect.TypeMSIX {
				_, err := msix.Extract(path, outputDir)
				return err
			}
			_, err := msi.Extract(path, outputDir)
			return err
		}
	case "deb":
		return func(path, outputDir string) error {
			_, err := deb.Extract(path, outputDir)
			return err
		}
	case "rpm":
		return func(path, outputDir string) error {
			_, err := rpm.Extract(path, outputDir)
			return err
		}
	case "packages":
		return func(path, outputDir string) error {
			// Detect which package format and extract accordingly
			result, err := detect.Detect(path)
			if err != nil {
				return err
			}
			switch result.FileType {
			case detect.TypeNSIS:
				_, err := nsis.Extract(path, outputDir)
				return err
			case detect.TypeAdvancedInstaller:
				_, err := advinstaller.ExtractMSI(path, outputDir)
				return err
			default:
				_, err := dissect.Run(path, dissect.Options{OutputDir: outputDir})
				return err
			}
		}
	case "web":
		return func(path, outputDir string) error {
			// JS/sourcemap/extension — analysis only, no extraction
			_, err := dissect.Run(path, dissect.Options{OutputDir: outputDir})
			return err
		}
	case "data":
		return func(path, outputDir string) error {
			result, err := detect.Detect(path)
			if err != nil {
				return err
			}
			switch result.FileType {
			case detect.TypeLevelDB:
				_, err := leveldb.ParseDirectory(path)
				return err
			case detect.TypeChromiumCache:
				_, err := cache.Parse(path, outputDir)
				return err
			default:
				return nil
			}
		}
	case "binary":
		return func(path, outputDir string) error {
			// Binary analysis only, no extraction step
			_, err := dissect.Run(path, dissect.Options{OutputDir: outputDir})
			return err
		}
	default:
		return nil
	}
}

// extractASAR handles ASAR extraction using the asar package.
func extractASAR(path, outputDir string) error {
	f, header, _, dataOffset, err := asar.OpenAndParse(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	asar.Extract(f, header, dataOffset, outputDir, path, false)
	return nil
}
