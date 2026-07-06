/*
Copyright (c) 2026 Security Research

06-04 Task 1: NEW top-level CLI surface for JS bundle reconstruction
(D-15). Splits webpack/Vite/esbuild/Rollup bundles back into per-module
files when source maps are absent. Uses `out "github.com/inovacc/unravel-oss/cmd/output"`
aliasing per D-20. The pkg/jsdeob/bundle/ package owns its types per D-21.
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/jsdeob"
	"github.com/inovacc/unravel-oss/pkg/jsdeob/bundle"

	"github.com/spf13/cobra"
)

var (
	bundleOutputDir   string
	bundleBeautify    bool
	bundleUseMCP      bool
	bundleConcurrency int
	bundleJSONFormat  bool
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Bundle reconstruction operations (webpack, Vite, esbuild, Rollup)",
	Long: `Reconstruct JS bundles back into per-module files when source maps
are absent. Recognises webpack, Vite, esbuild, and Rollup output shapes
via pattern-first / MCP-fallback / brace-balance-validate strategy.`,
}

var bundleReconstructCmd = &cobra.Command{
	Use:   "reconstruct <bundle.js>",
	Short: "Split a JS bundle back into per-module files",
	Long: `Run the hybrid reconstruction pipeline (Pass 1 patterns -> Pass 2
optional MCP fallback -> Pass 3 brace-balance validate) on a bundle and
write the D-13 layout under -o:

  <out>/modules/<recovered-name>.js     (when name is known)
  <out>/modules/_unnamed/<id>.js        (otherwise)
  <out>/_module_index.json              (full ID -> name+source mapping)
  <out>/manifest.json                   (bundle_kind + run summary)

Path-traversal sanitisation (T-06-01) and symlink rejection (T-06-06)
are applied at the CLI boundary.`,
	Args: cobra.ExactArgs(1),
	RunE: runBundleReconstruct,
}

func init() {
	rootCmd.AddCommand(bundleCmd)
	bundleCmd.AddCommand(bundleReconstructCmd)

	bundleReconstructCmd.Flags().StringVarP(&bundleOutputDir, "output", "o", "", "Output directory (required)")
	bundleReconstructCmd.Flags().BoolVar(&bundleBeautify, "beautify", false, "Chain BeautifyAI per recovered module")
	bundleReconstructCmd.Flags().BoolVar(&bundleUseMCP, "use-mcp", false, "Enable Pass 2 MCP fallback (default false)")
	bundleReconstructCmd.Flags().IntVar(&bundleConcurrency, "concurrency", 0, "Bounded parallel workers (0 = GOMAXPROCS/2)")
	bundleReconstructCmd.Flags().BoolVar(&bundleJSONFormat, "json", false, "Output as JSON")
	_ = bundleReconstructCmd.MarkFlagRequired("output")
}

// sanitizeBundlePath rejects path-traversal segments at the CLI boundary
// (T-06-01 / D-19).
func sanitizeBundlePath(p string, mustExist bool) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path contains '..' segment: %q", p)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	if mustExist {
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("stat path: %w", err)
		}
	}
	return abs, nil
}

// bundleAIBeautifier adapts an *ai.Client to bundle.Beautifier.
type bundleAIBeautifier struct {
	c *ai.Client
}

func (a *bundleAIBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

func runBundleReconstruct(cmd *cobra.Command, args []string) error {
	inAbs, err := sanitizeBundlePath(args[0], true)
	if err != nil {
		return fmt.Errorf("input path: %w", err)
	}
	outAbs, err := sanitizeBundlePath(bundleOutputDir, false)
	if err != nil {
		return fmt.Errorf("output path: %w", err)
	}

	// Reject symlink input (T-06-06).
	if info, lerr := os.Lstat(inAbs); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("input is symlink, refusing: %q", inAbs)
		}
	}

	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return fmt.Errorf("mkdir output: %w", err)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	opts := bundle.RunOptions{
		Input:       inAbs,
		Output:      outAbs,
		UseMCP:      bundleUseMCP,
		Beautify:    bundleBeautify,
		Concurrency: bundleConcurrency,
	}

	// AI client construction: required when --use-mcp is set; optional
	// for --beautify (downgrade gracefully if missing).
	if bundleUseMCP || bundleBeautify {
		client, cerr := ai.NewClient()
		if cerr != nil {
			if bundleUseMCP {
				return fmt.Errorf("--use-mcp requires AI client: %w", cerr)
			}
			_, _ = fmt.Fprintf(os.Stderr, "Warning: --beautify requested but AI client unavailable (%v); skipping per-module beautification\n", cerr)
		} else {
			adapter := &bundleAIBeautifier{c: client}
			if bundleUseMCP {
				opts.AIClient = adapter
			}
			if bundleBeautify {
				opts.BeautifierFn = func(ctx context.Context, src []byte, modulePath string) ([]byte, string, error) {
					bopts := jsdeob.BeautifyAIOptions{AIEnabled: true, InputPath: modulePath}
					b, rep, berr := jsdeob.BeautifyAI(ctx, adapter, src, bopts)
					if berr != nil {
						return src, "", berr
					}
					var fwJSON string
					if rep != nil && len(rep.FrameworkDetected) > 0 {
						if data, jerr := json.Marshal(rep.FrameworkDetected); jerr == nil {
							fwJSON = string(data)
						}
					}
					return b, fwJSON, nil
				}
			}
		}
	}

	report, err := bundle.Run(ctx, opts)
	if err != nil {
		return fmt.Errorf("bundle run: %w", err)
	}

	if bundleJSONFormat {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	out.PrintBundleReport(report, os.Stdout)
	return nil
}
