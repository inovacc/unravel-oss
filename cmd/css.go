/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/css"

	"github.com/spf13/cobra"
)

var (
	cssNormalize        bool
	cssDeduplicate      bool
	cssResolveImports   bool
	cssResolveVars      bool
	cssRemoveUnused     bool
	cssIncludeSourceMap bool
	cssNodeModules      string
	cssNoCache          bool
	cssBatch            []string
	cssJSONFormat       bool
)

var cssCmd = &cobra.Command{
	Use:   "css",
	Short: "CSS extraction and analysis",
	Long: `Extract, organize, and analyze CSS from Electron, Tauri, and web applications.

Discovers CSS from .css files, HTML <style> tags, inline styles, and CSS-in-JS
patterns. Resolves @import chains, deduplicates rules, and organizes output by
component.

Subcommands:
  extract - Extract and organize CSS from an application`,
}

var cssExtractCmd = &cobra.Command{
	Use:   "extract <app-path>",
	Short: "Extract and organize CSS from an application",
	Long: `Extract CSS from Electron/Tauri apps, ASAR archives, or directories.

Discovers all CSS sources (files, HTML style tags, inline styles, CSS-in-JS),
resolves @import chains, deduplicates rules, and writes organized output with
a manifest.json.

Use --batch to process multiple paths in one invocation.`,
	Args: cobra.MinimumNArgs(0),
	RunE: runCSSExtract,
}

func init() {
	rootCmd.AddCommand(cssCmd)
	cssCmd.AddCommand(cssExtractCmd)

	cssExtractCmd.Flags().BoolVar(&cssNormalize, "normalize", true, "Normalize and clean CSS")
	cssExtractCmd.Flags().BoolVar(&cssDeduplicate, "deduplicate", true, "Remove duplicate CSS rules")
	cssExtractCmd.Flags().BoolVar(&cssResolveImports, "resolve-imports", true, "Resolve @import chains")
	cssExtractCmd.Flags().BoolVar(&cssResolveVars, "resolve-vars", false, "Resolve CSS custom properties")
	cssExtractCmd.Flags().BoolVar(&cssRemoveUnused, "remove-unused", false, "Remove unused CSS rules")
	cssExtractCmd.Flags().BoolVar(&cssIncludeSourceMap, "include-sourcemap", false, "Include source map references")
	cssExtractCmd.Flags().StringVar(&cssNodeModules, "node-modules", "", "Path to node_modules for @import resolution")
	cssExtractCmd.Flags().BoolVar(&cssNoCache, "no-cache", false, "Skip result caching")
	cssExtractCmd.Flags().StringSliceVar(&cssBatch, "batch", nil, "Additional paths for batch processing")
	cssExtractCmd.Flags().BoolVar(&cssJSONFormat, "json", false, "Output as JSON")
}

func runCSSExtract(_ *cobra.Command, args []string) error {
	if len(args) == 0 && len(cssBatch) == 0 {
		return fmt.Errorf("at least one app-path is required (positional or --batch)")
	}

	outDir := output
	if outDir == "" {
		outDir = "css_extracted"
	}

	opts := css.Options{
		OutputDir:        outDir,
		Normalize:        cssNormalize,
		Deduplicate:      cssDeduplicate,
		ResolveImports:   cssResolveImports,
		ResolveVars:      cssResolveVars,
		RemoveUnused:     cssRemoveUnused,
		IncludeSourceMap: cssIncludeSourceMap,
		NodeModulesPath:  cssNodeModules,
		Verbose:          verbose,
		NoCache:          cssNoCache,
	}

	// Collect all paths.
	paths := make([]string, 0, len(args)+len(cssBatch))
	paths = append(paths, args...)
	paths = append(paths, cssBatch...)

	if len(paths) > 1 {
		return runCSSBatch(paths, opts)
	}

	// Single path extraction.
	var result *css.Result
	var err error

	if cssNoCache {
		result, err = css.Extract(paths[0], opts)
	} else {
		result, err = css.CachedExtract(paths[0], opts)
	}

	if err != nil {
		return fmt.Errorf("css extract: %w", err)
	}

	// Write manifest if output dir specified.
	if opts.OutputDir != "" {
		if mErr := css.WriteManifest(result, opts.OutputDir); mErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: manifest write failed: %v\n", mErr)
		}
	}

	if cssJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	out.PrintCSSResult(result, verbose)
	return nil
}

func runCSSBatch(paths []string, opts css.Options) error {
	results, err := css.BatchExtract(paths, opts)
	if err != nil {
		return fmt.Errorf("css batch extract: %w", err)
	}

	// Write manifests for each result.
	for i, r := range results {
		if r != nil && r.OutputDir != "" {
			if mErr := css.WriteManifest(r, r.OutputDir); mErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: manifest write for path %d failed: %v\n", i, mErr)
			}
		}
	}

	if cssJSONFormat {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	out.PrintCSSBatchResult(results)
	return nil
}
