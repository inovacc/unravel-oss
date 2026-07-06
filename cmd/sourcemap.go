/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/sourcemap"

	"github.com/spf13/cobra"
)

var sourcemapJSONFormat bool

var sourcemapCmd = &cobra.Command{
	Use:   "sourcemap",
	Short: "JavaScript source map analysis and extraction",
	Long: `Parse, extract, and scan JavaScript source map (.map) files.

Source maps link minified/bundled JavaScript back to original sources,
enabling recovery of the pre-build source tree including directory
structure, module names, and inline content.

Subcommands:
  info    - Parse source map metadata (version, sources, bundler)
  extract - Extract original source files from inline content
  scan    - Scan a directory for .map files and report bundlers`,
}

var sourcemapInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Parse source map metadata",
	Args:  cobra.ExactArgs(1),
	Run:   runSourcemapInfo,
}

var sourcemapExtractCmd = &cobra.Command{
	Use:   "extract <file>",
	Short: "Extract original sources from inline content",
	Args:  cobra.ExactArgs(1),
	Run:   runSourcemapExtract,
}

var sourcemapScanCmd = &cobra.Command{
	Use:   "scan <directory>",
	Short: "Scan directory for .map files",
	Args:  cobra.ExactArgs(1),
	Run:   runSourcemapScan,
}

var sourcemapResolveCmd = &cobra.Command{
	Use:   "resolve <file>",
	Short: "Resolve npm dependencies from a source map or bundled JS file",
	Long: `Trace bundled JavaScript back to npm packages.

When given a .map file, extracts package names from node_modules paths in the
sources array. When given a .js file, scans for require/import patterns and
webpack module markers.

Handles scoped packages (@scope/pkg), detects versions from embedded
package.json, and estimates per-package size from sourcesContent.`,
	Args: cobra.ExactArgs(1),
	Run:  runSourcemapResolve,
}

func init() {
	rootCmd.AddCommand(sourcemapCmd)
	sourcemapCmd.AddCommand(sourcemapInfoCmd)
	sourcemapCmd.AddCommand(sourcemapExtractCmd)
	sourcemapCmd.AddCommand(sourcemapScanCmd)
	sourcemapCmd.AddCommand(sourcemapResolveCmd)

	sourcemapCmd.PersistentFlags().BoolVar(&sourcemapJSONFormat, "json", false, "Output as JSON")
}

func runSourcemapInfo(_ *cobra.Command, args []string) {
	result, err := sourcemap.Parse(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if sourcemapJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Source Map: %s\n", args[0])
	fmt.Printf("  Version:     %d\n", result.Version)
	if result.File != "" {
		fmt.Printf("  File:        %s\n", result.File)
	}
	if result.SourceRoot != "" {
		fmt.Printf("  Source Root: %s\n", result.SourceRoot)
	}
	fmt.Printf("  Sources:     %d\n", result.SourceCount)
	fmt.Printf("  Names:       %d\n", result.NameCount)
	fmt.Printf("  Inline:      %v\n", result.HasInlineContent)
	fmt.Printf("  Segments:    %d\n", result.MappingSegments)

	if len(result.Sources) > 0 {
		fmt.Println("\nSources:")
		for _, s := range result.Sources {
			marker := " "
			if s.HasContent {
				marker = "*"
			}
			if s.Size > 0 {
				fmt.Printf("  %s %-60s %d bytes\n", marker, s.Path, s.Size)
			} else {
				fmt.Printf("  %s %s\n", marker, s.Path)
			}
		}
	}
}

func runSourcemapExtract(_ *cobra.Command, args []string) {
	outDir := output
	if outDir == "" {
		outDir = "sourcemap_extracted"
	}

	result, err := sourcemap.ExtractSources(args[0], outDir)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if sourcemapJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Extracted %d/%d sources to %s\n", result.Extracted, result.TotalSources, result.OutputDir)
	if result.Skipped > 0 {
		fmt.Printf("Skipped %d sources (no inline content)\n", result.Skipped)
	}
}

func runSourcemapScan(_ *cobra.Command, args []string) {
	result, err := sourcemap.ScanDir(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if sourcemapJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Directory: %s\n", result.Directory)
	fmt.Printf("Maps found: %d\n", result.TotalMaps)
	fmt.Printf("Total sources: %d\n", result.TotalSources)

	if len(result.Bundlers) > 0 {
		fmt.Println("\nBundlers:")
		for bundler, count := range result.Bundlers {
			fmt.Printf("  %-15s %d maps\n", bundler, count)
		}
	}

	if len(result.Maps) > 0 {
		fmt.Println("\nMaps:")
		for _, m := range result.Maps {
			bundlerStr := ""
			if m.Bundler != "" && m.Bundler != "unknown" {
				bundlerStr = fmt.Sprintf(" [%s]", m.Bundler)
			}
			fmt.Printf("  %-50s %d sources%s\n", m.Path, m.SourceCount, bundlerStr)
		}
	}
}

func runSourcemapResolve(_ *cobra.Command, args []string) {
	path := args[0]

	var result *sourcemap.ResolveResult
	var err error

	// Decide strategy based on file extension
	if strings.HasSuffix(strings.ToLower(path), ".map") {
		result, err = sourcemap.ResolveDependencies(path)
	} else {
		result, err = sourcemap.ResolveBundleJS(path)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if sourcemapJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Bundler: %s\n", result.BundlerUsed)
	fmt.Printf("Total modules: %d\n", result.TotalModules)
	fmt.Printf("Dependencies: %d\n", len(result.Dependencies))

	if len(result.Dependencies) > 0 {
		fmt.Println("\nPackages:")
		for _, dep := range result.Dependencies {
			version := ""
			if dep.Version != "" {
				version = fmt.Sprintf("@%s", dep.Version)
			}
			size := ""
			if dep.SizeEstimate > 0 {
				size = fmt.Sprintf(" (~%s)", formatBytes(dep.SizeEstimate))
			}
			fmt.Printf("  %-40s %d modules%s%s\n", dep.PackageName+version, len(dep.ModulePaths), size, "")
		}
	}
}

func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
