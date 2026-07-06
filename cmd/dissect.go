/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/dissect"

	"github.com/spf13/cobra"
)

var (
	dissectDeobf       bool
	dissectNative      bool
	dissectDotnet      bool
	dissectAI          bool
	dissectBeautify    bool
	dissectDisassemble bool
	dissectNoCache     bool
	dissectTeardownDir string
)

var dissectCmd = &cobra.Command{
	Use:   "dissect <path>",
	Short: "Auto-detect and run all applicable analyses on a file",
	Long: `Detect the file type at the given path and automatically run all
applicable non-destructive analyses, producing an aggregated result.

This combines detect + all relevant analysis commands into a single
workflow. Info-only by default (no file extraction unless -o is specified).

Examples:
  unravel dissect ./binary.exe
  unravel dissect ./binary.exe --disassemble
  unravel dissect ./app.asar --json
  unravel dissect ./app.apk -v
  unravel dissect ./app.js --beautify
  unravel dissect ./binary -o ./report`,
	Args: cobra.ExactArgs(1),
	Run:  runDissect,
}

func init() {
	appCmd.AddCommand(dissectCmd)
	dissectCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
	dissectCmd.Flags().BoolVar(&dissectDeobf, "deobf", false, "Enable jadx deobfuscation")
	dissectCmd.Flags().BoolVar(&dissectNative, "native", false, "Decompile native .so libraries")
	dissectCmd.Flags().BoolVar(&dissectDotnet, "dotnet", false, "Decompile .NET/Xamarin assemblies")
	dissectCmd.Flags().BoolVar(&dissectAI, "ai", false, "Run AI-powered deep analysis (requires running inside `unravel mcp serve`)")
	dissectCmd.Flags().BoolVar(&dissectBeautify, "beautify", false, "Beautify JavaScript files during analysis")
	dissectCmd.Flags().BoolVar(&dissectDisassemble, "disassemble", false, "Disassemble binary code sections")
	dissectCmd.Flags().BoolVar(&dissectNoCache, "no-cache", false, "Bypass analysis cache (force re-analysis)")
	dissectCmd.Flags().StringVar(&dissectTeardownDir, "teardown-dir", "", "ATS cache directory for step results (default: %LOCALAPPDATA%/Unravel/dissect)")
}

func runDissect(_ *cobra.Command, args []string) {
	path := args[0]

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	rec, err := debugRecorder(logger)
	if err != nil {
		fmt.Printf("Error initializing debug recorder: %v\n", err)
		os.Exit(1)
	}

	opts := dissect.Options{
		Verbose:         verbose,
		OutputDir:       output,
		Deobfuscate:     dissectDeobf,
		DecompileNative: dissectNative,
		DecompileDotnet: dissectDotnet,
		AIAnalysis:      dissectAI,
		Beautify:        dissectBeautify,
		Disassemble:     dissectDisassemble,
		NoCache:         dissectNoCache,
		TeardownDir:     dissectTeardownDir,
		Debug:           rec,
	}

	// Check if path is a directory — use directory-mode dissect.
	// BUG-08 / D-08 deviation (Rule 3): if the directory is an
	// already-extracted UWP package (AppxManifest.xml at root), DO NOT use
	// directory-mode. Fall through to single-target Run() so the workspace
	// writer (DISSECT_REPORT.md + communication/ + security/ + telemetry/
	// scaffolds) actually runs. The generic RunDirectory path is for
	// unstructured file trees and skips workspace generation.
	isUWPDir := false
	if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
		if _, mErr := os.Stat(filepath.Join(path, "AppxManifest.xml")); mErr == nil {
			isUWPDir = true
		}
	}
	if info, statErr := os.Stat(path); statErr == nil && info.IsDir() && !isUWPDir {
		dirResult, dirErr := dissect.RunDirectory(path, opts)
		if dirErr != nil {
			fmt.Printf("Error: %v\n", dirErr)
			os.Exit(1)
		}

		if jsonFormat {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(dirResult)

			return
		}

		fmt.Printf("Directory Analysis: %s\n", dirResult.Path)
		fmt.Printf("Files: %d total, %d analyzed, %s\n",
			dirResult.TotalFiles, dirResult.AnalyzedFiles, dirResult.Duration.Truncate(time.Millisecond))

		if dirResult.Summary != nil {
			if dirResult.Summary.IsDotNet {
				fmt.Println("Platform: .NET")
			}

			if dirResult.Summary.IsElectron {
				fmt.Println("Platform: Electron")
			}

			fmt.Println("\nFile types:")
			for t, count := range dirResult.Summary.TypeCounts {
				fmt.Printf("  %-25s %d\n", t, count)
			}

			if len(dirResult.Summary.Executables) > 0 {
				fmt.Printf("\nExecutables (%d):\n", len(dirResult.Summary.Executables))
				for _, e := range dirResult.Summary.Executables {
					fmt.Printf("  %s\n", e)
				}
			}
		}

		if len(dirResult.Errors) > 0 {
			fmt.Printf("\nErrors (%d):\n", len(dirResult.Errors))
			for _, e := range dirResult.Errors {
				fmt.Printf("  %s\n", e)
			}
		}

		return
	}

	result, err := dissect.Run(path, opts)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Write debug session metadata
	if rec.Enabled() {
		session := map[string]any{
			"timestamp":        time.Now().Format(time.RFC3339),
			"input":            path,
			"output_dir":       output,
			"verbose":          verbose,
			"deobfuscate":      dissectDeobf,
			"decompile_native": dissectNative,
			"decompile_dotnet": dissectDotnet,
			"ai_analysis":      dissectAI,
			"beautify":         dissectBeautify,
			"disassemble":      dissectDisassemble,
			"file_type":        string(result.Detection.FileType),
			"category":         string(result.Detection.Category),
			"analyses_count":   len(result.Analyses),
			"errors_count":     len(result.Errors),
			"duration_ms":      result.Duration.Milliseconds(),
		}
		if writeErr := rec.WriteJSON("session.json", session); writeErr != nil {
			logger.Warn("debug: failed to write session.json", "error", writeErr)
		}

		// Write full result as debug artifact
		if writeErr := rec.WriteJSON("result.json", result); writeErr != nil {
			logger.Warn("debug: failed to write result.json", "error", writeErr)
		}

		fmt.Printf("\nDebug artifacts: %s\n", rec.BaseDir())
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)

		return
	}

	out.PrintDissect(result)

	if output != "" {
		workDir, wsErr := dissect.WriteWorkspace(result, output)
		if wsErr != nil {
			fmt.Printf("Error writing workspace: %v\n", wsErr)
			os.Exit(1)
		}

		fmt.Printf("\nWorkspace: %s\n", workDir)
	}
}
