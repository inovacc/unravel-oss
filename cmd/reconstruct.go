/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/inovacc/unravel-oss/pkg/reconstruct"

	"github.com/spf13/cobra"
)

var (
	reconstructLanguage  string
	reconstructChunkSize int
	reconstructNoCache   bool
)

var reconstructCmd = &cobra.Command{
	Use:   "reconstruct <file-or-dir>",
	Short: "AI-powered code reconstruction via MCP delegation",
	Long: `Reconstruct decompiled source code into clean, readable, production-quality code.

For a single file: runs stage 1 cleanup, chunks content, and outputs the MCP
delegation prompt. The MCP host (Claude Code) processes the prompt, then the
result is applied back via the MCP tool.

For a directory: batch-processes all supported source files (.java, .js, .ts,
.cs, .go, .py), reporting progress per file.

Examples:
  unravel reconstruct ./decompiled/Main.java
  unravel reconstruct ./decompiled/ -o ./reconstructed
  unravel reconstruct ./app.js --language javascript
  unravel reconstruct ./src/ --chunk-size 300 -v`,
	Args: cobra.ExactArgs(1),
	Run:  runReconstruct,
}

func init() {
	appCmd.AddCommand(reconstructCmd)
	reconstructCmd.Flags().StringVar(&reconstructLanguage, "language", "", "Override language detection (java, javascript, typescript, csharp, go, python)")
	reconstructCmd.Flags().IntVar(&reconstructChunkSize, "chunk-size", 500, "Line count threshold before chunking")
	reconstructCmd.Flags().BoolVar(&reconstructNoCache, "no-cache", false, "Skip cache lookup")
}

func runReconstruct(_ *cobra.Command, args []string) {
	path := args[0]

	opts := reconstruct.DefaultOptions()
	opts.OutputDir = output
	opts.MCPMode = true
	opts.NoCache = reconstructNoCache

	if reconstructLanguage != "" {
		opts.Language = reconstruct.Language(reconstructLanguage)
	}
	if reconstructChunkSize > 0 {
		opts.ChunkThreshold = reconstructChunkSize
	}

	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if info.IsDir() {
		runBatchReconstruct(path, opts)
		return
	}

	runSingleReconstruct(path, opts)
}

func runSingleReconstruct(path string, opts reconstruct.Options) {
	result, err := reconstruct.Run(path, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	// Print prompt for MCP host processing.
	fmt.Print(result.Prompt)

	if verbose {
		fmt.Fprintf(os.Stderr, "\n--- Stage: %s | Chunks: %d ---\n", result.Stage, len(result.Chunks))
	}
}

func runBatchReconstruct(dir string, opts reconstruct.Options) {
	progress := func(current, total int, path, status string) {
		fmt.Fprintf(os.Stderr, "[%d/%d] Reconstructing: %s ... %s\n", current, total, path, status)
	}

	results, err := reconstruct.RunBatch(dir, opts, progress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if results == nil {
		fmt.Fprintln(os.Stderr, "No supported source files found.")
		return
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}

	// Summary.
	var completed, failed, awaiting int
	for _, r := range results {
		switch r.Stage {
		case "complete":
			completed++
		case "failed":
			failed++
		default:
			awaiting++
		}
	}

	fmt.Fprintf(os.Stderr, "\nBatch complete: %d files (%d complete, %d awaiting MCP, %d failed)\n",
		len(results), completed, awaiting, failed)
}
