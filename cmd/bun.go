/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/bun"

	"github.com/spf13/cobra"
)

var bunCmd = &cobra.Command{
	Use:   "bun",
	Short: "Bun standalone binary analysis and decompilation",
	Long: `Analyze and decompile Bun standalone executables (created with bun build --compile).

Bun standalone binaries embed JavaScript/TypeScript sources in a StandaloneModuleGraph
stored in a .bun PE section (Windows), __BUN Mach-O section (macOS), or appended to ELF.

Subcommands:
  info      - Show Bun binary metadata (version, files, entrypoint)
  extract   - Decompile: extract all bundled JS/TS sources to disk
  check     - Quick check if a binary is a Bun standalone executable`,
}

var bunInfoCmd = &cobra.Command{
	Use:   "info <binary>",
	Short: "Show Bun binary metadata and bundled file list",
	Args:  cobra.ExactArgs(1),
	Run:   runBunInfo,
}

var bunExtractCmd = &cobra.Command{
	Use:   "extract <binary>",
	Short: "Decompile: extract all bundled sources to disk",
	Args:  cobra.ExactArgs(1),
	Run:   runBunExtract,
}

var bunCheckCmd = &cobra.Command{
	Use:   "check <binary>",
	Short: "Quick check if a binary is a Bun standalone executable",
	Args:  cobra.ExactArgs(1),
	Run:   runBunCheck,
}

func init() {
	rootCmd.AddCommand(bunCmd)
	bunCmd.AddCommand(bunInfoCmd)
	bunCmd.AddCommand(bunExtractCmd)
	bunCmd.AddCommand(bunCheckCmd)

	bunCmd.PersistentFlags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}

func runBunInfo(_ *cobra.Command, args []string) {
	result, err := bun.Analyze(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if !result.IsBun {
		fmt.Printf("%s is not a Bun standalone binary.\n", args[0])
		os.Exit(1)
	}

	if jsonFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("File:         %s\n", result.Name)
	fmt.Printf("Size:         %.1f MB\n", float64(result.Size)/1024/1024)
	fmt.Printf("Bun Version:  %s\n", result.Version)
	if result.Revision != "" {
		fmt.Printf("Revision:     %s\n", result.Revision)
	}
	fmt.Printf("Entrypoint:   %s\n", result.Entrypoint)
	fmt.Printf("Bundled Files: %d\n", result.FileCount)
	fmt.Printf("Byte Count:   %d (0x%X)\n", result.ByteCount, result.ByteCount)

	if len(result.Files) > 0 {
		fmt.Println()
		fmt.Printf("%-4s %-50s %10s  %s\n", "#", "PATH", "SIZE", "FLAGS")
		fmt.Println(strings.Repeat("-", 80))

		var totalSize int
		for i, f := range result.Files {
			flags := ""
			if f.IsEntrypoint {
				flags = "[entrypoint]"
			}
			if f.HasBytecode {
				if flags != "" {
					flags += " "
				}
				flags += fmt.Sprintf("[bytecode:%s]", bunFmtSize(f.BytecodeSize))
			}
			if f.HasSourceMap {
				if flags != "" {
					flags += " "
				}
				flags += "[sourcemap]"
			}

			fmt.Printf("%-4d %-50s %10s  %s\n", i+1, truncBunPath(f.Path, 50), bunFmtSize(f.Size), flags)
			totalSize += f.Size
		}

		fmt.Println(strings.Repeat("-", 80))
		fmt.Printf("     %-50s %10s\n", "TOTAL", bunFmtSize(totalSize))
	}
}

func runBunExtract(_ *cobra.Command, args []string) {
	outDir := output
	if outDir == "" {
		base := filepath.Base(args[0])
		ext := filepath.Ext(base)
		name := strings.TrimSuffix(base, ext)
		outDir = name + "_extracted"
	}

	fmt.Printf("Decompiling %s ...\n\n", filepath.Base(args[0]))

	result, err := bun.Extract(args[0], outDir, verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("\nBun Version:   %s\n", result.Version)
	fmt.Printf("Entrypoint:    %s\n", result.Entrypoint)
	fmt.Printf("Files:         %d\n", result.FileCount)
	fmt.Printf("Output:        %s\n", outDir)
}

func runBunCheck(_ *cobra.Command, args []string) {
	isBun, err := bun.IsBunBinary(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		fmt.Printf(`{"path":%q,"is_bun":%v}`, args[0], isBun)
		fmt.Println()
		return
	}

	if isBun {
		fmt.Printf("%s: Bun standalone binary detected\n", filepath.Base(args[0]))
	} else {
		fmt.Printf("%s: not a Bun binary\n", filepath.Base(args[0]))
	}
}

func truncBunPath(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}

func bunFmtSize(bytes int) string {
	switch {
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(1024*1024))
	case bytes >= 1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024.0)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
