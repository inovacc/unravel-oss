/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/inovacc/unravel-oss/pkg/wasm"

	"github.com/spf13/cobra"
)

var wasmJSONFormat bool

var wasmCmd = &cobra.Command{
	Use:   "wasm",
	Short: "WebAssembly binary analysis",
	Long: `Parse and analyze WebAssembly (.wasm) binary modules.

Extracts module metadata including version, sections, imports, exports,
function counts, memory/table info, and custom section names.

Subcommands:
  info    - Display WASM module metadata`,
}

var wasmInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Display WebAssembly module metadata",
	Args:  cobra.ExactArgs(1),
	Run:   runWASMInfo,
}

func init() {
	rootCmd.AddCommand(wasmCmd)
	wasmCmd.AddCommand(wasmInfoCmd)

	wasmCmd.PersistentFlags().BoolVar(&wasmJSONFormat, "json", false, "Output as JSON")
}

func runWASMInfo(_ *cobra.Command, args []string) {
	info, err := wasm.Parse(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if wasmJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("WebAssembly Module: %s\n", args[0])
	fmt.Printf("  Version:     %d\n", info.Version)
	fmt.Printf("  Sections:    %d\n", len(info.Sections))
	fmt.Printf("  Functions:   %d\n", info.Functions)
	fmt.Printf("  Imports:     %d\n", len(info.Imports))
	fmt.Printf("  Exports:     %d\n", len(info.Exports))
	fmt.Printf("  Memories:    %d\n", info.Memories)
	fmt.Printf("  Tables:      %d\n", info.Tables)
	fmt.Printf("  Globals:     %d\n", info.Globals)
	fmt.Printf("  Code Size:   %d bytes\n", info.CodeSize)
	fmt.Printf("  Data Size:   %d bytes\n", info.DataSize)

	if len(info.Sections) > 0 {
		fmt.Println("\nSections:")
		for _, s := range info.Sections {
			fmt.Printf("  %-12s  ID=%2d  %d bytes\n", s.Name, s.ID, s.Size)
		}
	}

	if len(info.Imports) > 0 {
		fmt.Println("\nImports:")
		for _, imp := range info.Imports {
			fmt.Printf("  %-8s  %s.%s\n", imp.Kind, imp.Module, imp.Field)
		}
	}

	if len(info.Exports) > 0 {
		fmt.Println("\nExports:")
		for _, exp := range info.Exports {
			fmt.Printf("  %-8s  %-30s  index=%d\n", exp.Kind, exp.Name, exp.Index)
		}
	}

	if len(info.CustomNames) > 0 {
		fmt.Println("\nCustom Sections:")
		for _, name := range info.CustomNames {
			fmt.Printf("  %s\n", name)
		}
	}
}
