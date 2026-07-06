/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/dotnet/decompile"

	"github.com/spf13/cobra"
)

var dotnetJSON bool

var dotnetCmd = &cobra.Command{
	Use:   "dotnet",
	Short: ".NET application analysis and dependency inspection",
	Long: `Parse and analyze .NET application artifacts (.deps.json, .runtimeconfig.json).

Extracts target framework, NuGet dependencies, IPC mechanisms, detected
frameworks, and runtime configuration from self-contained or
framework-dependent .NET deployments.

Subcommands:
  deps      - Parse a .deps.json file and display dependencies
  info      - Scan a directory for .NET artifacts and display a summary
  runtime   - Parse a .runtimeconfig.json file and display configuration`,
}

var dotnetDepsCmd = &cobra.Command{
	Use:   "deps <file>",
	Short: "Parse a .deps.json file and display dependencies",
	Args:  cobra.ExactArgs(1),
	Run:   runDotnetDeps,
}

var dotnetInfoCmd = &cobra.Command{
	Use:   "info <directory>",
	Short: "Scan a directory for .NET artifacts and display a summary",
	Args:  cobra.ExactArgs(1),
	Run:   runDotnetInfo,
}

var dotnetRuntimeCmd = &cobra.Command{
	Use:   "runtime <file>",
	Short: "Parse a .runtimeconfig.json file and display configuration",
	Args:  cobra.ExactArgs(1),
	Run:   runDotnetRuntime,
}

var dotnetIPCCmd = &cobra.Command{
	Use:   "ipc <deps.json>",
	Short: "Detect IPC mechanisms from .NET dependency chain",
	Args:  cobra.ExactArgs(1),
	Run:   runDotnetIPC,
}

var dotnetDecompileCmd = &cobra.Command{
	Use:   "decompile <input>",
	Short: "Decompile .NET assemblies via ilspycmd with optional AI beautification",
	Long: `Decompile .NET assemblies (.dll/.exe) or whole apps (directory containing
deps.json) via ilspycmd, then optionally run AI beautification (XML doc
comments, resolved generics, conservative renames). Writes a parallel
<out>/raw and <out>/beautified tree plus a run-level manifest.json.

Prerequisite: dotnet tool install -g ilspycmd`,
	Args: cobra.ExactArgs(1),
	RunE: runDotnetDecompile,
}

func init() {
	rootCmd.AddCommand(dotnetCmd)
	dotnetCmd.AddCommand(dotnetDepsCmd)
	dotnetCmd.AddCommand(dotnetInfoCmd)
	dotnetCmd.AddCommand(dotnetRuntimeCmd)
	dotnetCmd.AddCommand(dotnetIPCCmd)
	dotnetCmd.AddCommand(dotnetDecompileCmd)

	dotnetCmd.PersistentFlags().BoolVar(&dotnetJSON, "json", false, "Output as JSON")

	dotnetDecompileCmd.Flags().StringP("output", "o", "", "Output directory (required)")
	dotnetDecompileCmd.Flags().Bool("no-ai", false, "Skip AI beautification (raw tree only)")
	dotnetDecompileCmd.Flags().Bool("include-framework", false, "Include Microsoft.*/System.* framework assemblies (default: skip)")
	dotnetDecompileCmd.Flags().Int("concurrency", 0, "Bounded parallel workers (0 = GOMAXPROCS/2)")
	dotnetDecompileCmd.Flags().Duration("timeout", 5*time.Minute, "Per-assembly ilspycmd timeout")
	_ = dotnetDecompileCmd.MarkFlagRequired("output")
}

// sanitizeDotnetPath cleans + rejects path-traversal segments at the Cobra
// boundary (D-04 / T-05-01). Mirrors sanitizeUDFPath in webview2.go but
// allows non-existent output paths (we'll mkdir them) while requiring the
// input path to exist.
func sanitizeDotnetPath(p string, mustExist bool) (string, error) {
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

// aiBeautifier adapts an *ai.Client to the decompile.Beautifier interface.
type aiBeautifier struct {
	c *ai.Client
}

func (a *aiBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

func runDotnetDecompile(cmd *cobra.Command, args []string) error {
	outputDir, _ := cmd.Flags().GetString("output")
	noAI, _ := cmd.Flags().GetBool("no-ai")
	includeFramework, _ := cmd.Flags().GetBool("include-framework")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	inAbs, err := sanitizeDotnetPath(args[0], true)
	if err != nil {
		return fmt.Errorf("input path: %w", err)
	}
	outAbs, err := sanitizeDotnetPath(outputDir, false)
	if err != nil {
		return fmt.Errorf("output path: %w", err)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	d, err := decompile.New()
	if err != nil {
		return fmt.Errorf("ilspycmd: %w", err)
	}

	opts := decompile.Options{
		Input:            inAbs,
		Output:           outAbs,
		IncludeFramework: includeFramework,
		Concurrency:      concurrency,
		Timeout:          timeout,
		Mode:             decompile.ModeAuto,
	}

	result, err := d.Run(ctx, opts)
	if err != nil {
		return fmt.Errorf("decompile run: %w", err)
	}

	// Build BeautifyOptions / RunOptions for the orchestrator.
	bopts := decompile.BeautifyOptions{
		AIEnabled:   !noAI,
		Concurrency: concurrency,
	}

	var beautifier decompile.Beautifier
	if !noAI {
		client, cerr := ai.NewClient()
		if cerr != nil {
			// AI credentials missing — fall back to no-AI manifest only.
			fmt.Fprintf(os.Stderr, "Warning: AI disabled (%v); writing raw tree + no-AI manifest only\n", cerr)
			bopts.AIEnabled = false
		} else {
			beautifier = &aiBeautifier{c: client}
		}
	}

	orch := decompile.NewOrchestrator(beautifier, bopts)

	mode := "auto"
	if st, statErr := os.Stat(inAbs); statErr == nil {
		if st.IsDir() {
			mode = "full-app"
		} else {
			mode = "single"
		}
	}

	report, err := orch.Run(ctx, result, decompile.RunOptions{
		Output:           outAbs,
		Input:            inAbs,
		Mode:             mode,
		IncludeFramework: includeFramework,
		Concurrency:      concurrency,
	})
	if err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}

	if dotnetJSON {
		payload := struct {
			Decompile *decompile.Result         `json:"decompile"`
			Beautify  *decompile.BeautifyReport `json:"beautify"`
		}{result, report}
		data, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	out.DisplayDecompileReport(result, report)
	return nil
}

func runDotnetDeps(_ *cobra.Command, args []string) {
	result, err := dotnet.ParseDeps(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if dotnetJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Target Framework: %s\n", result.TargetFramework)
	if result.RuntimeID != "" {
		fmt.Printf("Runtime ID:       %s\n", result.RuntimeID)
	}
	fmt.Printf("Total Libraries:  %d\n", result.TotalLibraries)
	fmt.Printf("  Project:        %d\n", len(result.ProjectLibs))
	fmt.Printf("  Package:        %d\n", len(result.PackageLibs))

	if len(result.Frameworks) > 0 {
		fmt.Printf("\nDetected Frameworks:\n")
		for _, fw := range result.Frameworks {
			fmt.Printf("  - %s\n", fw)
		}
	}

	if len(result.IPCMechanisms) > 0 {
		fmt.Printf("\nIPC Mechanisms:\n")
		for _, ipc := range result.IPCMechanisms {
			fmt.Printf("  - %s\n", ipc)
		}
	}

	if len(result.ProjectLibs) > 0 {
		fmt.Printf("\nProject Libraries:\n")
		for _, lib := range result.ProjectLibs {
			fmt.Printf("  %-40s %s\n", lib.Name, lib.Version)
		}
	}

	if len(result.PackageLibs) > 0 {
		fmt.Printf("\nPackage Libraries:\n")
		for _, lib := range result.PackageLibs {
			fmt.Printf("  %-40s %s\n", lib.Name, lib.Version)
		}
	}
}

func runDotnetInfo(_ *cobra.Command, args []string) {
	dir := args[0]

	if !dotnet.IsDotNetApp(dir) {
		fmt.Printf("Error: %s does not appear to be a .NET application directory\n", dir)
		os.Exit(1)
	}

	type infoResult struct {
		Directory      string                        `json:"directory"`
		DepsFiles      []string                      `json:"deps_files"`
		RuntimeConfigs []string                      `json:"runtime_configs"`
		Deps           []*dotnet.DepsResult          `json:"deps,omitempty"`
		Runtimes       []*dotnet.RuntimeConfigResult `json:"runtimes,omitempty"`
	}

	info := infoResult{
		Directory:      dir,
		DepsFiles:      dotnet.FindDepsJSON(dir),
		RuntimeConfigs: dotnet.FindRuntimeConfig(dir),
	}

	for _, f := range info.DepsFiles {
		d, err := dotnet.ParseDeps(f)
		if err != nil {
			fmt.Printf("Warning: failed to parse %s: %v\n", f, err)

			continue
		}
		info.Deps = append(info.Deps, d)
	}

	for _, f := range info.RuntimeConfigs {
		r, err := dotnet.ParseRuntimeConfig(f)
		if err != nil {
			fmt.Printf("Warning: failed to parse %s: %v\n", f, err)

			continue
		}
		info.Runtimes = append(info.Runtimes, r)
	}

	if dotnetJSON {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Directory: %s\n", dir)
	fmt.Printf("Found %d .deps.json file(s), %d .runtimeconfig.json file(s)\n\n",
		len(info.DepsFiles), len(info.RuntimeConfigs))

	for _, d := range info.Deps {
		fmt.Printf("--- %s ---\n", d.TargetFramework)
		if d.RuntimeID != "" {
			fmt.Printf("  Runtime ID:      %s\n", d.RuntimeID)
		}
		fmt.Printf("  Total Libraries: %d (project: %d, package: %d)\n",
			d.TotalLibraries, len(d.ProjectLibs), len(d.PackageLibs))
		if len(d.Frameworks) > 0 {
			fmt.Printf("  Frameworks:      %s\n", joinItems(d.Frameworks))
		}
		if len(d.IPCMechanisms) > 0 {
			fmt.Printf("  IPC Mechanisms:  %s\n", joinItems(d.IPCMechanisms))
		}
		fmt.Println()
	}

	for _, r := range info.Runtimes {
		fmt.Printf("--- Runtime Config (TFM: %s) ---\n", r.TFM)
		for _, fw := range r.Frameworks {
			fmt.Printf("  Framework: %s %s\n", fw.Name, fw.Version)
		}
		if r.IsASPNET {
			fmt.Printf("  Type: ASP.NET Core\n")
		}
		if r.IsDesktop {
			fmt.Printf("  Type: Desktop (WPF/WinForms)\n")
		}
		fmt.Println()
	}
}

func runDotnetRuntime(_ *cobra.Command, args []string) {
	result, err := dotnet.ParseRuntimeConfig(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if dotnetJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("TFM: %s\n", result.TFM)

	if len(result.Frameworks) > 0 {
		fmt.Printf("\nFrameworks:\n")
		for _, fw := range result.Frameworks {
			fmt.Printf("  %s %s\n", fw.Name, fw.Version)
		}
	}

	if result.IsASPNET {
		fmt.Printf("\nApplication Type: ASP.NET Core\n")
	}
	if result.IsDesktop {
		fmt.Printf("\nApplication Type: Desktop (WPF/WinForms)\n")
	}

	if len(result.Properties) > 0 {
		fmt.Printf("\nConfig Properties:\n")
		for k, v := range result.Properties {
			fmt.Printf("  %-40s %v\n", k, v)
		}
	}
}

func runDotnetIPC(_ *cobra.Command, args []string) {
	result, err := dotnet.ParseDeps(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	cl := dotnet.ClassifyLibraries(result)

	if dotnetJSON {
		type ipcOutput struct {
			IPCMechanisms []string               `json:"ipc_mechanisms"`
			IPCLibraries  []dotnet.ClassifiedLib `json:"ipc_libraries"`
		}

		var ipcLibs []dotnet.ClassifiedLib
		for _, groups := range [][]dotnet.ClassifiedLib{cl.Microsoft, cl.ThirdParty, cl.Runtime} {
			for _, lib := range groups {
				if lib.Category == "ipc" {
					ipcLibs = append(ipcLibs, lib)
				}
			}
		}

		out := ipcOutput{
			IPCMechanisms: result.IPCMechanisms,
			IPCLibraries:  ipcLibs,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Target: %s\n\n", result.TargetFramework)

	if len(result.IPCMechanisms) > 0 {
		fmt.Printf("IPC Mechanisms Detected:\n")
		for _, m := range result.IPCMechanisms {
			fmt.Printf("  - %s\n", m)
		}
		fmt.Println()
	} else {
		fmt.Println("No IPC mechanisms detected.")
		fmt.Println()
	}

	fmt.Printf("IPC-Related Libraries:\n")
	found := false
	for _, groups := range [][]dotnet.ClassifiedLib{cl.Microsoft, cl.ThirdParty, cl.Runtime} {
		for _, lib := range groups {
			if lib.Category == "ipc" {
				found = true
				pre := ""
				if lib.IsPrerelease {
					pre = " (prerelease)"
				}
				fmt.Printf("  %-45s %s%s\n", lib.Name, lib.Version, pre)
			}
		}
	}
	if !found {
		fmt.Println("  (none)")
	}
}

// joinItems joins a string slice with ", " for display.
func joinItems(items []string) string {
	result := ""
	for i, item := range items {
		if i > 0 {
			result += ", "
		}
		result += item
	}

	return result
}
