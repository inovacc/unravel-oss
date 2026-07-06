/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	mcpclient "github.com/inovacc/unravel-oss/pkg/mcp/client"
	"github.com/inovacc/unravel-oss/pkg/npm"
	"github.com/inovacc/unravel-oss/pkg/npm/mcpprobe"
	"github.com/inovacc/unravel-oss/pkg/sandbox"

	"github.com/spf13/cobra"
)

var (
	npmJSON           bool
	npmOutputDir      string
	npmReportDir      string
	npmSandboxTimeout int
	npmSandboxEntry   string
	npmSandboxEnv     bool
)

var npmCmd = &cobra.Command{
	Use:   "npm",
	Short: "NPM package analysis and security scanning",
	Long: `Fetch, download, and analyze NPM packages for security risks.

Supports querying the NPM registry for package metadata, downloading
tarballs for offline analysis, scanning installed dependencies, and
parsing package.json dependency trees.

Subcommands:
  info      - Fetch and display package metadata from the NPM registry
  download  - Download a package tarball for offline analysis
  analyze   - Scan a directory for security findings
  deps      - Parse package.json and display the dependency tree`,
}

var npmInfoCmd = &cobra.Command{
	Use:   "info <package[@version]>",
	Short: "Fetch and display NPM package metadata",
	Args:  cobra.ExactArgs(1),
	Run:   runNpmInfo,
}

var npmDownloadCmd = &cobra.Command{
	Use:   "download <package[@version]>",
	Short: "Download a package tarball for offline analysis",
	Args:  cobra.ExactArgs(1),
	Run:   runNpmDownload,
}

var npmAnalyzeCmd = &cobra.Command{
	Use:   "analyze <directory>",
	Short: "Scan a directory for NPM security findings",
	Args:  cobra.ExactArgs(1),
	Run:   runNpmAnalyze,
}

var npmDepsCmd = &cobra.Command{
	Use:   "deps <directory>",
	Short: "Parse package.json and display the dependency tree",
	Args:  cobra.ExactArgs(1),
	Run:   runNpmDeps,
}

var npmMCPCmd = &cobra.Command{
	Use:   "mcp <directory>",
	Short: "Extract MCP tool inventory from a Node.js package",
	Args:  cobra.ExactArgs(1),
	Run:   runNpmMCP,
}

var npmBatchCmd = &cobra.Command{
	Use:   "batch <pkg1[@version]> [pkg2[@version]] ...",
	Short: "Download and analyze multiple npm packages",
	Args:  cobra.MinimumNArgs(1),
	Run:   runNpmBatch,
}

var npmDiffCmd = &cobra.Command{
	Use:   "diff <package> <old-version> <new-version>",
	Short: "Compare security profile between two package versions",
	Args:  cobra.ExactArgs(3),
	Run:   runNpmDiff,
}

var npmProbeTimeout int

var npmProbeCmd = &cobra.Command{
	Use:   "probe <command|directory> [args...]",
	Short: "Launch an MCP server and enumerate its tools/resources/prompts",
	Long: `Start an MCP server process via stdio transport and probe it using
the MCP protocol to discover registered tools, resources, and prompts.

If the first argument is a directory containing a package.json, the entry
point is auto-detected from the bin field, scripts, or main field.

Examples:
  unravel npm probe ./downloaded-mcp-server/
  unravel npm probe node ./server.js
  unravel npm probe npx -y @anthropic/mcp-server-time`,
	Args: cobra.MinimumNArgs(1),
	Run:  runNpmProbe,
}

var npmSandboxCmd = &cobra.Command{
	Use:   "sandbox <directory>",
	Short: "Run a Node.js package in a sandboxed environment",
	Long: `Execute a Node.js package with interceptors for network, filesystem,
child_process, and environment variable access. All intercepted calls are
reported in the output. This is a best-effort instrumentation layer, not
a security boundary.`,
	Args: cobra.ExactArgs(1),
	Run:  runNpmSandbox,
}

func init() {
	rootCmd.AddCommand(npmCmd)
	npmCmd.AddCommand(npmInfoCmd, npmDownloadCmd, npmAnalyzeCmd, npmDepsCmd, npmMCPCmd, npmSandboxCmd, npmBatchCmd, npmDiffCmd, npmProbeCmd)
	npmCmd.PersistentFlags().BoolVar(&npmJSON, "json", false, "Output as JSON")
	npmDownloadCmd.Flags().StringVarP(&npmOutputDir, "output", "o", "", "Output directory")
	npmAnalyzeCmd.Flags().StringVar(&npmReportDir, "report", "", "Write report.md and report.json to this directory")
	npmSandboxCmd.Flags().IntVar(&npmSandboxTimeout, "timeout", 30, "Execution timeout in seconds")
	npmSandboxCmd.Flags().StringVar(&npmSandboxEntry, "entry", "", "Override entry point (default: from package.json)")
	npmSandboxCmd.Flags().BoolVar(&npmSandboxEnv, "capture-env", false, "Capture process.env access")
	npmProbeCmd.Flags().IntVar(&npmProbeTimeout, "timeout", 10, "Timeout in seconds for server enumeration")
	npmBatchCmd.Flags().StringVarP(&npmBatchOutputDir, "output", "o", "", "Write comparative report to this directory")
}

var npmBatchOutputDir string

// parsePackageSpec splits "pkg@version" on the last "@" to handle scoped packages.
// Examples: "express@4.18.0" -> ("express", "4.18.0"), "@scope/pkg@1.0" -> ("@scope/pkg", "1.0")
func parsePackageSpec(spec string) (name, version string) {
	// Handle scoped packages: if starts with @, find the second @
	if strings.HasPrefix(spec, "@") {
		rest := spec[1:]
		idx := strings.LastIndex(rest, "@")
		if idx > 0 {
			return spec[:idx+1], rest[idx+1:]
		}

		return spec, ""
	}

	idx := strings.LastIndex(spec, "@")
	if idx > 0 {
		return spec[:idx], spec[idx+1:]
	}

	return spec, ""
}

func runNpmInfo(_ *cobra.Command, args []string) {
	info, err := npm.FetchInfo(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if npmJSON {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	latest := info.DistTags["latest"]

	fmt.Printf("Package:       %s\n", info.Name)
	fmt.Printf("Latest:        %s\n", latest)
	fmt.Printf("Description:   %s\n", info.Description)
	fmt.Printf("License:       %v\n", info.License)
	fmt.Printf("Versions:      %d\n", len(info.Versions))

	if len(info.Maintainers) > 0 {
		names := make([]string, len(info.Maintainers))
		for i, m := range info.Maintainers {
			names[i] = m.Name
		}

		fmt.Printf("Maintainers:   %s\n", strings.Join(names, ", "))
	}

	if v, ok := info.Versions[latest]; ok {
		fmt.Printf("Dependencies:  %d\n", len(v.Dependencies))
	}

	if info.Homepage != "" {
		fmt.Printf("Homepage:      %s\n", info.Homepage)
	}
}

func runNpmDownload(_ *cobra.Command, args []string) {
	name, version := parsePackageSpec(args[0])

	outDir := npmOutputDir
	if outDir == "" {
		if version != "" {
			outDir = fmt.Sprintf("%s-%s", strings.ReplaceAll(name, "/", "-"), version)
		} else {
			outDir = strings.ReplaceAll(name, "/", "-")
		}
	}

	result, err := npm.Download(name, version, outDir)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if npmJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Package:     %s@%s\n", result.Package, result.Version)
	fmt.Printf("Output:      %s\n", result.OutputDir)
	fmt.Printf("Files:       %d\n", result.Files)
	fmt.Printf("Total Size:  %d bytes\n", result.Size)
}

func runNpmAnalyze(_ *cobra.Command, args []string) {
	report, err := npm.Analyze(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Write report files if --report is set
	if npmReportDir != "" {
		if mkErr := os.MkdirAll(npmReportDir, 0o755); mkErr != nil {
			fmt.Printf("Error creating report directory: %v\n", mkErr)
			os.Exit(1)
		}

		md := npm.GenerateMarkdown(report)
		mdPath := filepath.Join(npmReportDir, "report.md")
		if wErr := os.WriteFile(mdPath, []byte(md), 0o644); wErr != nil {
			fmt.Printf("Error writing report.md: %v\n", wErr)
			os.Exit(1)
		}

		jsonStr, jErr := npm.GenerateJSON(report)
		if jErr != nil {
			fmt.Printf("Error generating JSON report: %v\n", jErr)
			os.Exit(1)
		}

		jsonPath := filepath.Join(npmReportDir, "report.json")
		if wErr := os.WriteFile(jsonPath, []byte(jsonStr), 0o644); wErr != nil {
			fmt.Printf("Error writing report.json: %v\n", wErr)
			os.Exit(1)
		}

		fmt.Printf("Reports written to %s\n", npmReportDir)
	}

	if npmJSON {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Package:       %s@%s\n", report.PackageName, report.Version)
	fmt.Printf("Risk Score:    %d/100\n", report.RiskScore)
	fmt.Printf("Dependencies:  %d\n", report.Dependencies)
	fmt.Printf("PostInstall:   %v\n", report.HasPostInstall)

	if len(report.NetworkCalls) > 0 {
		fmt.Printf("Network Calls: %d\n", len(report.NetworkCalls))
	}

	if len(report.ExecCalls) > 0 {
		fmt.Printf("Exec Calls:    %d\n", len(report.ExecCalls))
	}

	if len(report.Secrets) > 0 {
		fmt.Printf("Secrets:       %d\n", len(report.Secrets))
	}

	if len(report.MCPTools) > 0 {
		fmt.Printf("MCP Tools:     %d\n", len(report.MCPTools))
		for _, t := range report.MCPTools {
			fmt.Printf("  - %s\n", t)
		}
	}

	if len(report.ObfuscationIndicators) > 0 {
		fmt.Printf("\nObfuscation Indicators (%d):\n", len(report.ObfuscationIndicators))
		for _, ind := range report.ObfuscationIndicators {
			fmt.Printf("  - %s\n", ind)
		}
	}

	if len(report.SupplyChainRisks) > 0 {
		fmt.Printf("\nSupply Chain Risks (%d):\n", len(report.SupplyChainRisks))
		for _, risk := range report.SupplyChainRisks {
			fmt.Printf("  - %s\n", risk)
		}
	}

	if len(report.InstallScripts) > 0 {
		fmt.Printf("\nInstall Scripts:\n")
		for hook, script := range report.InstallScripts {
			fmt.Printf("  %-15s %s\n", hook+":", script)
		}
	}

	if len(report.DynamicRequires) > 0 {
		fmt.Printf("\nDynamic Requires (%d):\n", len(report.DynamicRequires))
		for _, dr := range report.DynamicRequires {
			fmt.Printf("  - %s\n", dr)
		}
	}

	if len(report.TelemetrySDKs) > 0 {
		fmt.Printf("\nTelemetry SDKs (%d):\n", len(report.TelemetrySDKs))
		for _, sdk := range report.TelemetrySDKs {
			fmt.Printf("  - %s\n", sdk)
		}
	}

	if len(report.VulnerablePackages) > 0 {
		fmt.Printf("\nVulnerable/Malicious Packages (%d):\n", len(report.VulnerablePackages))
		for _, vp := range report.VulnerablePackages {
			fmt.Printf("  - %s\n", vp)
		}
	}

	if len(report.RiskFactors) > 0 {
		fmt.Println("\nRisk Factors:")
		for _, rf := range report.RiskFactors {
			fmt.Printf("  - %s\n", rf)
		}
	}
}

func runNpmDeps(_ *cobra.Command, args []string) {
	dir := args[0]

	// Determine if the argument is a file or directory
	pkgPath := dir
	lockDir := dir
	info, statErr := os.Stat(dir)
	if statErr != nil {
		fmt.Printf("Error: %v\n", statErr)
		os.Exit(1)
	}
	if info.IsDir() {
		pkgPath = filepath.Join(dir, "package.json")
		// lockDir stays as dir
	} else {
		lockDir = filepath.Dir(dir)
	}

	pkg, err := npm.ParsePackageJSON(pkgPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Try to parse package-lock.json if it exists alongside
	lockPath := filepath.Join(lockDir, "package-lock.json")
	var lockResult *npm.LockfileResult
	if _, lockErr := os.Stat(lockPath); lockErr == nil {
		lockResult, _ = npm.ParseLockfile(lockPath)
	}

	if npmJSON {
		combined := map[string]interface{}{
			"package": pkg,
		}
		if lockResult != nil {
			combined["lockfile"] = lockResult
		}
		data, _ := json.MarshalIndent(combined, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Package:          %s@%s\n", pkg.Name, pkg.Version)
	fmt.Printf("Description:      %s\n", pkg.Description)

	if len(pkg.Dependencies) > 0 {
		fmt.Printf("\nDependencies (%d):\n", len(pkg.Dependencies))
		for name, ver := range pkg.Dependencies {
			fmt.Printf("  %-30s %s\n", name, ver)
		}
	}

	if len(pkg.DevDependencies) > 0 {
		fmt.Printf("\nDev Dependencies (%d):\n", len(pkg.DevDependencies))
		for name, ver := range pkg.DevDependencies {
			fmt.Printf("  %-30s %s\n", name, ver)
		}
	}

	if len(pkg.Scripts) > 0 {
		fmt.Printf("\nScripts (%d):\n", len(pkg.Scripts))
		for name, script := range pkg.Scripts {
			fmt.Printf("  %-20s %s\n", name, script)
		}
	}

	// Display lockfile stats if available
	if lockResult != nil {
		fmt.Printf("\nLockfile (v%d):\n", lockResult.LockVersion)
		fmt.Printf("  Total Dependencies:    %d\n", lockResult.TotalDeps)
		fmt.Printf("  Direct Dependencies:   %d\n", lockResult.DirectDeps)
		fmt.Printf("  Transitive Deps:       %d\n", lockResult.TransDeps)
		fmt.Printf("  Max Depth:             %d\n", lockResult.MaxDepth)
		if lockResult.Duplicates > 0 {
			fmt.Printf("  Duplicate Packages:    %d (same name, different versions)\n", lockResult.Duplicates)
		}
	}
}

// mcpInventory holds the MCP-specific findings from a Node.js package.
type mcpInventory struct {
	PackageName   string   `json:"package_name"`
	Version       string   `json:"version"`
	SDKVersion    string   `json:"sdk_version,omitempty"`
	SDKDep        string   `json:"sdk_dependency,omitempty"` // "dependency" or "devDependency"
	TransportType string   `json:"transport_type,omitempty"`
	Tools         []string `json:"tools,omitempty"`
	Resources     []string `json:"resources,omitempty"`
	Prompts       []string `json:"prompts,omitempty"`
}

var (
	mcpToolRegex     = regexp.MustCompile(`server\.tool\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	mcpResourceRegex = regexp.MustCompile(`server\.resource\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	mcpPromptRegex   = regexp.MustCompile(`server\.prompt\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	mcpStdioRegex    = regexp.MustCompile(`(?i)StdioServerTransport|stdio`)
	mcpSSERegex      = regexp.MustCompile(`(?i)SSEServerTransport|sse`)
	mcpStreamRegex   = regexp.MustCompile(`(?i)StreamableHTTPServerTransport|streamable`)
)

func runNpmMCP(_ *cobra.Command, args []string) {
	dir := args[0]

	pkgPath := filepath.Join(dir, "package.json")
	pkg, err := npm.ParsePackageJSON(pkgPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	inv := &mcpInventory{
		PackageName: pkg.Name,
		Version:     pkg.Version,
	}

	// Check for MCP SDK in dependencies
	const mcpSDKName = "@modelcontextprotocol/sdk"
	if ver, ok := pkg.Dependencies[mcpSDKName]; ok {
		inv.SDKVersion = ver
		inv.SDKDep = "dependency"
	} else if ver, ok := pkg.DevDependencies[mcpSDKName]; ok {
		inv.SDKVersion = ver
		inv.SDKDep = "devDependency"
	}

	// Walk JS files for registrations and transport
	toolSet := make(map[string]bool)
	resourceSet := make(map[string]bool)
	promptSet := make(map[string]bool)
	transportDetected := ""

	jsExts := map[string]bool{".js": true, ".ts": true, ".mjs": true, ".cjs": true, ".jsx": true, ".tsx": true}

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			base := filepath.Base(path)
			if info != nil && info.IsDir() && (base == "node_modules" || base == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !jsExts[ext] {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer func() { _ = f.Close() }()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()

			if matches := mcpToolRegex.FindAllStringSubmatch(line, -1); matches != nil {
				for _, m := range matches {
					toolSet[m[1]] = true
				}
			}
			if matches := mcpResourceRegex.FindAllStringSubmatch(line, -1); matches != nil {
				for _, m := range matches {
					resourceSet[m[1]] = true
				}
			}
			if matches := mcpPromptRegex.FindAllStringSubmatch(line, -1); matches != nil {
				for _, m := range matches {
					promptSet[m[1]] = true
				}
			}

			// Transport detection (first match wins)
			if transportDetected == "" {
				if mcpStdioRegex.MatchString(line) {
					transportDetected = "stdio"
				} else if mcpSSERegex.MatchString(line) {
					transportDetected = "sse"
				} else if mcpStreamRegex.MatchString(line) {
					transportDetected = "streamable-http"
				}
			}
		}
		return nil
	})

	for t := range toolSet {
		inv.Tools = append(inv.Tools, t)
	}
	for r := range resourceSet {
		inv.Resources = append(inv.Resources, r)
	}
	for p := range promptSet {
		inv.Prompts = append(inv.Prompts, p)
	}
	inv.TransportType = transportDetected

	if npmJSON {
		data, _ := json.MarshalIndent(inv, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Package:       %s@%s\n", inv.PackageName, inv.Version)
	if inv.SDKVersion != "" {
		fmt.Printf("MCP SDK:       %s (%s)\n", inv.SDKVersion, inv.SDKDep)
	} else {
		fmt.Println("MCP SDK:       not found")
	}
	if inv.TransportType != "" {
		fmt.Printf("Transport:     %s\n", inv.TransportType)
	}

	if len(inv.Tools) > 0 {
		fmt.Printf("\nTools (%d):\n", len(inv.Tools))
		for _, t := range inv.Tools {
			fmt.Printf("  - %s\n", t)
		}
	}
	if len(inv.Resources) > 0 {
		fmt.Printf("\nResources (%d):\n", len(inv.Resources))
		for _, r := range inv.Resources {
			fmt.Printf("  - %s\n", r)
		}
	}
	if len(inv.Prompts) > 0 {
		fmt.Printf("\nPrompts (%d):\n", len(inv.Prompts))
		for _, p := range inv.Prompts {
			fmt.Printf("  - %s\n", p)
		}
	}

	if inv.SDKVersion == "" && len(inv.Tools) == 0 && len(inv.Resources) == 0 && len(inv.Prompts) == 0 {
		fmt.Println("\nNo MCP integration detected in this package.")
	}
}

func runNpmSandbox(_ *cobra.Command, args []string) {
	dir := args[0]

	opts := sandbox.Options{
		Timeout:    time.Duration(npmSandboxTimeout) * time.Second,
		EntryPoint: npmSandboxEntry,
		CaptureEnv: npmSandboxEnv,
	}

	ctx := context.Background()

	result, err := sandbox.Run(ctx, dir, opts)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if npmJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Package Dir:   %s\n", result.PackageDir)
	fmt.Printf("Entry Point:   %s\n", result.EntryPoint)
	fmt.Printf("Exit Code:     %d\n", result.ExitCode)
	fmt.Printf("Duration:      %s\n", result.Duration.Round(time.Millisecond))

	if result.TimedOut {
		fmt.Println("Status:        TIMED OUT")
	}

	if result.Error != "" {
		fmt.Printf("Error:         %s\n", result.Error)
	}

	if len(result.NetworkCalls) > 0 {
		fmt.Printf("\nNetwork Calls (%d):\n", len(result.NetworkCalls))
		for _, nc := range result.NetworkCalls {
			fmt.Printf("  %s %s [%s]\n", nc.Method, nc.URL, nc.Protocol)
		}
	}

	if len(result.FileAccess) > 0 {
		fmt.Printf("\nFile Access (%d):\n", len(result.FileAccess))
		for _, fa := range result.FileAccess {
			fmt.Printf("  %-6s %s\n", fa.Op, fa.Path)
		}
	}

	if len(result.SpawnedProcs) > 0 {
		fmt.Printf("\nSpawned Processes (%d):\n", len(result.SpawnedProcs))
		for _, p := range result.SpawnedProcs {
			fmt.Printf("  - %s\n", p)
		}
	}

	if len(result.EnvAccess) > 0 {
		fmt.Printf("\nEnv Access (%d):\n", len(result.EnvAccess))
		for _, e := range result.EnvAccess {
			fmt.Printf("  - %s\n", e)
		}
	}

	if result.Stdout != "" {
		fmt.Printf("\n--- stdout ---\n%s", result.Stdout)
	}

	if result.Stderr != "" {
		fmt.Printf("\n--- stderr ---\n%s", result.Stderr)
	}
}

func runNpmBatch(_ *cobra.Command, args []string) {
	ctx := context.Background()

	result, err := npm.BatchAnalyze(ctx, args, 4)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if npmJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Batch Analysis: %d packages\n\n", len(result.Packages))
	fmt.Printf("  %-40s %-12s %s\n", "PACKAGE", "VERSION", "RISK")
	fmt.Printf("  %-40s %-12s %s\n", strings.Repeat("-", 40), strings.Repeat("-", 12), strings.Repeat("-", 6))

	for _, entry := range result.Packages {
		if entry.Error != "" {
			fmt.Printf("  %-40s %-12s ERROR: %s\n", entry.Name, entry.Version, entry.Error)
			continue
		}
		riskLabel := fmt.Sprintf("%d/100", entry.Analysis.RiskScore)
		fmt.Printf("  %-40s %-12s %s\n", entry.Name, entry.Version, riskLabel)
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Average Risk:    %d/100\n", result.TotalRisk)
	fmt.Printf("  High Risk (>50): %d\n", result.HighRisk)

	if len(result.CriticalPkgs) > 0 {
		fmt.Printf("  Critical (>75):  %s\n", strings.Join(result.CriticalPkgs, ", "))
	}

	// Write comparative report if output dir is specified.
	if npmBatchOutputDir != "" {
		if mkErr := os.MkdirAll(npmBatchOutputDir, 0o755); mkErr != nil {
			fmt.Printf("Error creating output directory: %v\n", mkErr)
			os.Exit(1)
		}

		// Collect successful analysis results for comparison.
		var analysisResults []*npm.AnalysisResult
		for _, entry := range result.Packages {
			if entry.Analysis != nil {
				analysisResults = append(analysisResults, entry.Analysis)
			}
		}

		compareReport := npm.CompareReport(analysisResults)
		reportPath := filepath.Join(npmBatchOutputDir, "batch-comparison.md")
		if wErr := os.WriteFile(reportPath, []byte(compareReport), 0o644); wErr != nil {
			fmt.Printf("Error writing comparative report: %v\n", wErr)
			os.Exit(1)
		}

		// Also write JSON summary.
		jsonData, jErr := json.MarshalIndent(result, "", "  ")
		if jErr != nil {
			fmt.Printf("Error marshaling batch JSON: %v\n", jErr)
			os.Exit(1)
		}

		jsonPath := filepath.Join(npmBatchOutputDir, "batch-comparison.json")
		if wErr := os.WriteFile(jsonPath, jsonData, 0o644); wErr != nil {
			fmt.Printf("Error writing batch JSON: %v\n", wErr)
			os.Exit(1)
		}

		fmt.Printf("\nComparative report written to %s\n", npmBatchOutputDir)
	}
}

func runNpmDiff(_ *cobra.Command, args []string) {
	name := args[0]
	oldVersion := args[1]
	newVersion := args[2]

	diff, err := npm.DiffVersions(name, oldVersion, newVersion)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if npmJSON {
		data, _ := json.MarshalIndent(diff, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Version Diff: %s\n", diff.Package)
	fmt.Printf("  Old: %s (risk %d/100)\n", diff.OldVersion, diff.OldAnalysis.RiskScore)
	fmt.Printf("  New: %s (risk %d/100)\n", diff.NewVersion, diff.NewAnalysis.RiskScore)

	deltaSign := "+"
	if diff.RiskDelta < 0 {
		deltaSign = ""
	}
	fmt.Printf("  Risk Delta: %s%d\n", deltaSign, diff.RiskDelta)

	if len(diff.Changes) == 0 {
		fmt.Println("\n  No security-relevant changes detected.")
		return
	}

	fmt.Printf("\nChanges (%d):\n", len(diff.Changes))
	for _, c := range diff.Changes {
		marker := "+"
		if c.Type == "removed" {
			marker = "-"
		}
		fmt.Printf("  [%s] %s %s: %s\n", marker, c.Type, c.Category, c.Detail)
	}
}

func runNpmProbe(_ *cobra.Command, args []string) {
	timeout := time.Duration(npmProbeTimeout) * time.Second

	// Check if the first argument is a directory (package-based probe).
	info, statErr := os.Stat(args[0])
	if statErr == nil && info.IsDir() {
		runNpmProbeDir(args[0], timeout)

		return
	}

	// Otherwise, treat as a command + args (raw probe).
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := mcpclient.Probe(ctx, args[0], args[1:]...)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if npmJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	printProbeResult(result)
}

func runNpmProbeDir(dir string, timeout time.Duration) {
	ctx := context.Background()

	result, err := mcpprobe.Probe(ctx, dir, timeout)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if npmJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	if result.Error != "" {
		fmt.Printf("Error:         %s\n", result.Error)

		return
	}

	fmt.Print(mcpprobe.FormatToolList(result))
}
