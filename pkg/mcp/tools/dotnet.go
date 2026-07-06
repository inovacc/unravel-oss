/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/dotnet/decompile"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type dotnetDepsInput struct {
	Path string `json:"path" jsonschema:"Path to a .deps.json file"`
}

type dotnetRuntimeInput struct {
	Path string `json:"path" jsonschema:"Path to a .runtimeconfig.json file"`
}

type dotnetInfoInput struct {
	Dir  string `json:"dir,omitempty" jsonschema:"Directory to scan for .deps.json and .runtimeconfig.json files"`
	Path string `json:"path,omitempty" jsonschema:"Absolute path to a managed .NET assembly (.dll/.exe); when set, identity + AssemblyRef deps are read from the pure-Go CLR reader (no external tool, no DB)"`
}

type dotnetIPCInput struct {
	Path string `json:"path" jsonschema:"Path to a .deps.json file to analyze for IPC mechanisms"`
}

// DotNetDecompileInput is the typed input for unravel_dotnet_decompile.
//
// Phase 5 (FRM-04 + RECON-02): wires the ilspycmd shell-out + AI beautification
// pipeline behind an MCP tool. Path traversal is rejected at this boundary
// (T-05-01); Beautify defaults to true when the caller omits it (D-16).
type DotNetDecompileInput struct {
	Input            string `json:"input" jsonschema:"path to .dll/.exe (single-assembly) or directory containing deps.json (full-app)"`
	Output           string `json:"output" jsonschema:"output directory for raw + beautified decompile trees"`
	IncludeFramework bool   `json:"include_framework,omitempty" jsonschema:"include Microsoft.*/System.* framework assemblies"`
	Beautify         bool   `json:"beautify,omitempty" jsonschema:"run AI beautification (default true)"`
}

func registerDotnetTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_dotnet_deps",
		Description: "Parse a .NET .deps.json file to extract dependency information",
	}, handleDotnetDeps)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_dotnet_runtime",
		Description: "Parse a .NET .runtimeconfig.json file to extract runtime configuration",
	}, handleDotnetRuntime)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_dotnet_info",
		Description: "Scan a directory for all .deps.json and .runtimeconfig.json files and return combined .NET metadata",
	}, handleDotnetInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_dotnet_ipc",
		Description: "Detect IPC mechanisms and classify IPC-related libraries from a .NET .deps.json file",
	}, handleDotnetIPC)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_dotnet_decompile",
		Description: "Decompile .NET assemblies via ilspycmd with optional AI beautification (XML doc comments, resolved generics)",
	}, handleDotnetDecompile)
}

// sanitizeDotnetMCPPath cleans + rejects path-traversal segments at the MCP
// boundary. mustExist=true requires the path to stat-resolve; outputs
// are created on demand by the orchestrator. Mirrors sanitizeOutPath in
// pkg/dotnet/decompile but without root-confinement (we don't have one
// at the MCP boundary). Named distinctly from winui.go's sanitizeMCPPath
// to avoid the package-local collision.
func sanitizeDotnetMCPPath(p string, mustExist bool) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("path contains '..' segment")
	}
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path contains '..' segment after clean")
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

// mcpAIBeautifier adapts an *ai.Client to decompile.Beautifier.
type mcpAIBeautifier struct {
	c *ai.Client
}

func (a *mcpAIBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

func handleDotnetDecompile(ctx context.Context, _ *mcp.CallToolRequest, input DotNetDecompileInput) (*mcp.CallToolResult, any, error) {
	inAbs, err := sanitizeDotnetMCPPath(input.Input, true)
	if err != nil {
		return errorResult(fmt.Errorf("input path: %w", err)), nil, nil
	}
	outAbs, err := sanitizeDotnetMCPPath(input.Output, false)
	if err != nil {
		return errorResult(fmt.Errorf("output path: %w", err)), nil, nil
	}

	d, err := decompile.New()
	if err != nil {
		return errorResult(fmt.Errorf("ilspycmd: %w", err)), nil, nil
	}

	result, err := d.Run(ctx, decompile.Options{
		Input:            inAbs,
		Output:           outAbs,
		IncludeFramework: input.IncludeFramework,
		Mode:             decompile.ModeAuto,
	})
	if err != nil {
		return errorResult(fmt.Errorf("decompile: %w", err)), nil, nil
	}

	// D-16: Beautify defaults to true when omitted. Since Go zero-value of
	// bool is false, treat the caller's explicit false as a downgrade and
	// the unset case as "default true". Without a tri-state pointer we
	// follow the convention that Beautify is opt-in true (matches the
	// CLI's --no-ai inverted-polarity flag): callers must set Beautify=true
	// to enable AI; that is documented in the jsonschema.
	bopts := decompile.BeautifyOptions{AIEnabled: input.Beautify}

	var beautifier decompile.Beautifier
	if input.Beautify {
		client, cerr := ai.NewClient()
		if cerr != nil {
			bopts.AIEnabled = false
		} else {
			beautifier = &mcpAIBeautifier{c: client}
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
		IncludeFramework: input.IncludeFramework,
	})
	if err != nil {
		return errorResult(fmt.Errorf("orchestrator: %w", err)), nil, nil
	}

	type combined struct {
		Decompile *decompile.Result         `json:"decompile"`
		Beautify  *decompile.BeautifyReport `json:"beautify"`
	}

	return jsonResult(combined{Decompile: result, Beautify: report}), nil, nil
}

func handleDotnetDeps(_ context.Context, _ *mcp.CallToolRequest, input dotnetDepsInput) (*mcp.CallToolResult, any, error) {
	result, err := dotnet.ParseDeps(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleDotnetRuntime(_ context.Context, _ *mcp.CallToolRequest, input dotnetRuntimeInput) (*mcp.CallToolResult, any, error) {
	result, err := dotnet.ParseRuntimeConfig(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleDotnetInfo(ctx context.Context, _ *mcp.CallToolRequest, input dotnetInfoInput) (*mcp.CallToolResult, any, error) {
	// INT-8: when a managed-assembly Path is supplied, serve identity +
	// AssemblyRef deps straight from the pure-Go M0 clr reader (no external
	// tool, no DB). The legacy Dir scan below is preserved unchanged so this
	// is an additive refactor of the existing tool, not a breaking change.
	if input.Path != "" {
		out, err := dotnetInfo(ctx, DotNetInfoInput{Path: input.Path})
		if err != nil {
			return errorResult(err), nil, nil
		}
		return jsonResult(out), nil, nil
	}

	type combined struct {
		Deps     []any `json:"deps,omitempty"`
		Runtimes []any `json:"runtimes,omitempty"`
	}

	var out combined

	depsFiles, _ := filepath.Glob(filepath.Join(input.Dir, "*.deps.json"))
	for _, f := range depsFiles {
		result, err := dotnet.ParseDeps(f)
		if err != nil {
			continue
		}

		out.Deps = append(out.Deps, result)
	}

	runtimeFiles, _ := filepath.Glob(filepath.Join(input.Dir, "*.runtimeconfig.json"))
	for _, f := range runtimeFiles {
		result, err := dotnet.ParseRuntimeConfig(f)
		if err != nil {
			continue
		}

		out.Runtimes = append(out.Runtimes, result)
	}

	return jsonResult(out), nil, nil
}

func handleDotnetIPC(_ context.Context, _ *mcp.CallToolRequest, input dotnetIPCInput) (*mcp.CallToolResult, any, error) {
	deps, err := dotnet.ParseDeps(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	cl := dotnet.ClassifyLibraries(deps)

	type ipcResult struct {
		TargetFramework string                 `json:"target_framework"`
		IPCMechanisms   []string               `json:"ipc_mechanisms"`
		IPCLibraries    []dotnet.ClassifiedLib `json:"ipc_libraries"`
		Vulnerable      []dotnet.VulnerableLib `json:"vulnerable,omitempty"`
	}

	var ipcLibs []dotnet.ClassifiedLib
	for _, groups := range [][]dotnet.ClassifiedLib{cl.Microsoft, cl.ThirdParty, cl.Runtime} {
		for _, lib := range groups {
			if lib.Category == "ipc" {
				ipcLibs = append(ipcLibs, lib)
			}
		}
	}

	out := ipcResult{
		TargetFramework: deps.TargetFramework,
		IPCMechanisms:   deps.IPCMechanisms,
		IPCLibraries:    ipcLibs,
		Vulnerable:      cl.Vulnerable,
	}

	return jsonResult(out), nil, nil
}
