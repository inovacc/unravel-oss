/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/dissect"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type dissectInput struct {
	Path            string `json:"path" jsonschema:"Path to file or directory to dissect"`
	OutputDir       string `json:"output_dir,omitempty" jsonschema:"Output directory for reports (optional)"`
	Deobfuscate     bool   `json:"deobfuscate,omitempty" jsonschema:"Enable jadx deobfuscation"`
	DecompileNative bool   `json:"decompile_native,omitempty" jsonschema:"Decompile native .so libraries"`
	DecompileDotnet bool   `json:"decompile_dotnet,omitempty" jsonschema:"Decompile .NET assemblies"`
	AIAnalysis      bool   `json:"ai_analysis,omitempty" jsonschema:"Run AI deep analysis via the wired MCP host (no-op outside 'unravel mcp serve')"`
	AIAnalysisMCP   bool   `json:"ai_analysis_mcp,omitempty" jsonschema:"Return AI prompt + data for Claude Code to analyze directly (no API key needed)"`
	Beautify        bool   `json:"beautify,omitempty" jsonschema:"Beautify JavaScript files during analysis"`
	Disassemble     bool   `json:"disassemble,omitempty" jsonschema:"Disassemble binary code sections using external tools or native decoder"`
}

type dissectDirectoryInput struct {
	Directory string `json:"directory" jsonschema:"Path to directory to scan and dissect all recognized files"`
	Verbose   bool   `json:"verbose,omitempty" jsonschema:"Enable verbose output with per-file details"`
}

func registerDissectTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_dissect",
		Description: "Auto-detect file type and run all applicable non-destructive analyses, producing an aggregated result",
	}, handleDissect)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_dissect_dir",
		Description: "Scan a directory, detect all recognized file types, and run dissect on each file. Returns aggregate results with type/category counts, executables, libraries, and per-file analysis.",
	}, handleDissectDirectory)
}

func handleDissect(_ context.Context, _ *mcp.CallToolRequest, input dissectInput) (*mcp.CallToolResult, any, error) {
	opts := dissect.Options{
		OutputDir:       input.OutputDir,
		Deobfuscate:     input.Deobfuscate,
		DecompileNative: input.DecompileNative,
		DecompileDotnet: input.DecompileDotnet,
		AIAnalysis:      input.AIAnalysis,
		Beautify:        input.Beautify,
		Disassemble:     input.Disassemble,
	}

	result, err := dissect.Run(input.Path, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	if input.OutputDir != "" {
		mdPath := input.OutputDir + "/DISSECT_REPORT.md"
		_ = dissect.GenerateMarkdownReport(result, mdPath)

		if result.AIPrompt != "" {
			promptPath := filepath.Join(input.OutputDir, "AI_PROMPT.md")
			_ = os.WriteFile(promptPath, []byte(result.AIPrompt), 0644)
		}

		if result.AIInsights != nil {
			insightsPath := filepath.Join(input.OutputDir, "AI_ANALYSIS.md")
			_ = dissect.WriteAIAnalysisReport(result.AIInsights, insightsPath)
		}
	}

	// MCP AI mode: return the AI prompt + analysis data directly so Claude Code
	// processes it in-conversation. No API key needed — Claude Code IS the AI.
	if input.AIAnalysisMCP && result.AIPrompt != "" {
		dataJSON, err := ai.MarshalDissectForAI(result)
		if err != nil {
			return errorResult(fmt.Errorf("marshal data for AI: %w", err)), nil, nil
		}

		dataSummary := ai.BuildDataSummary(dataJSON)

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: result.AIPrompt},
				&mcp.TextContent{Text: dataSummary},
			},
		}, nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleDissectDirectory(_ context.Context, _ *mcp.CallToolRequest, input dissectDirectoryInput) (*mcp.CallToolResult, any, error) {
	opts := dissect.Options{
		Verbose: input.Verbose,
	}

	result, err := dissect.RunDirectory(input.Directory, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
