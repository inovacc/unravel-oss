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
	"github.com/inovacc/unravel-oss/pkg/jsdeob"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type jsdeobAnalyzeInput struct {
	FilePath string `json:"file_path" jsonschema:"Path to JavaScript file to analyze"`
}

type jsdeobDeobfuscateInput struct {
	FilePath string `json:"file_path" jsonschema:"Path to JavaScript file to deobfuscate"`
	All      bool   `json:"all,omitempty" jsonschema:"Apply all transformations (default true)"`
}

// JsBeautifyInput is the typed input for unravel_js_beautify (06-04
// Task 2). Path-traversal sanitisation (T-06-01) and symlink rejection
// (T-06-06) are enforced in the handler.
type JsBeautifyInput struct {
	Path      string `json:"path" jsonschema:"absolute path to a minified/obfuscated .js file"`
	OutputDir string `json:"output_dir" jsonschema:"output directory; beautified file written under it as <basename>"`
	Ai        bool   `json:"ai,omitempty" jsonschema:"enable AI-assisted framework-aware beautification + smart renaming (default false = deterministic pure-Go beautify). The AI path needs an MCP sampling-capable caller; headless/sub-agent callers must leave this false."`
}

func registerJsdeobTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_jsdeob_analyze",
		Description: "Analyze JavaScript file for security-relevant patterns: dangerous functions, obfuscation indicators, network operations, encoded payloads",
	}, handleJsdeobAnalyze)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_jsdeob_deobfuscate",
		Description: "Deobfuscate JavaScript: unpack, decode strings, simplify math, rename variables, beautify, extract URLs",
	}, handleJsdeobDeobfuscate)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_js_beautify",
		Description: "Deterministic pure-Go JS beautification by default (no LLM/sampling — works headless). Set ai=true for AI-assisted framework-aware beautification (React/Vue/Angular/Svelte/...) with a structural-preservation guard and raw fallback.",
	}, handleJsBeautify)
}

// sanitizeJsMCPPath cleans + rejects path-traversal segments at the MCP
// boundary (T-06-01).
func sanitizeJsMCPPath(p string, mustExist bool) (string, error) {
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

// jsMCPAIBeautifier adapts an *ai.Client to jsdeob.Beautifier.
type jsMCPAIBeautifier struct {
	c *ai.Client
}

func (a *jsMCPAIBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

func handleJsBeautify(ctx context.Context, _ *mcp.CallToolRequest, input JsBeautifyInput) (*mcp.CallToolResult, any, error) {
	inAbs, err := sanitizeJsMCPPath(input.Path, true)
	if err != nil {
		return errorResult(fmt.Errorf("input path: %w", err)), nil, nil
	}
	outAbs, err := sanitizeJsMCPPath(input.OutputDir, false)
	if err != nil {
		return errorResult(fmt.Errorf("output path: %w", err)), nil, nil
	}

	// Reject symlink input (T-06-06).
	if info, lerr := os.Lstat(inAbs); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errorResult(fmt.Errorf("input is symlink, refusing")), nil, nil
		}
	}

	src, err := os.ReadFile(inAbs)
	if err != nil {
		return errorResult(fmt.Errorf("read input: %w", err)), nil, nil
	}

	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return errorResult(fmt.Errorf("mkdir output: %w", err)), nil, nil
	}
	outFile := filepath.Join(outAbs, filepath.Base(inAbs))

	// T0.4 (KB pipeline remediation): default to deterministic pure-Go
	// beautification — JS beautify needs no LLM — so headless / sub-agent
	// callers (no MCP sampling capability) work instead of hitting "Method
	// not found" on the sampling seam. Only enter the AI path when ai=true,
	// mirroring the CLI's --ai flag (cmd/jsdeob.go). The AI path adds
	// framework-aware smart renaming.
	var outBytes []byte
	var report *jsdeob.BeautifyAIReport
	if input.Ai {
		client, cerr := ai.NewClient()
		if cerr != nil {
			return errorResult(fmt.Errorf("ai client: %w", cerr)), nil, nil
		}
		b, rep, berr := jsdeob.BeautifyAI(ctx, &jsMCPAIBeautifier{c: client}, src, jsdeob.BeautifyAIOptions{
			AIEnabled: true, InputPath: inAbs, OutputDir: outAbs,
		})
		if berr != nil {
			return errorResult(fmt.Errorf("beautify-ai: %w", berr)), nil, nil
		}
		outBytes, report = b, rep
	} else {
		outBytes = []byte(jsdeob.Beautify(string(src)))
		report = &jsdeob.BeautifyAIReport{
			Beautified: true,
			Reason:     "pure-go (deterministic; pass ai=true for framework-aware AI beautify)",
			RawSize:    len(src),
			OutSize:    len(outBytes),
		}
	}

	// Reject symlink at output target (T-06-06).
	if info, lerr := os.Lstat(outFile); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errorResult(fmt.Errorf("refusing to write through symlink: %q", outFile)), nil, nil
		}
	}
	if werr := os.WriteFile(outFile, outBytes, 0o644); werr != nil {
		return errorResult(fmt.Errorf("write output: %w", werr)), nil, nil
	}

	type combined struct {
		OutputPath string                   `json:"output_path"`
		Report     *jsdeob.BeautifyAIReport `json:"report"`
	}
	return jsonResult(combined{OutputPath: outFile, Report: report}), nil, nil
}

func handleJsdeobAnalyze(_ context.Context, _ *mcp.CallToolRequest, input jsdeobAnalyzeInput) (*mcp.CallToolResult, any, error) {
	code, err := os.ReadFile(input.FilePath)
	if err != nil {
		return errorResult(fmt.Errorf("failed to read file: %w", err)), nil, nil
	}

	codeStr := string(code)
	urls := jsdeob.ExtractURLs(codeStr)
	strs := jsdeob.ExtractStrings(codeStr)
	funcs := jsdeob.ExtractFunctions(codeStr)
	apiCalls := jsdeob.ExtractAPICalls(codeStr)

	result := map[string]any{
		"file":            input.FilePath,
		"size_bytes":      len(code),
		"urls":            urls,
		"strings_count":   len(strs),
		"functions_count": len(funcs),
		"api_calls":       apiCalls,
	}

	return jsonResult(result), nil, nil
}

func handleJsdeobDeobfuscate(_ context.Context, _ *mcp.CallToolRequest, input jsdeobDeobfuscateInput) (*mcp.CallToolResult, any, error) {
	code, err := os.ReadFile(input.FilePath)
	if err != nil {
		return errorResult(fmt.Errorf("failed to read file: %w", err)), nil, nil
	}

	opts := jsdeob.Options{
		Beautify:       true,
		DecodeStrings:  true,
		UnpackPacked:   true,
		SimplifyMath:   true,
		RenameVars:     true,
		ExtractStrings: true,
	}

	result, err := jsdeob.Deobfuscate(string(code), opts)
	if err != nil {
		return errorResult(fmt.Errorf("deobfuscation failed: %w", err)), nil, nil
	}

	output := map[string]any{
		"file":            input.FilePath,
		"transformations": result.Transformations,
		"urls":            result.ExtractedURLs,
		"strings_count":   len(result.ExtractedStrs),
		"code_length":     len(result.Code),
		"code":            result.Code,
	}

	return jsonResult(output), nil, nil
}
