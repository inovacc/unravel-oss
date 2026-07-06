/*
Copyright (c) 2026 Security Research

06-04 Task 2: NEW MCP tool surface for JS bundle reconstruction
(D-16). Wires pkg/jsdeob/bundle.Run behind unravel_bundle_reconstruct
with typed input, path-traversal sanitisation (T-06-01), and symlink
rejection (T-06-06).
*/
package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/jsdeob"
	"github.com/inovacc/unravel-oss/pkg/jsdeob/bundle"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// BundleReconstructInput is the typed input for unravel_bundle_reconstruct.
type BundleReconstructInput struct {
	BundlePath string `json:"bundle_path" jsonschema:"absolute path to a webpack/Vite/esbuild/Rollup .js bundle"`
	OutputDir  string `json:"output_dir" jsonschema:"output directory for D-13 layout (modules/, _module_index.json, manifest.json)"`
	UseMCP     bool   `json:"use_mcp,omitempty" jsonschema:"enable Pass 2 MCP fallback for unknown bundle shapes (default false)"`
	Beautify   bool   `json:"beautify,omitempty" jsonschema:"chain BeautifyAI per recovered module (default false)"`
}

func registerBundleTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_bundle_reconstruct",
		Description: "Reconstruct a JS bundle (webpack/Vite/esbuild/Rollup) into per-module files using the hybrid pattern-first / MCP-fallback / brace-balance-validate strategy. Writes manifest.json + _module_index.json under output_dir.",
	}, handleBundleReconstruct)
}

// sanitizeBundleMCPPath cleans + rejects path-traversal segments at the
// MCP boundary (T-06-01).
func sanitizeBundleMCPPath(p string, mustExist bool) (string, error) {
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

// bundleMCPAIBeautifier adapts an *ai.Client to bundle.Beautifier.
type bundleMCPAIBeautifier struct {
	c *ai.Client
}

func (a *bundleMCPAIBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

func handleBundleReconstruct(ctx context.Context, _ *mcp.CallToolRequest, input BundleReconstructInput) (*mcp.CallToolResult, any, error) {
	inAbs, err := sanitizeBundleMCPPath(input.BundlePath, true)
	if err != nil {
		return errorResult(fmt.Errorf("input path: %w", err)), nil, nil
	}
	outAbs, err := sanitizeBundleMCPPath(input.OutputDir, false)
	if err != nil {
		return errorResult(fmt.Errorf("output path: %w", err)), nil, nil
	}

	// Reject symlink input (T-06-06).
	if info, lerr := os.Lstat(inAbs); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errorResult(fmt.Errorf("input is symlink, refusing")), nil, nil
		}
	}

	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return errorResult(fmt.Errorf("mkdir output: %w", err)), nil, nil
	}

	opts := bundle.RunOptions{
		Input:    inAbs,
		Output:   outAbs,
		UseMCP:   input.UseMCP,
		Beautify: input.Beautify,
	}

	if input.UseMCP || input.Beautify {
		client, cerr := ai.NewClient()
		if cerr != nil {
			if input.UseMCP {
				return errorResult(fmt.Errorf("--use-mcp requires AI client: %w", cerr)), nil, nil
			}
		} else {
			adapter := &bundleMCPAIBeautifier{c: client}
			if input.UseMCP {
				opts.AIClient = adapter
			}
			if input.Beautify {
				opts.BeautifierFn = func(ctx context.Context, src []byte, modulePath string) ([]byte, string, error) {
					b, rep, berr := jsdeob.BeautifyAI(ctx, adapter, src, jsdeob.BeautifyAIOptions{
						AIEnabled: true, InputPath: modulePath,
					})
					if berr != nil {
						return src, "", berr
					}
					var fwJSON string
					if rep != nil && len(rep.FrameworkDetected) > 0 {
						if data, jerr := json.Marshal(rep.FrameworkDetected); jerr == nil {
							fwJSON = string(data)
						}
					}
					return b, fwJSON, nil
				}
			}
		}
	}

	report, err := bundle.Run(ctx, opts)
	if err != nil {
		return errorResult(fmt.Errorf("bundle run: %w", err)), nil, nil
	}
	return jsonResult(report), nil, nil
}
