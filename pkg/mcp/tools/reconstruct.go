/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/inovacc/unravel-oss/pkg/reconstruct"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ReconstructInput defines the MCP tool input schema.
type ReconstructInput struct {
	Path     string `json:"path" jsonschema:"path to file or directory to reconstruct"`
	Mode     string `json:"mode" jsonschema:"plan (get prompt), apply (submit code), status (batch progress)"`
	Code     string `json:"code,omitempty" jsonschema:"reconstructed code for mode=apply"`
	Language string `json:"language,omitempty" jsonschema:"override auto-detection"`
}

// batchState tracks active batch sessions.
type batchState struct {
	mu       sync.Mutex
	sessions map[string]*batchSession
}

type batchSession struct {
	Dir     string
	Total   int
	Current int
	Status  string
	Results []*reconstruct.Result
}

var activeBatches = &batchState{
	sessions: make(map[string]*batchSession),
}

func registerReconstructTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_reconstruct",
		Description: "AI-powered code reconstruction: structural cleanup, semantic enrichment, and verification",
	}, handleReconstruct)
}

func handleReconstruct(_ context.Context, _ *mcp.CallToolRequest, input ReconstructInput) (*mcp.CallToolResult, any, error) {
	switch input.Mode {
	case "plan":
		return handleReconstructPlan(input)
	case "apply":
		return handleReconstructApply(input)
	case "status":
		return handleReconstructStatus(input)
	default:
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("unknown mode %q: use plan, apply, or status", input.Mode)},
			},
			IsError: true,
		}, nil, nil
	}
}

func handleReconstructPlan(input ReconstructInput) (*mcp.CallToolResult, any, error) {
	if input.Path == "" {
		return errorResult(fmt.Errorf("path is required for mode=plan")), nil, nil
	}

	opts := reconstruct.DefaultOptions()
	opts.MCPMode = true
	if input.Language != "" {
		opts.Language = reconstruct.Language(input.Language)
	}

	info, err := os.Stat(input.Path)
	if err != nil {
		return errorResult(fmt.Errorf("stat %s: %w", input.Path, err)), nil, nil
	}

	if info.IsDir() {
		return handleReconstructBatchPlan(input.Path, opts)
	}

	result, err := reconstruct.Run(input.Path, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: result.Prompt},
		},
	}, nil, nil
}

func handleReconstructBatchPlan(dir string, opts reconstruct.Options) (*mcp.CallToolResult, any, error) {
	session := &batchSession{Dir: dir}

	progress := func(current, total int, path, status string) {
		session.Current = current
		session.Total = total
		session.Status = fmt.Sprintf("[%d/%d] %s: %s", current, total, path, status)
	}

	results, err := reconstruct.RunBatch(dir, opts, progress)
	if err != nil {
		return errorResult(err), nil, nil
	}

	session.Results = results
	session.Total = len(results)
	session.Current = len(results)

	activeBatches.mu.Lock()
	activeBatches.sessions[dir] = session
	activeBatches.mu.Unlock()

	// Return prompts for all files.
	var content []mcp.Content
	for i, r := range results {
		if r.Prompt != "" {
			content = append(content, &mcp.TextContent{
				Text: fmt.Sprintf("--- File %d of %d ---\n%s", i+1, len(results), r.Prompt),
			})
		}
	}

	if len(content) == 0 {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "No supported source files found in directory."},
			},
		}, nil, nil
	}

	return &mcp.CallToolResult{Content: content}, nil, nil
}

func handleReconstructApply(input ReconstructInput) (*mcp.CallToolResult, any, error) {
	if input.Path == "" {
		return errorResult(fmt.Errorf("path is required for mode=apply")), nil, nil
	}
	if input.Code == "" {
		return errorResult(fmt.Errorf("code is required for mode=apply")), nil, nil
	}

	// Read original file.
	data, err := os.ReadFile(input.Path)
	if err != nil {
		return errorResult(fmt.Errorf("read original %s: %w", input.Path, err)), nil, nil
	}

	lang := reconstruct.Language(input.Language)
	if lang == "" {
		lang = reconstruct.DetectLanguage(string(data), input.Path)
	}

	opts := reconstruct.DefaultOptions()
	result, err := reconstruct.Apply(string(data), input.Code, lang, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	if result.Stage == "retry" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Verification failed. Please retry with the following prompt:"},
				&mcp.TextContent{Text: result.Prompt},
			},
		}, nil, nil
	}

	// Return success with provenance summary.
	summary := map[string]any{
		"stage":    result.Stage,
		"verified": result.Provenance != nil && result.Provenance.Verified,
	}
	if result.Provenance != nil {
		summary["confidence"] = result.Provenance.Confidence
		summary["original_hash"] = result.Provenance.OriginalHash
	}

	summaryJSON, _ := json.Marshal(summary)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(summaryJSON)},
		},
	}, nil, nil
}

func handleReconstructStatus(input ReconstructInput) (*mcp.CallToolResult, any, error) {
	activeBatches.mu.Lock()
	defer activeBatches.mu.Unlock()

	if input.Path != "" {
		session, ok := activeBatches.sessions[input.Path]
		if !ok {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: "No active batch for directory: " + input.Path},
				},
			}, nil, nil
		}
		status := fmt.Sprintf("Batch %s: %d/%d files processed. Last: %s",
			session.Dir, session.Current, session.Total, session.Status)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: status},
			},
		}, nil, nil
	}

	if len(activeBatches.sessions) == 0 {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "No active batch sessions."},
			},
		}, nil, nil
	}

	var lines []string
	for dir, session := range activeBatches.sessions {
		lines = append(lines, fmt.Sprintf("%s: %d/%d", dir, session.Current, session.Total))
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("Active batches:\n%s", fmt.Sprintf("%s", lines))},
		},
	}, nil, nil
}
