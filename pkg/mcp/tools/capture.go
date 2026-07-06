/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/diff"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type captureDiffInput struct {
	BeforeFile string `json:"before_file" jsonschema:"Path to the baseline capture JSON file"`
	AfterFile  string `json:"after_file" jsonschema:"Path to the comparison capture JSON file"`
}

type captureListInput struct {
	Directory string `json:"directory" jsonschema:"Directory to scan for .json capture files"`
}

func registerCaptureTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_capture_diff",
		Description: "Compare two capture session files and return a behavioral diff showing changes in network endpoints, IPC channels, storage paths, stealth behaviors, and console patterns.",
	}, handleCaptureDiff)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_capture_list",
		Description: "List capture session files in a directory, showing app name, event count, duration, and framework for each file.",
	}, handleCaptureList)
}

func handleCaptureDiff(_ context.Context, _ *mcp.CallToolRequest, input captureDiffInput) (*mcp.CallToolResult, any, error) {
	before, err := capture.ReadFile(input.BeforeFile)
	if err != nil {
		return errorResult(fmt.Errorf("read before file: %w", err)), nil, nil
	}

	after, err := capture.ReadFile(input.AfterFile)
	if err != nil {
		return errorResult(fmt.Errorf("read after file: %w", err)), nil, nil
	}

	result := diff.Compare(before, after, input.BeforeFile, input.AfterFile)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return errorResult(err), nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}

type captureFileInfo struct {
	File       string `json:"file"`
	AppName    string `json:"app_name"`
	Framework  string `json:"framework"`
	EventCount int    `json:"event_count"`
	DurationMs int64  `json:"duration_ms"`
}

func handleCaptureList(_ context.Context, _ *mcp.CallToolRequest, input captureListInput) (*mcp.CallToolResult, any, error) {
	entries, err := os.ReadDir(input.Directory)
	if err != nil {
		return errorResult(fmt.Errorf("read directory: %w", err)), nil, nil
	}

	var files []captureFileInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(input.Directory, entry.Name())
		session, err := capture.ReadFile(path)
		if err != nil {
			continue
		}

		files = append(files, captureFileInfo{
			File:       entry.Name(),
			AppName:    session.App.Name,
			Framework:  session.App.Framework,
			EventCount: len(session.Events),
			DurationMs: session.Capture.DurationMs,
		})
	}

	data, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		return errorResult(err), nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}
