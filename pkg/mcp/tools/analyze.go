/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/gather"
	"github.com/inovacc/unravel-oss/pkg/manifest"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type analyzeInput struct {
	AppPath      string `json:"app_path,omitempty" jsonschema:"Path to Electron/Tauri application directory or binary"`
	AppType      string `json:"app_type,omitempty" jsonschema:"Force app type: electron, tauri, or auto (default: auto)"`
	ManifestPath string `json:"manifest_path,omitempty" jsonschema:"Path to custom YAML manifest file"`
	Gather       bool   `json:"gather,omitempty" jsonschema:"Scan system for installed Electron/Tauri apps instead of analyzing a specific path"`
}

func registerAnalyzeTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_scan",
		Description: "Full security analysis of an Electron/Tauri app: detection, security config, stealth features, telemetry, IPC, and API endpoints",
	}, handleAnalyze)
}

func handleAnalyze(_ context.Context, _ *mcp.CallToolRequest, input analyzeInput) (*mcp.CallToolResult, any, error) {
	var (
		m   *manifest.Manifest
		err error
	)

	if input.ManifestPath != "" {
		m, err = manifest.Load(input.ManifestPath)
		if err != nil {
			return errorResult(err), nil, nil
		}
	} else {
		m, err = manifest.LoadDefault()
		if err != nil {
			m = manifest.Default()
		}
	}

	if input.Gather {
		entries := gather.Gather(m, false)
		return jsonResult(entries), nil, nil
	}

	appType := input.AppType
	if appType == "" {
		appType = "auto"
	}

	result, err := app.RunAnalysis(input.AppPath, m, appType, false)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
