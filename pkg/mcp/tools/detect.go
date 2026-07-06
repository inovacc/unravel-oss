/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"os"

	"github.com/inovacc/unravel-oss/pkg/detect"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type detectInput struct {
	Path string `json:"path" jsonschema:"Path to file or directory to identify"`
}

func registerDetectTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_detect",
		Description: "Detect file type by content (magic bytes, headers, structure) and show applicable unravel commands",
	}, handleDetect)
}

func handleDetect(_ context.Context, _ *mcp.CallToolRequest, input detectInput) (*mcp.CallToolResult, any, error) {
	info, err := os.Stat(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	if info.IsDir() {
		result, scanErr := detect.Scan(input.Path)
		if scanErr != nil {
			return errorResult(scanErr), nil, nil
		}

		return jsonResult(result), nil, nil
	}

	result, detectErr := detect.Detect(input.Path)
	if detectErr != nil {
		return errorResult(detectErr), nil, nil
	}

	return jsonResult(result), nil, nil
}
