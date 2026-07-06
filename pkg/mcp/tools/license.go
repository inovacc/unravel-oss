/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"time"

	"github.com/inovacc/unravel-oss/pkg/license"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type licenseTestInput struct {
	URL        string `json:"url" jsonschema:"License API endpoint URL"`
	LicenseKey string `json:"license_key,omitempty" jsonschema:"License key to test (optional)"`
	Timeout    int    `json:"timeout,omitempty" jsonschema:"Request timeout in seconds (default 10)"`
}

func registerLicenseTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_license_test",
		Description: "Test license validation endpoints for common bypass vulnerabilities (empty keys, format manipulation, replay attacks)",
	}, handleLicenseTest)
}

func handleLicenseTest(_ context.Context, _ *mcp.CallToolRequest, input licenseTestInput) (*mcp.CallToolResult, any, error) {
	timeout := input.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	cfg := license.Config{
		TargetURL:  input.URL,
		Timeout:    time.Duration(timeout) * time.Second,
		LicenseKey: input.LicenseKey,
	}

	report := license.RunTests(cfg)

	return jsonResult(report), nil, nil
}
