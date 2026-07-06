/*
Copyright (c) 2026 Security Research

registry.go — MCP tool for Windows registry forensic dumps (Phase 20.3).
*/
package mcptools

import (
	"context"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/winregistry"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type registryDumpInput struct {
	Keys            []string `json:"keys" jsonschema:"Hive-prefixed registry paths to dump (HKLM\\..., HKCU\\..., HKCR\\..., HKU\\..., HKCC\\...)"`
	MaxDepth        int      `json:"max_depth,omitempty" jsonschema:"Max subkey recursion depth (default 3, capped at 20)"`
	MaxValuesPerKey int      `json:"max_values_per_key,omitempty" jsonschema:"Max values captured per key (default 256, capped at 4096)"`
	DryRun          bool     `json:"dry_run,omitempty" jsonschema:"Walk subkeys but skip value reads"`
}

func registerRegistryTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_registry_dump",
		Description: "Read-only Windows registry walker. Captures scoped hive-prefixed keys " +
			"(HKLM/HKCU/HKCR/HKU/HKCC) with bounded recursion (max_depth, default 3) and " +
			"per-key value cap (max_values_per_key, default 256). Returns a structured " +
			"Result envelope with per-key timestamps + typed values (REG_SZ as string, " +
			"REG_DWORD/QWORD as integers, REG_BINARY/MULTI_SZ as base64/array). On " +
			"non-Windows hosts returns a structured 'not supported on $GOOS' Result. " +
			"Phase 20.3.",
	}, handleRegistryDump)
}

func handleRegistryDump(_ context.Context, _ *mcp.CallToolRequest, in registryDumpInput) (*mcp.CallToolResult, any, error) {
	if len(in.Keys) == 0 {
		return errorResult(fmt.Errorf("keys is required (at least one hive-prefixed registry path)")), nil, nil
	}
	res, err := winregistry.Dump(winregistry.DumpOptions{
		Keys:            in.Keys,
		MaxDepth:        in.MaxDepth,
		MaxValuesPerKey: in.MaxValuesPerKey,
		DryRun:          in.DryRun,
	})
	// On non-Windows the function returns (Result, ErrNotSupported); we
	// still want to ship the Result envelope so the caller sees the
	// structured platform error.
	if res == nil {
		return errorResult(fmt.Errorf("registry dump: %w", err)), nil, nil
	}
	return jsonResult(res), res, nil
}
