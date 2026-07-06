/*
Copyright (c) 2026 Security Research

tpm.go — MCP tools for TPM forensic dumps (Phase 20.1).
*/
package mcptools

import (
	"context"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/tpm"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type tpmDumpInput struct {
	SearchPath string `json:"search_path" jsonschema:"Filesystem path to scan for sealbox-style sealed blobs"`
	OutputPath string `json:"output_path,omitempty" jsonschema:"Optional directory to write extraction_results.json + per-key files (caller must ensure parent is writable)"`
}

type tpmInfoInput struct{}

func registerTPMTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_tpm_info",
		Description: "Report TPM availability and platform info (Available, Platform, Error). Read-only; does not touch the TPM.",
	}, handleTPMInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_tpm_dump",
		Description: "Forensic dump of TPM-sealed blobs on disk. Scans the given path for sealbox-style sealed " +
			"blobs and emits an ExtractionResult with per-blob SHA-256, size, mod-time, and CanUnseal verdict. " +
			"Key material is never returned through the MCP envelope; if OutputPath is supplied the unsealed " +
			"key bytes are written to <output>/keys/<blob>.key on disk only. Phase 20.1.",
	}, handleTPMDump)
}

func handleTPMInfo(_ context.Context, _ *mcp.CallToolRequest, _ tpmInfoInput) (*mcp.CallToolResult, any, error) {
	info := tpm.CheckTPM()
	return jsonResult(info), info, nil
}

func handleTPMDump(_ context.Context, _ *mcp.CallToolRequest, in tpmDumpInput) (*mcp.CallToolResult, any, error) {
	if in.SearchPath == "" {
		return errorResult(fmt.Errorf("search_path is required")), nil, nil
	}
	result, err := tpm.ScanAndExtract(in.SearchPath, in.OutputPath)
	if err != nil {
		return errorResult(fmt.Errorf("tpm scan: %w", err)), nil, nil
	}
	// Sanitise: never return key material through the MCP envelope. Keys
	// (if extracted) are persisted to OutputPath on disk; the response
	// must report only metadata.
	for i := range result.SealedKeys {
		result.SealedKeys[i].KeyHex = ""
	}
	return jsonResult(result), result, nil
}
