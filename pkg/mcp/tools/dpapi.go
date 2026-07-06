/*
Copyright (c) 2026 Security Research

dpapi.go — MCP tool for Windows DPAPI flag-only forensic dump (Phase 20.2).
Decryption stays in pkg/dpapi (windows+cgo gated, separate CLI surface).
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/dpapidump"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type dpapiDumpInput struct {
	MasterKeyRoots   []string `json:"master_key_roots,omitempty" jsonschema:"DPAPI master-key directories (empty = default %APPDATA%\\Microsoft\\Protect on Windows)"`
	ChromiumProfiles []string `json:"chromium_profiles,omitempty" jsonschema:"Chromium profile directories containing Local State"`
	MaxFiles         int      `json:"max_files,omitempty" jsonschema:"Max master-key files reported per root (default 256)"`
}

func registerDPAPITools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_dpapi_dump",
		Description: "Flag-only enumeration of Windows DPAPI master keys + Chromium-wrapped " +
			"secrets. Reports presence + size + algorithm wrapper WITHOUT decrypting " +
			"(D-14 / D-18). Master-key files are flagged by GUID-shape filename + " +
			"version-header sanity. Chromium envelopes report Local State " +
			"encrypted_key length + Base64 prefix (typically the 'DPAPI' sentinel) " +
			"plus sibling Cookies/Login Data sizes. Decryption is a separate path " +
			"(unravel dpapi decrypt, windows+cgo only). Cross-platform when roots " +
			"and profile paths are supplied explicitly. Phase 20.2.",
	}, handleDPAPIDump)
}

func handleDPAPIDump(_ context.Context, _ *mcp.CallToolRequest, in dpapiDumpInput) (*mcp.CallToolResult, any, error) {
	res, err := dpapidump.Dump(dpapidump.DumpOptions{
		MasterKeyRoots:   in.MasterKeyRoots,
		ChromiumProfiles: in.ChromiumProfiles,
		MaxFiles:         in.MaxFiles,
	})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(res), res, nil
}
