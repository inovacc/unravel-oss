/*
Copyright (c) 2026 Security Research

kb_import.go — MCP handler for unravel_kb_transfer_import (P43-03 / KBIM-04).

v2.17 / B2: routes through the supervisor thin-client. The supervisor
calls kbstore.Import which reads the bundle directly from the
filesystem path (tar slip + checksum + schema validation happen
supervisor-side as before).

Idempotent on re-import (KBIM-03): kbstore.Import uses ON CONFLICT
DO NOTHING for every upsert; the second call returns NewRowsCount=0.

D-09 inviolate: NO anthropic / claude imports.
*/
package mcptools

import (
	"context"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/internal/supervisor"
)

// kbImportInput mirrors cmd/kb_import.go flags. The path is sent to the
// supervisor verbatim (after local sanity validation); the supervisor
// re-validates against tar slip + checksum + schema.
type kbImportInput struct {
	BundlePath    string `json:"bundle_path"             jsonschema:"absolute path to a .kbb.tar.gz file or an unpacked .kbb/ directory"`
	App           string `json:"app,omitempty"           jsonschema:"optional app override for the import target"`
	VerifyKeyPath string `json:"verify_key_path,omitempty" jsonschema:"optional path to a 32-byte raw Ed25519 public key; when set, the bundle's signature is verified before import (rejects unsigned/tampered V2 bundles)"`
}

// RegisterKBImportExport wires both unravel_kb_transfer_export and unravel_kb_transfer_import
// onto server. Called from cmd/mcp.go alongside RegisterKB.
func RegisterKBImportExport(server *mcp.Server) {
	registerKBExportTool(server)
	registerKBImportTool(server)
}

func registerKBImportTool(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "unravel_kb_transfer_import",
		Description: "Import a D-43 bundle (.kbb.tar.gz or directory) into the knowledge base; idempotent (ON CONFLICT DO NOTHING)",
	}, kbImportHandler)
}

func kbImportHandler(ctx context.Context, _ *mcp.CallToolRequest, in kbImportInput) (*mcp.CallToolResult, any, error) {
	if in.BundlePath == "" {
		return kbErrResult("bundle_path is required"), nil, nil
	}

	// Reject obviously-bad paths early. kbstore.Import re-validates
	// internally against tar slip + checksum + schema (T-43-05/06/09).
	clean := filepath.Clean(in.BundlePath)
	if !filepath.IsAbs(clean) {
		return kbErrResult("bundle_path must be absolute"), nil, nil
	}

	// Phase B2: route through supervisor thin-client.
	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return kbErrResult(err.Error()), nil, nil
	}

	report, err := cli.Import(ctx, supervisor.KBImportParams{
		Path:          clean,
		App:           in.App,
		VerifyKeyPath: in.VerifyKeyPath,
	})
	if err != nil {
		return kbErrResult(err.Error()), nil, nil
	}

	return mustKBJSON(kbJSONResult(report))
}
