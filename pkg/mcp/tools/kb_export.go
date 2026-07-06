/*
Copyright (c) 2026 Security Research

kb_export.go — MCP handler for unravel_kb_transfer_export (P43-03 / KBIM-04).

v2.17 / B2: routes through the supervisor thin-client. The supervisor
returns a kbstore.ExportPayload (DB-row payload, no on-disk bundle); the
on-disk D-43 bundle packaging (manifest.json + .kbb.tar.gz) remains
available via the `unravel kb export` CLI which keeps the direct-DB
path. Wire shape NOTE: prior to B2 this tool emitted
{bundle_dir,bundle_path,manifest,packed,manifest_path}; from B2 onward
it emits the supervisor.KBExportResult payload (schema_version, modules,
files, app_facts, kb_diffs, …). Callers that need the on-disk bundle
must use the CLI.

D-09 inviolate: NO anthropic / claude imports.
*/
package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/internal/supervisor"
)

// kbExportInput mirrors cmd/kb_export.go::kbExportFlags 1:1 for the
// supervisor-routed payload mode (B2).
//
// OutDir / NoPack are retained on the struct for backwards-compatible
// wire schema acceptance but are ignored — bundle packaging happens in
// the CLI path. ManifestPath / BundlePath fields disappear from output.
type kbExportInput struct {
	KbID       string `json:"kb_id"                 jsonschema:"canonical kb_id to export (alias resolution NOT applied; pass canonical id)"`
	LatestOnly bool   `json:"latest_only,omitempty" jsonschema:"include only the newest epoch (legacy --latest-only flag)"`
	OutDir     string `json:"out_dir,omitempty"     jsonschema:"DEPRECATED: ignored. Bundle packaging is CLI-only since v2.17."`
	NoPack     bool   `json:"no_pack,omitempty"     jsonschema:"DEPRECATED: ignored. Bundle packaging is CLI-only since v2.17."`
}

// kbExportOutput kept as an internal type for backwards source-level
// compatibility (kb_export_internal_test asserts the manifest_path JSON
// tag). The handler no longer emits this struct directly — the
// supervisor.KBExportResult goes on the wire instead.
type kbExportOutput struct {
	BundleDir    string `json:"bundle_dir"`
	BundlePath   string `json:"bundle_path,omitempty"`
	Manifest     any    `json:"manifest"`
	Packed       bool   `json:"packed"`
	ManifestPath string `json:"manifest_path,omitempty"`
}

func registerKBExportTool(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "unravel_kb_transfer_export",
		Description: "Export a kb_id to a portable D-43 payload (knowledge.json-equivalent DB rows). Bundle packaging (.kbb.tar.gz) is CLI-only — use `unravel kb export` for on-disk bundles.",
	}, kbExportHandler)
}

func kbExportHandler(ctx context.Context, _ *mcp.CallToolRequest, in kbExportInput) (*mcp.CallToolResult, any, error) {
	if in.KbID == "" {
		return kbErrResult("kb_id is required"), nil, nil
	}

	// Phase B2: route through supervisor thin-client. Wire shape now
	// matches supervisor.KBExportResult (= kbstore.ExportPayload).
	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return kbErrResult(err.Error()), nil, nil
	}

	out, err := cli.Export(ctx, supervisor.KBExportParams{
		KBID:       in.KbID,
		LatestOnly: in.LatestOnly,
	})
	if err != nil {
		return kbErrResult(err.Error()), nil, nil
	}

	return mustKBJSON(kbJSONResult(out))
}
