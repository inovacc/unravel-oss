/*
Copyright (c) 2026 Security Research
*/
// unravel_kb_transfer_diff_apps — cross-app behavioural diff over enriched
// modules (KB-CONSUMPTION Phase F per
// docs/superpowers/specs/2026-05-24-kbc-phase-d-g-scope.md).
//
// Returns enriched modules unique to each side of the diff, grouped
// by (app, name). Pairs with a forthcoming `unravel kb diff-apps`
// CLI for human-readable Markdown rendering (out of scope for the
// MCP-tool ship).
//
// v2.17 / B2: routes through the supervisor thin-client
// (internal/supervisor/clients.KBClient.DiffApps). The supervisor owns
// the DSN; the legacy per-call `db` field is retained for backward
// compatibility but is ignored (see KBDiffAppsInput.DB).
package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/internal/supervisor"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

// KBDiffAppsInput is the typed input for unravel_kb_transfer_diff_apps.
type KBDiffAppsInput struct {
	DB       string `json:"db,omitempty"       jsonschema:"DEPRECATED: ignored. The supervisor owns the DSN."`
	AppA     string `json:"app_a"              jsonschema:"left side of the diff (required, e.g. whatsapp)"`
	AppB     string `json:"app_b"              jsonschema:"right side of the diff (required, e.g. slack)"`
	Category string `json:"category,omitempty" jsonschema:"optional tags substring filter (e.g. crypto, network, persistence)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"max rows per side (default 100, hard cap 1000)"`
}

// KBDiffAppsModule is one row of either side of the diff result.
type KBDiffAppsModule struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Tags string `json:"tags,omitempty"`
	Role string `json:"role,omitempty"`
}

func registerKBDiffAppsTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_transfer_diff_apps",
		Description: "Cross-app behavioural diff over enriched modules. " +
			"For two apps (e.g. whatsapp vs slack) returns the named modules " +
			"present in one app's enrichment set but not the other, grouped " +
			"by (app, name). Optional `category` filter narrows by a tags " +
			"substring (crypto/network/persistence/...). Modules without a " +
			"summary are excluded — only enriched rows participate.",
	}, handleKBDiffApps)
}

func handleKBDiffApps(ctx context.Context, _ *mcp.CallToolRequest, in KBDiffAppsInput) (*mcp.CallToolResult, any, error) {
	// Phase B2: route through supervisor thin-client. Wire shape preserved
	// (KBDiffAppsResult is a type-alias of kbstore.DiffAppsResult).
	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return errorResult(err), nil, nil
	}
	res, err := cli.DiffApps(ctx, supervisor.KBDiffAppsParams{
		AppA:     in.AppA,
		AppB:     in.AppB,
		Category: in.Category,
		Limit:    in.Limit,
	})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(res), res, nil
}

// KBDiffAppsModule kept as an alias for backward compatibility with any
// external callers that referenced the tools-package type. The canonical
// type now lives at kbstore.DiffAppsModule.
var _ = KBDiffAppsModule{}
var _ = kbstore.DiffAppsModule{}
