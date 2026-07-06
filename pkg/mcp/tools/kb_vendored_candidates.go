/*
Copyright (c) 2026 Security Research
*/

// Package mcptools / kb_vendored_candidates.go registers the
// unravel_kb_vendored_candidates MCP tool used by the /unravel-vendored
// Claude Code command.
//
// Returns the top-N body_sha256 groups whose occurrence count meets a
// minimum threshold — these are almost always vendored libraries
// (React, MobX, Apollo, jwt-decode, Dexie, ...) inlined into the
// bundle. Operators feed the resulting hash list back via the
// UNRAVEL_VENDORED_SHAS env var so pending_enrich skips them on the
// next run.
//
// This closes the loop on the plugin-side workflow where the operator
// previously had to drop into psql with a hand-rolled query.
package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/supervisor"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// KBVendoredCandidatesInput is the typed input for
// unravel_kb_vendored_candidates.
type KBVendoredCandidatesInput struct {
	App      string `json:"app,omitempty" jsonschema:"app filter (teams, whatsapp, slack, ...); empty = all apps"`
	DB       string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	MinCount int    `json:"min_count,omitempty" jsonschema:"minimum occurrence count for a hash to qualify as vendored (default 3, hard floor 2)"`
	Top      int    `json:"top,omitempty" jsonschema:"max rows to return, highest occurrence first (default 50, hard cap 200)"`
}

// KBVendoredCandidate is one row in the response.
type KBVendoredCandidate struct {
	SHA256      string `json:"sha256"`
	Occurrences int    `json:"occurrences"`
	SampleName  string `json:"sample_name"`
}

func registerKBVendoredCandidatesTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_vendored_candidates",
		Description: "List body_sha256 groups whose occurrence count >= min_count — " +
			"almost always vendored libraries inlined into the bundle. Returns " +
			"{candidates:[{sha256, occurrences, sample_name}], total_hashes, " +
			"total_vendored_modules, app, min_count, top, env_line}. The env_line " +
			"is paste-ready: prepend it to UNRAVEL_VENDORED_SHAS to make " +
			"pending_enrich skip these rows on the next run. Used by the " +
			"/unravel-vendored plugin command.",
	}, handleKBVendoredCandidates)
}

func handleKBVendoredCandidates(ctx context.Context, _ *mcp.CallToolRequest, in KBVendoredCandidatesInput) (*mcp.CallToolResult, any, error) {
	cli, err := getKBClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("kb client: %w", err)), nil, nil
	}
	res, err := cli.VendoredCandidates(ctx, supervisor.KBVendoredCandidatesParams{
		App:      in.App,
		MinCount: in.MinCount,
		Top:      in.Top,
	})
	if err != nil {
		return errorResult(fmt.Errorf("vendored candidates: %w", err)), nil, nil
	}
	// MCP-tool-side presentation: convert payload candidates into the
	// legacy KBVendoredCandidate shape (same JSON tags) and build the
	// paste-ready env_line on top. env_line stays a CLI-helper concern
	// rather than a supervisor wire field.
	candidates := make([]KBVendoredCandidate, 0, len(res.Candidates))
	for _, c := range res.Candidates {
		candidates = append(candidates, KBVendoredCandidate{
			SHA256:      c.SHA256,
			Occurrences: c.Occurrences,
			SampleName:  c.SampleName,
		})
	}
	envLine := buildVendoredEnvLine(candidates)
	out := map[string]any{
		"candidates":             candidates,
		"total_hashes":           res.TotalHashes,
		"total_vendored_modules": res.TotalVendoredModules,
		"app":                    res.App,
		"min_count":              res.MinCount,
		"top":                    res.Top,
		"env_line":               envLine,
	}
	return jsonResult(out), out, nil
}

func buildVendoredEnvLine(cands []KBVendoredCandidate) string {
	if len(cands) == 0 {
		return ""
	}
	hashes := make([]byte, 0, len(cands)*65)
	for i, c := range cands {
		if i > 0 {
			hashes = append(hashes, ',')
		}
		hashes = append(hashes, c.SHA256...)
	}
	return "export UNRAVEL_VENDORED_SHAS=" + string(hashes)
}
