/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"database/sql"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/pkg/goversions"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
)

// openGoversionsDB mirrors the other tools' DB-open path: kbdb.Open reads
// DSN from UNRAVEL_KB_DB / UNRAVEL_KB_DSN / config.yaml (same as openKB).
func openGoversionsDB(ctx context.Context) (*sql.DB, error) {
	return kbdb.Open(ctx, "")
}

type goListInput struct {
	Stable bool `json:"stable" jsonschema:"only stable releases"`
	Limit  int  `json:"limit"  jsonschema:"max rows (0 = all)"`
}

func handleGoVersionsList(ctx context.Context, _ *mcp.CallToolRequest, in goListInput) (*mcp.CallToolResult, any, error) {
	db, err := openGoversionsDB(ctx)
	if err != nil {
		return errorResult(err), nil, nil
	}
	defer func() { _ = db.Close() }()
	rels, err := goversions.ListReleases(db, in.Stable, in.Limit)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(rels), nil, nil
}

type goVersionInput struct {
	Version string `json:"version" jsonschema:"a Go version such as go1.22.5"`
}

func handleGoReleaseInfo(ctx context.Context, _ *mcp.CallToolRequest, in goVersionInput) (*mcp.CallToolResult, any, error) {
	db, err := openGoversionsDB(ctx)
	if err != nil {
		return errorResult(err), nil, nil
	}
	defer func() { _ = db.Close() }()
	rel, meta, files, err := goversions.ReleaseInfo(db, in.Version)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(map[string]any{"release": rel, "meta": meta, "files": files}), nil, nil
}

func handleGoCVEPosture(ctx context.Context, _ *mcp.CallToolRequest, in goVersionInput) (*mcp.CallToolResult, any, error) {
	db, err := openGoversionsDB(ctx)
	if err != nil {
		return errorResult(err), nil, nil
	}
	defer func() { _ = db.Close() }()
	p, err := goversions.CVEPostureFor(db, in.Version)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(p), nil, nil
}

type goVerifyInput struct {
	SHA256 string `json:"sha256" jsonschema:"artifact sha256 to check against official Go releases"`
}

func handleGoVerifyArtifact(ctx context.Context, _ *mcp.CallToolRequest, in goVerifyInput) (*mcp.CallToolResult, any, error) {
	db, err := openGoversionsDB(ctx)
	if err != nil {
		return errorResult(err), nil, nil
	}
	defer func() { _ = db.Close() }()
	ver, file, ok, err := goversions.VerifyArtifact(db, in.SHA256)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(map[string]any{"official": ok, "version": ver, "filename": file}), nil, nil
}

func registerGoversionsTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{Name: "unravel_go_versions_list", Description: "List known Go releases (newest first)"}, handleGoVersionsList)
	mcp.AddTool(s, &mcp.Tool{Name: "unravel_go_release_info", Description: "Files, checksums, date, security note for a Go version"}, handleGoReleaseInfo)
	mcp.AddTool(s, &mcp.Tool{Name: "unravel_go_cve_posture", Description: "CVE posture (exposed/fixed) for a Go version"}, handleGoCVEPosture)
	mcp.AddTool(s, &mcp.Tool{Name: "unravel_go_verify_artifact", Description: "Check whether a sha256 is an official Go artifact"}, handleGoVerifyArtifact)
}
