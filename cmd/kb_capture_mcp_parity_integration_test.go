//go:build integration

/*
Copyright (c) 2026 Security Research

kb_capture_mcp_parity_integration_test.go — Phase 39 (P39-03) in-process
parity assertion (D-39-IN-PROCESS-PARITY) between MCP-driven
`unravel_kb_capture` and CLI-driven `unravel kb capture`.

Both flows ultimately call into the same ingest pipeline
(`pkg/knowledge/kb/ingest.Run`), but they reach it via different
orchestrators:

  - CLI flow:  cmd.runKbCapture → kbCaptureFlags global → ingest.Run
  - MCP flow:  mcptools.kbCaptureHandler → kbCaptureRun → ingest.Run

If MCP and CLI diverge on deterministic identity fields (kb_id,
platform, package_id, display_name) for the same input, the
in-process delegation has a state leak (kbCaptureFlags global, env
var, working directory, or schema mismatch). Failure surfaces as a
real bug worth investigating loudly, NOT silent acceptance.

Run via: `go test -tags=integration -run TestKBCapture_InProcessParity ./cmd/ -count=1`

Skipped under -short and when fdroid.apk fixture is absent.
*/
package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	mcptools "github.com/inovacc/unravel-oss/pkg/mcp/tools"
)

// openParityDB opens a *sql.DB against the testcontainer Postgres DSN.
// Mirrors cmd/kb_gc.go::sql.Open("postgres", dsn) usage.
func openParityDB(dsn string) (*sql.DB, error) {
	return sql.Open("postgres", dsn)
}

// driveKbCaptureViaMCP drives `unravel_kb_capture` through an in-memory
// MCP transport against the same testcontainer Postgres pool used by
// driveKbCapture (CLI flow). Returns the deterministic identity fields
// observed in the resulting kb_apps row.
func driveKbCaptureViaMCP(t *testing.T, ctx context.Context, dsn, appPath string) (kbID, platform, packageID, displayName string, epoch int64) {
	t.Helper()

	// Start a brand-new in-memory MCP server with kb tools wired
	// against the SAME testcontainer DSN used by the CLI driver.
	srv := mcptools.NewServer(mcptools.ServerConfig{
		OnServer: func(s *gomcp.Server) {
			db, err := openParityDB(dsn)
			if err != nil {
				t.Fatalf("open parity DB: %v", err)
			}
			mcptools.RegisterKB(s, db)
		},
	})

	st, ct := gomcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("mcp server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	c := gomcp.NewClient(&gomcp.Implementation{Name: "p39-parity-test", Version: "v0"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("mcp client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	abs, err := filepath.Abs(appPath)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	res, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "unravel_kb_capture",
		Arguments: map[string]any{
			"path":   abs,
			"reason": "p39-03-parity-mcp",
			"by":     "executor",
		},
	})
	if err != nil {
		t.Fatalf("call unravel_kb_capture: %v", err)
	}
	if res.IsError {
		text := ""
		if len(res.Content) > 0 {
			if tc, ok := res.Content[0].(*gomcp.TextContent); ok {
				text = tc.Text
			}
		}
		t.Fatalf("unravel_kb_capture IsError=true: %s", text)
	}
	if len(res.Content) == 0 {
		t.Fatalf("unravel_kb_capture returned no content")
	}
	tc, ok := res.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] not TextContent: %T", res.Content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("unmarshal capture result: %v", err)
	}

	kbID, _ = out["kb_id"].(string)
	if e, ok := out["epoch"].(float64); ok {
		epoch = int64(e)
	}
	// Re-read the kb_apps row directly to obtain platform / package_id
	// / display_name in their canonical SQL form. The MCP handler
	// returns ingest.Result which exposes kb_id/epoch but not
	// platform/package_id/display_name as top-level fields. The kb_apps
	// row IS the parity oracle (D-39-IN-PROCESS-PARITY).
	db, err := openParityDB(dsn)
	if err != nil {
		t.Fatalf("open kb_apps DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	qctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	row := db.QueryRowContext(qctx,
		`SELECT platform, package_id, display_name
		   FROM kb_apps
		  WHERE kb_id = $1`, kbID)
	if err := row.Scan(&platform, &packageID, &displayName); err != nil {
		t.Fatalf("scan kb_apps row for kb_id=%q: %v", kbID, err)
	}
	return kbID, platform, packageID, displayName, epoch
}

// TestKBCapture_InProcessParity drives unravel_kb_capture through both
// the MCP flow and the CLI flow against TWO independent testcontainer
// Postgres instances using the SAME fdroid.apk fixture. Asserts that
// both flows produce identical deterministic identity fields:
//
//   - kb_id        (SHA-256[:16] derived from fingerprint inputs)
//   - platform     (from knowledge.json platform field)
//   - package_id   (from knowledge.json package_id field)
//   - display_name (from knowledge.json display_name field)
//
// Time-stamped fields (captured_at, epoch ordering) are excluded from
// the parity assertion per T-39-07: each flow runs against a fresh DB
// so epoch=1 on each side, and time.Now() differs between runs.
//
// Failure of this test means MCP and CLI flows have diverged on
// identity. That is a real bug — surface it loudly, do NOT mask.
func TestKBCapture_InProcessParity(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}
	apkPath := resolveFixture(t, "input/fdroid.apk")
	requireFixture(t, apkPath)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// CLI side — fresh testcontainer Postgres + UNRAVEL_KB_STORE.
	dbCLI, dsnCLI := dbtest.StartPostgres(t)
	cliKbID, cliPlatform, cliPkgID, cliDisplay := driveKbCapture(t, ctx, dbCLI, dsnCLI, apkPath)

	// MCP side — independent testcontainer Postgres so kb_id is
	// computed from the same fingerprint inputs but stored separately.
	_, dsnMCP := dbtest.StartPostgres(t)
	mcpKbID, mcpPlatform, mcpPkgID, mcpDisplay, _ := driveKbCaptureViaMCP(t, ctx, dsnMCP, apkPath)

	if cliKbID == "" || mcpKbID == "" {
		t.Fatalf("empty kb_id on one side: cli=%q mcp=%q", cliKbID, mcpKbID)
	}
	if cliKbID != mcpKbID {
		t.Errorf("kb_id parity FAILED: cli=%q mcp=%q (D-39-IN-PROCESS-PARITY violated — fingerprint inputs differ between flows)",
			cliKbID, mcpKbID)
	}
	if cliPlatform != mcpPlatform {
		t.Errorf("platform parity FAILED: cli=%q mcp=%q", cliPlatform, mcpPlatform)
	}
	if cliPkgID != mcpPkgID {
		t.Errorf("package_id parity FAILED: cli=%q mcp=%q", cliPkgID, mcpPkgID)
	}
	if cliDisplay != mcpDisplay {
		t.Errorf("display_name parity FAILED: cli=%q mcp=%q", cliDisplay, mcpDisplay)
	}
	if cliPlatform != "android" {
		t.Errorf("expected platform=android for fdroid.apk; got cli=%q", cliPlatform)
	}
	if cliPkgID != "org.fdroid.fdroid" {
		t.Errorf("expected package_id=org.fdroid.fdroid for fdroid.apk; got cli=%q", cliPkgID)
	}
}
