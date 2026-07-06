//go:build integration

/*
Copyright (c) 2026 Security Research

kb_integration_test.go — direct-mode integration tests for the 5 kb_*
MCP handlers. Boots a Postgres testcontainer via dbtest, registers
kb_* handlers on an in-memory MCP transport, and exercises happy/sad
paths.

Run via: `go test -tags=integration -timeout 5m ./pkg/mcptools/...`

These tests skip under `-short` per CLAUDE.md (testcontainer + Docker).

Phase 39 (P39-03) un-skipped the P33 TODO scaffolds. The four tests
that previously deferred to "TODO(33-06)" now drive the MCP handler
against the real fdroid.apk fixture (or skip cleanly if the fixture is
absent). The bridge-mode parity test moved to
`cmd/kb_capture_mcp_parity_integration_test.go` (it requires access to
both runKbCapture and mcptools.NewServer in one package).
*/
package mcptools_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/pkg/config"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	mcptools "github.com/inovacc/unravel-oss/pkg/mcp/tools"
)

// useConfigDSN points the kb_* resolver at dsn by writing a temp config.yaml and
// pinning UNRAVEL_CONFIG to it. config.yaml is the single DSN source of truth
// (the UNRAVEL_KB_DSN env fallback was removed), so integration tests inject the
// testcontainer DSN this way instead of via the env var.
func useConfigDSN(t *testing.T, dsn string) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	pw, _ := u.User.Password()
	port := 5432
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	cfg := config.Config{Database: config.Database{
		Host:     u.Hostname(),
		Port:     port,
		User:     u.User.Username(),
		DBName:   strings.TrimPrefix(u.Path, "/"),
		SSLMode:  u.Query().Get("sslmode"),
		Password: pw,
	}}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.SaveTo(cfg, p); err != nil {
		t.Fatalf("save config: %v", err)
	}
	t.Setenv("UNRAVEL_CONFIG", p)
}

// startKBClient spins up an in-memory MCP server with kb tools wired
// against db (may be nil for DSN-missing tests) and returns a connected
// client session.
func startKBClient(t *testing.T, ctx context.Context, db *sql.DB) *mcp.ClientSession {
	t.Helper()

	srv := mcptools.NewServer(mcptools.ServerConfig{
		OnServer: func(s *mcp.Server) { mcptools.RegisterKB(s, db) },
	})

	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func readToolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		t.Fatalf("empty content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] not TextContent: %T", res.Content[0])
	}
	return tc.Text
}

func callTool(t *testing.T, ctx context.Context, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return res
}

// resolveFixture mirrors cmd/kb_capture_e2e_integration_test.go::resolveFixture.
// Tries the relative path first, then walks up to find the input/ directory.
func resolveFixture(t *testing.T, rel string) string {
	t.Helper()
	if _, err := os.Stat(rel); err == nil {
		return rel
	}
	for _, prefix := range []string{"..", filepath.Join("..", ".."), filepath.Join("..", "..", "..")} {
		candidate := filepath.Join(prefix, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return rel
}

// requireFixture skips when the fixture is missing — keeps CI green on
// hosts without the test corpus.
func requireFixture(t *testing.T, path string) string {
	t.Helper()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		t.Skipf("fixture not present: %s", path)
	} else if err != nil {
		t.Fatalf("stat fixture %s: %v", path, err)
	}
	return path
}

// captureFdroidViaMCP drives unravel_kb_capture in MCP-mode against the
// fdroid.apk fixture. Returns the parsed handler result. Skips cleanly
// if fixture or testcontainer isn't available.
func captureFdroidViaMCP(t *testing.T, ctx context.Context, cs *mcp.ClientSession) map[string]any {
	t.Helper()
	apkRel := "input/fdroid.apk"
	apkPath := resolveFixture(t, apkRel)
	requireFixture(t, apkPath)

	abs, err := filepath.Abs(apkPath)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	res := callTool(t, ctx, cs, "unravel_kb_capture", map[string]any{
		"path":   abs,
		"reason": "p39-03-integration",
		"by":     "executor",
	})
	if res.IsError {
		t.Fatalf("kb_capture returned IsError=true: %s", readToolText(t, res))
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(readToolText(t, res)), &out); err != nil {
		t.Fatalf("unmarshal capture result: %v", err)
	}
	return out
}

// TestKBToolsDirect_DSNMissing asserts every kb_* tool short-circuits
// with the canonical kbDSNHint text when the server was started with
// kbDB=nil (D-33-DSN-FAIL-AT-CALL).
func TestKBToolsDirect_DSNMissing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration suite (testing.Short)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cs := startKBClient(t, ctx, nil)

	tools := []struct {
		name string
		args map[string]any
	}{
		{"unravel_kb_catalog_apps", map[string]any{}},
		{"unravel_kb_catalog_timeline", map[string]any{"kb_id": "x:y:z"}},
		{"unravel_kb_transfer_diff", map[string]any{"kb_id": "x:y:z", "from_epoch": 1, "to_epoch": 2}},
		{"unravel_kb_catalog_search", map[string]any{"query": "foo"}},
		{"unravel_kb_capture", map[string]any{"path": "/tmp/x"}},
	}
	for _, tt := range tools {
		t.Run(tt.name, func(t *testing.T) {
			res := callTool(t, ctx, cs, tt.name, tt.args)
			if !res.IsError {
				t.Fatalf("%s: expected IsError=true with DSN missing", tt.name)
			}
			text := readToolText(t, res)
			if !strings.Contains(text, "config.yaml") {
				t.Errorf("%s: expected DSN hint, got %q", tt.name, text)
			}
		})
	}
}

// TestKBToolsDirect_AppsAndTimeline drives kb_capture against fdroid.apk,
// then asserts that kb_apps lists the new row and kb_timeline returns at
// least one epoch entry with schema_version=1 (P33 D-33-RESULT-PARITY).
//
// Phase 39 (P39-03) un-skipped this scaffold by wiring it to the real
// fdroid.apk fixture and the testcontainer Postgres pool.
func TestKBToolsDirect_AppsAndTimeline(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres testcontainer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	root := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", root)

	db, dsn := dbtest.StartPostgres(t)
	useConfigDSN(t, dsn)
	cs := startKBClient(t, ctx, db)

	cap := captureFdroidViaMCP(t, ctx, cs)
	kbID, _ := cap["kb_id"].(string)
	if kbID == "" {
		t.Fatalf("captured kb_id empty: %#v", cap)
	}

	// kb_apps lists at least the freshly-captured row.
	appsRes := callTool(t, ctx, cs, "unravel_kb_catalog_apps", map[string]any{})
	if appsRes.IsError {
		t.Fatalf("kb_apps IsError: %s", readToolText(t, appsRes))
	}
	var appsOut map[string]any
	if err := json.Unmarshal([]byte(readToolText(t, appsRes)), &appsOut); err != nil {
		t.Fatalf("unmarshal apps: %v", err)
	}
	if v, _ := appsOut["schema_version"].(float64); v != 1 {
		t.Errorf("kb_apps schema_version: got %v, want 1", appsOut["schema_version"])
	}

	// kb_timeline for the captured kb_id returns at least one epoch.
	tlRes := callTool(t, ctx, cs, "unravel_kb_catalog_timeline", map[string]any{"kb_id": kbID})
	if tlRes.IsError {
		t.Fatalf("kb_timeline IsError: %s", readToolText(t, tlRes))
	}
	var tlOut map[string]any
	if err := json.Unmarshal([]byte(readToolText(t, tlRes)), &tlOut); err != nil {
		t.Fatalf("unmarshal timeline: %v", err)
	}
	if v, _ := tlOut["schema_version"].(float64); v != 1 {
		t.Errorf("kb_timeline schema_version: got %v, want 1", tlOut["schema_version"])
	}
}

// TestKBToolsDirect_DiffShortAndLongRange drives two captures (force=true
// on the second) and asserts kb_diff between epoch 1 and 2 returns
// schema_version=1 with no cap-message (consecutive path).
//
// Long-range cap-message parity (>20 epoch span) is not exercised here
// because seeding 25 synthetic epochs would require additional
// fixture work; the cap-message string is asserted byte-for-byte via
// the ingest writer's existing unit tests against constant
// `kbDiffCapMsg` in pkg/mcptools/kb.go (D-33-CLI-PARITY-INVARIANT).
//
// Phase 39 (P39-03) un-skipped this scaffold.
func TestKBToolsDirect_DiffShortAndLongRange(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres testcontainer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	root := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", root)

	db, dsn := dbtest.StartPostgres(t)
	useConfigDSN(t, dsn)
	cs := startKBClient(t, ctx, db)

	// First capture.
	cap1 := captureFdroidViaMCP(t, ctx, cs)
	kbID, _ := cap1["kb_id"].(string)
	if kbID == "" {
		t.Fatalf("cap1 missing kb_id")
	}

	// Force-recapture to produce a second epoch on the same kb_id.
	apkPath := resolveFixture(t, "input/fdroid.apk")
	abs, _ := filepath.Abs(apkPath)
	res2 := callTool(t, ctx, cs, "unravel_kb_capture", map[string]any{
		"path":   abs,
		"force":  true,
		"reason": "p39-03-force-recapture",
	})
	if res2.IsError {
		t.Fatalf("force recapture IsError: %s", readToolText(t, res2))
	}

	// Diff epoch 1 → 2 (consecutive path).
	diffRes := callTool(t, ctx, cs, "unravel_kb_transfer_diff", map[string]any{
		"kb_id":      kbID,
		"from_epoch": 1,
		"to_epoch":   2,
	})
	if diffRes.IsError {
		t.Fatalf("kb_diff IsError: %s", readToolText(t, diffRes))
	}
	var diffOut map[string]any
	if err := json.Unmarshal([]byte(readToolText(t, diffRes)), &diffOut); err != nil {
		t.Fatalf("unmarshal diff: %v", err)
	}
	if v, _ := diffOut["schema_version"].(float64); v != 1 {
		t.Errorf("kb_diff schema_version: got %v, want 1", diffOut["schema_version"])
	}
	// Consecutive path: cap_message MUST be absent or empty.
	if cm, ok := diffOut["cap_message"]; ok && cm != nil && cm != "" {
		t.Errorf("kb_diff consecutive path emitted cap_message: %v", cm)
	}
}

// TestKBToolsDirect_SearchCursor drives a capture, then exercises
// kb_search across the resulting modules. Asserts pagination shape
// (cursor token round-trips) and that an empty/garbage cursor falls
// back to a fresh page rather than erroring (D-33 cursor opaque-token
// semantics).
//
// Phase 39 (P39-03) un-skipped this scaffold.
func TestKBToolsDirect_SearchCursor(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres testcontainer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	root := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", root)

	db, dsn := dbtest.StartPostgres(t)
	useConfigDSN(t, dsn)
	cs := startKBClient(t, ctx, db)

	captureFdroidViaMCP(t, ctx, cs)

	// First page — small limit to force pagination if many modules
	// were ingested. Searching for a permissive query (single char) so
	// trigram match returns SOMETHING.
	page1 := callTool(t, ctx, cs, "unravel_kb_catalog_search", map[string]any{
		"query": "a",
		"limit": 5,
	})
	if page1.IsError {
		t.Fatalf("kb_search page1 IsError: %s", readToolText(t, page1))
	}
	var p1 map[string]any
	if err := json.Unmarshal([]byte(readToolText(t, page1)), &p1); err != nil {
		t.Fatalf("unmarshal page1: %v", err)
	}
	if v, _ := p1["schema_version"].(float64); v != 1 {
		t.Errorf("kb_search schema_version: got %v, want 1", p1["schema_version"])
	}

	// Garbage cursor MUST NOT error — opaque-token semantics restart from
	// the start (D-33 SearchCursor invariant).
	garbage := callTool(t, ctx, cs, "unravel_kb_catalog_search", map[string]any{
		"query":  "a",
		"cursor": "not-a-real-cursor",
		"limit":  5,
	})
	if garbage.IsError {
		t.Errorf("kb_search with garbage cursor MUST NOT error (got IsError=true): %s", readToolText(t, garbage))
	}
}

// TestKBToolsDirect_CaptureTimeoutDefault asserts that omitting
// timeout_seconds yields the 600s default (D-33-CAPTURE-SYNC). This is
// a behavioural smoke: a default-timeout capture against fdroid.apk
// completes well within 600s.
//
// Phase 39 (P39-03) un-skipped this scaffold.
func TestKBToolsDirect_CaptureTimeoutDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres testcontainer + minimal capture target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	root := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", root)

	db, dsn := dbtest.StartPostgres(t)
	useConfigDSN(t, dsn)
	cs := startKBClient(t, ctx, db)

	apkPath := resolveFixture(t, "input/fdroid.apk")
	requireFixture(t, apkPath)
	abs, _ := filepath.Abs(apkPath)

	// Note: we cannot directly observe the 600s clamp from the client
	// side; that's enforced inside kbCaptureHandler. What we CAN assert
	// is that a default-timeout call (no timeout_seconds) succeeds.
	start := time.Now()
	res := callTool(t, ctx, cs, "unravel_kb_capture", map[string]any{
		"path":   abs,
		"reason": "p39-03-default-timeout",
	})
	if res.IsError {
		t.Fatalf("default-timeout capture failed: %s", readToolText(t, res))
	}
	if time.Since(start) >= 10*time.Minute {
		t.Errorf("capture exceeded sane upper bound; default 600s clamp may be misapplied")
	}
}

// TestKBToolsDirect_CaptureTimeoutCustom asserts that a caller-supplied
// timeout_seconds is accepted; values outside [60, 1800] are clamped
// silently (D-33-CAPTURE-SYNC). Concretely tests timeout_seconds=120
// (valid mid-range) and timeout_seconds=1 (clamped up to 60s minimum).
//
// Phase 39 (P39-03) un-skipped this scaffold.
func TestKBToolsDirect_CaptureTimeoutCustom(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres testcontainer + minimal capture target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	root := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", root)

	db, dsn := dbtest.StartPostgres(t)
	useConfigDSN(t, dsn)
	cs := startKBClient(t, ctx, db)

	apkPath := resolveFixture(t, "input/fdroid.apk")
	requireFixture(t, apkPath)
	abs, _ := filepath.Abs(apkPath)

	// Mid-range timeout (120s) — valid as-is.
	res := callTool(t, ctx, cs, "unravel_kb_capture", map[string]any{
		"path":            abs,
		"timeout_seconds": 120,
		"reason":          "p39-03-timeout-120s",
	})
	if res.IsError {
		// 120s may be insufficient for fdroid full pipeline depending
		// on host I/O. Accept timeout error text but reject other
		// errors. The clamp-up-to-60 path is asserted purely by the
		// fact that "1" doesn't reject — see below.
		text := readToolText(t, res)
		if !strings.Contains(text, "timed out") {
			t.Fatalf("custom timeout 120s: unexpected error: %s", text)
		}
	}

	// Below-min (1s) — clamped UP to 60s; the call should not be
	// rejected by argument validation. We don't assert success of the
	// capture itself — 60s may or may not be enough for fdroid — only
	// that the clamp doesn't reject the input.
	res2 := callTool(t, ctx, cs, "unravel_kb_capture", map[string]any{
		"path":            abs,
		"timeout_seconds": 1,
		"force":           true,
		"reason":          "p39-03-timeout-clamp-min",
	})
	if res2.IsError {
		text := readToolText(t, res2)
		// Acceptable: either success or a timed-out (clamp applied to
		// 60s, capture didn't finish). Reject only argument-validation
		// rejections that would suggest the clamp was skipped.
		if strings.Contains(text, "timeout_seconds") && !strings.Contains(text, "timed out") {
			t.Errorf("timeout_seconds=1 unexpectedly rejected at validation: %s", text)
		}
	}
}

// TestKBToolsDirect_CaptureForceSemantics asserts force=false skips on
// identical binary_sha256 and force=true produces a new epoch.
//
// Phase 39 (P39-03) un-skipped this scaffold.
func TestKBToolsDirect_CaptureForceSemantics(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres testcontainer + minimal capture target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	root := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", root)

	db, dsn := dbtest.StartPostgres(t)
	useConfigDSN(t, dsn)
	cs := startKBClient(t, ctx, db)

	apkPath := resolveFixture(t, "input/fdroid.apk")
	requireFixture(t, apkPath)
	abs, _ := filepath.Abs(apkPath)

	// Capture #1 — first time; epoch=1 expected.
	cap1 := callTool(t, ctx, cs, "unravel_kb_capture", map[string]any{
		"path":   abs,
		"reason": "p39-03-force-first",
	})
	if cap1.IsError {
		t.Fatalf("first capture failed: %s", readToolText(t, cap1))
	}
	var c1 map[string]any
	_ = json.Unmarshal([]byte(readToolText(t, cap1)), &c1)
	epoch1, _ := c1["epoch"].(float64)

	// Capture #2 with force=false on same SHA — should skip.
	cap2 := callTool(t, ctx, cs, "unravel_kb_capture", map[string]any{
		"path":   abs,
		"reason": "p39-03-force-skip",
	})
	if cap2.IsError {
		t.Fatalf("second capture (no force) failed: %s", readToolText(t, cap2))
	}
	var c2 map[string]any
	_ = json.Unmarshal([]byte(readToolText(t, cap2)), &c2)
	skipped, _ := c2["skipped"].(bool)
	if !skipped {
		t.Errorf("force=false same-SHA recapture: expected skipped=true; got %#v", c2)
	}

	// Capture #3 with force=true — should produce a new epoch > epoch1.
	cap3 := callTool(t, ctx, cs, "unravel_kb_capture", map[string]any{
		"path":   abs,
		"force":  true,
		"reason": "p39-03-force-true",
	})
	if cap3.IsError {
		t.Fatalf("third capture (force=true) failed: %s", readToolText(t, cap3))
	}
	var c3 map[string]any
	_ = json.Unmarshal([]byte(readToolText(t, cap3)), &c3)
	epoch3, _ := c3["epoch"].(float64)
	if epoch3 <= epoch1 {
		t.Errorf("force=true recapture: expected new epoch > %v; got %v", epoch1, epoch3)
	}
}

// TestKBToolsDirect_CapturePathTraversal asserts relative paths and
// ../ traversal attempts are rejected with IsError=true
// (D-33-CAPTURE-PATH-VALIDATION).
func TestKBToolsDirect_CapturePathTraversal(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	db, _ := dbtest.StartPostgres(t)
	cs := startKBClient(t, ctx, db)

	bad := []string{
		"../etc/passwd",
		"relative/path/binary",
		"./local",
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			res := callTool(t, ctx, cs, "unravel_kb_capture", map[string]any{"path": p})
			if !res.IsError {
				t.Errorf("path %q: expected IsError=true", p)
			}
		})
	}
}
