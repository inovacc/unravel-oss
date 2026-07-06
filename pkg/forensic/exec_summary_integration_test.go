/*
Copyright (c) 2026 Security Research

Phase 11-03 Task 2: end-to-end integration test for the production sampling
client. Wires an in-memory transport stub host, registers a deterministic
CreateMessage handler, calls forensic.WriteHTMLReportFull with
mcpinternal.ForensicClient(), and asserts the rendered HTML contains the
canned ExecSummary text. Also exercises the D-06 graceful-degrade path when
no session is wired.
*/
package forensic_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	mcpinternal "github.com/inovacc/unravel-oss/internal/mcp"
	"github.com/inovacc/unravel-oss/pkg/forensic"
	pkgmcp "github.com/inovacc/unravel-oss/pkg/mcp"
)

// newStubHost mirrors internal/mcp/sampling_test.go::newStubHost (kept local
// per 11-03 plan §"either expose ... OR duplicate"; duplication keeps the
// internal/mcp test surface small).
func newStubHost(t *testing.T, handler func(context.Context, *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error)) *gomcp.ServerSession {
	t.Helper()
	ctx := context.Background()
	ct, st := gomcp.NewInMemoryTransports()
	host := gomcp.NewClient(&gomcp.Implementation{Name: "test-host", Version: "0.0.0"}, &gomcp.ClientOptions{
		CreateMessageHandler: handler,
	})
	srv := gomcp.NewServer(&gomcp.Implementation{Name: "unravel-test", Version: "0.0.0"}, nil)
	// 11-01 SUMMARY diagnostic: server.Connect MUST run before host.Connect or
	// both sides deadlock on the init handshake.
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := host.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("host connect: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Close()
	})
	return ss
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func loadSampleReportForTest(t *testing.T) *forensic.Report {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "sample_report.json"))
	if err != nil {
		t.Fatalf("read sample_report.json: %v", err)
	}
	var r forensic.Report
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("unmarshal sample_report.json: %v", err)
	}
	return &r
}

// uniqueModelID returns a per-test model discriminator so the on-disk cache
// (keyed by sha256(findings)+0x00+modelID) cannot hit between runs.
func uniqueModelID(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test-model-%s-%d", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
}

// TestWriteHTMLReportFull_AI_InMemoryHost proves the full path:
// stub host -> sample() -> forensicAdapter.Summarize -> ParseMCPResponse ->
// renderHTML. The canned TLDR string must appear verbatim in report.html.
func TestWriteHTMLReportFull_AI_InMemoryHost(t *testing.T) {
	t.Setenv("UNRAVEL_MCP_MODEL", uniqueModelID(t))
	canned := forensic.ExecSummary{
		TLDR: "AI-test executive summary -- end-to-end stub host fired",
		TopRisks: []forensic.TopRisk{
			{Title: "Hardcoded API key in apk strings", Severity: "high", CWE: 798},
		},
		RemediationPriorities: []string{
			"Rotate the leaked credential and migrate to runtime-issued tokens",
		},
	}
	body, err := json.Marshal(canned)
	if err != nil {
		t.Fatalf("marshal canned summary: %v", err)
	}

	ss := newStubHost(t, func(_ context.Context, _ *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error) {
		return &gomcp.CreateMessageResult{
			Content: &gomcp.TextContent{Text: string(body)},
			Model:   "test-model",
			Role:    "assistant",
		}, nil
	})
	pkgmcp.SetSession(ss, quietLogger())
	t.Cleanup(func() { pkgmcp.SetSession(nil, quietLogger()) })

	r := loadSampleReportForTest(t)
	outDir := t.TempDir()
	htmlOpts := forensic.HTMLRenderOptions{
		IncludeImages: false,
		AI:            true,
		MCPClient:     mcpinternal.ForensicClient(),
	}
	if err := forensic.WriteHTMLReportFull(context.Background(), r, htmlOpts, outDir); err != nil {
		t.Fatalf("WriteHTMLReportFull: %v", err)
	}
	htmlBytes, err := os.ReadFile(filepath.Join(outDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(htmlBytes)
	if !strings.Contains(html, "AI-test executive summary -- end-to-end stub host fired") {
		t.Fatalf("AI section missing canned TLDR; HTML body:\n%s", html)
	}
	if !strings.Contains(html, "Hardcoded API key in apk strings") {
		t.Fatalf("AI section missing canned TopRisk title")
	}
}

// TestForensic_GracefulDegrade_NoSession proves the D-06 path:
// SetSession(nil) -> ForensicClient() returns NilMCPClient -> Summarize errors
// -> WriteHTMLReportFull renders without the AI section, no error returned.
func TestForensic_GracefulDegrade_NoSession(t *testing.T) {
	t.Setenv("UNRAVEL_MCP_MODEL", uniqueModelID(t))
	pkgmcp.SetSession(nil, quietLogger())

	r := loadSampleReportForTest(t)
	outDir := t.TempDir()
	htmlOpts := forensic.HTMLRenderOptions{
		IncludeImages: false,
		AI:            true,
		MCPClient:     mcpinternal.ForensicClient(),
	}
	if err := forensic.WriteHTMLReportFull(context.Background(), r, htmlOpts, outDir); err != nil {
		t.Fatalf("WriteHTMLReportFull (no session): %v", err)
	}
	htmlBytes, err := os.ReadFile(filepath.Join(outDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	// Graceful degrade: must NOT contain a canned-AI marker. Renderer either
	// omits the section or shows a documented placeholder; either way, the
	// canned TLDR from the in-memory test cannot appear.
	if strings.Contains(string(htmlBytes), "AI-test executive summary") {
		t.Fatalf("graceful-degrade path leaked stub-host content into output")
	}
}
