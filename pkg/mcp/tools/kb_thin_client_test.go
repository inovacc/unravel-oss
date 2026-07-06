/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// dialAlwaysFails forces the singleton to exhaust autospawn + retries
// so the ported handlers exercise the ErrSupervisorUnavailable mapping
// path. Pairs with the resetSingletonForTest / withSingletonHooks
// helpers from client_singleton_test.go.
func dialAlwaysFails(_ context.Context, _ string) (net.Conn, error) {
	return nil, errors.New("dial: connection refused (test)")
}

func spawnNoop(_, _ string, _ func() bool) error { return nil }

func wantUnavailableText(t *testing.T, name string, res *mcp.CallToolResult) {
	t.Helper()
	if res == nil || !res.IsError {
		t.Fatalf("%s: want IsError result", name)
	}
	if len(res.Content) == 0 {
		t.Fatalf("%s: empty content", name)
	}
	txt, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s: want TextContent, got %T", name, res.Content[0])
	}
	if !strings.Contains(txt.Text, "daemon unavailable") {
		t.Fatalf("%s: missing daemon-unavailable hint; got %q", name, txt.Text)
	}
}

func TestKBStats_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBStats(context.Background(), nil, kbStatsInput{})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_stats", res)
}

func TestKBDump_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBDump(context.Background(), nil, kbDumpInput{ID: 1})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_dump", res)
}

func TestKBDump_IDRequired(t *testing.T) {
	// ID=0 must short-circuit before touching the singleton.
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBDump(context.Background(), nil, kbDumpInput{ID: 0})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("kb_dump id=0 must be IsError")
	}
}

func TestKBFacts_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBFacts(context.Background(), nil, kbFactsInput{App: "any"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_facts", res)
}

func TestKBGaps_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBGaps(context.Background(), nil, kbGapsInput{App: "any"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_gaps", res)
}

func TestKBApps_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := kbAppsHandler(context.Background(), nil, kbAppsInput{})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("kb_apps: want IsError when supervisor unavailable")
	}
	txt, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("kb_apps: want TextContent, got %T", res.Content[0])
	}
	if !strings.Contains(txt.Text, "daemon unavailable") {
		t.Fatalf("kb_apps: missing daemon-unavailable hint; got %q", txt.Text)
	}
}

func TestKBApps_InvalidRiskShortCircuits(t *testing.T) {
	// Invalid risk validation runs before the supervisor dial.
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := kbAppsHandler(context.Background(), nil, kbAppsInput{Risk: "explosive"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("kb_apps invalid risk must be IsError")
	}
}

// ---------------------------------------------------------------------
// Phase B2 — cross-app verb supervisor-unavailable coverage.
// ---------------------------------------------------------------------

func TestKBDiffApps_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBDiffApps(context.Background(), nil, KBDiffAppsInput{AppA: "whatsapp", AppB: "slack"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_diff_apps", res)
}

func TestKBExport_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := kbExportHandler(context.Background(), nil, kbExportInput{KbID: "whatsapp-windows-deadbeef00"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_export", res)
}

func TestKBExport_KbIDRequired(t *testing.T) {
	// Empty kb_id must short-circuit before touching the singleton.
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := kbExportHandler(context.Background(), nil, kbExportInput{})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("kb_export empty kb_id must be IsError")
	}
}

func TestKBImport_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	// Cross-platform absolute path; the supervisor dial happens after
	// the IsAbs check.
	bundle := filepath.Join(t.TempDir(), "x.kbb.tar.gz")
	res, _, err := kbImportHandler(context.Background(), nil, kbImportInput{BundlePath: bundle})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_import", res)
}

func TestKBImport_BundlePathRequired(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := kbImportHandler(context.Background(), nil, kbImportInput{})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("kb_import empty bundle_path must be IsError")
	}
}

func TestKBImport_BundlePathMustBeAbsolute(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := kbImportHandler(context.Background(), nil, kbImportInput{BundlePath: "relative/path.kbb"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("kb_import relative path must be IsError")
	}
}

func TestKBTimeline_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := kbTimelineHandler(context.Background(), nil, kbTimelineInput{KbID: "whatsapp-windows-deadbeef00"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_timeline", res)
}

func TestKBTimeline_KbIDRequired(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := kbTimelineHandler(context.Background(), nil, kbTimelineInput{})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("kb_timeline empty kb_id must be IsError")
	}
}

// ---------------------------------------------------------------------
// Phase B3 — gap/health verb supervisor-unavailable coverage.
// ---------------------------------------------------------------------

func TestKBPullGap_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBPullGap(context.Background(), nil, kbPullGapInput{App: "whatsapp"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_pull_gap", res)
}

func TestKBPullGap_AppRequired(t *testing.T) {
	// Empty app must short-circuit before touching the singleton.
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBPullGap(context.Background(), nil, kbPullGapInput{})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("kb_pull_gap empty app must be IsError")
	}
}

func TestKBPushAnswer_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBPushAnswer(context.Background(), nil, kbPushAnswerInput{GapID: 1, Value: "v"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_push_answer", res)
}

func TestKBPushAnswer_GapIDRequired(t *testing.T) {
	// GapID=0 must short-circuit before touching the singleton.
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBPushAnswer(context.Background(), nil, kbPushAnswerInput{Value: "v"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("kb_push_answer gap_id=0 must be IsError")
	}
}

func TestKBDoctor_SupervisorUnavailable(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
	res, _, err := handleKBDoctor(context.Background(), nil, kbDoctorInput{})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	wantUnavailableText(t, "kb_doctor", res)
}
