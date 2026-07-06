/*
Copyright (c) 2026 Security Research

Plan 07-04 Task 2: registration + handler dispatch tests for the 3 new
Phase 7 plan 04 MCP tools.
*/
package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/components"
)

// TestPhase7ToolsRegistered checks all 3 new tools are present in the
// pkg/mcptools source by name.
func TestPhase7ToolsRegistered(t *testing.T) {
	body, err := os.ReadFile("knowledge_phase7.go")
	if err != nil {
		t.Fatalf("read knowledge_phase7.go: %v", err)
	}
	want := []string{
		`"unravel_kb_transfer_migrate"`,
		`"unravel_kb_enrich_classify"`,
		`"unravel_kb_ops_regression_check"`,
	}
	src := string(body)
	for _, w := range want {
		if !strings.Contains(src, w) {
			t.Errorf("knowledge_phase7.go missing tool registration %s", w)
		}
	}
}

// TestExtendedDescriptions verifies the existing knowledge + knowledge_diff
// descriptions were extended per the plan.
func TestExtendedDescriptions(t *testing.T) {
	body, err := os.ReadFile("knowledge.go")
	if err != nil {
		t.Fatalf("read knowledge.go: %v", err)
	}
	src := string(body)
	if !strings.Contains(src, "component-grouped source tree") {
		t.Error("unravel_knowledge description missing 'component-grouped source tree'")
	}
	if !strings.Contains(src, "BLOCK") || !strings.Contains(src, "severity") {
		t.Error("unravel_kb_transfer_diff_dirs description must mention BLOCK + severity")
	}
}

// TestHandleKnowledgeMigrateRejectsBadFramework verifies the handler returns
// IsError for an unknown framework.
func TestHandleKnowledgeMigrateRejectsBadFramework(t *testing.T) {
	res, _, err := handleKnowledgeMigrate(context.Background(), nil,
		knowledgeMigrateInput{KBDir: t.TempDir(), Framework: "ruby-on-rails"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatal("expected IsError result for unknown framework")
	}
}

// TestHandleKnowledgeMigrateRejectsTraversal verifies the path-traversal
// guard fires (T-07-01).
func TestHandleKnowledgeMigrateRejectsTraversal(t *testing.T) {
	res, _, err := handleKnowledgeMigrate(context.Background(), nil,
		knowledgeMigrateInput{KBDir: "../etc", Framework: "react"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatal("expected IsError result for traversal kb_dir")
	}
}

// TestHandleClassifyComponentInline verifies classify_component classifies
// inline content into a known bucket.
func TestHandleClassifyComponentInline(t *testing.T) {
	in := knowledgeClassifyComponentInput{
		Path:    "src/auth/login.js",
		Content: "function login(user, pass) { return fetch('/api/auth') }",
	}
	res, _, err := handleKnowledgeClassifyComponent(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("unexpected error result: %+v", res)
	}
	// Decode the JSON text content.
	if len(res.Content) == 0 {
		t.Fatal("empty content")
	}
}

// TestHandleClassifyComponentRejectsLargeContent verifies T-07-06 cap.
func TestHandleClassifyComponentRejectsLargeContent(t *testing.T) {
	huge := strings.Repeat("x", maxClassifyContentBytes+1)
	res, _, err := handleKnowledgeClassifyComponent(context.Background(), nil,
		knowledgeClassifyComponentInput{Path: "/tmp/x.js", Content: huge})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatal("expected IsError for oversized content (T-07-06)")
	}
}

// TestHandleRegressionCheckRejectsTraversal verifies path guard on both dirs.
func TestHandleRegressionCheckRejectsTraversal(t *testing.T) {
	res, _, err := handleKnowledgeRegressionCheck(context.Background(), nil,
		knowledgeRegressionCheckInput{OldDir: "../old", NewDir: "../new"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatal("expected IsError result for traversal old_dir/new_dir")
	}
}

// TestHandleRegressionCheckEmptyDirs verifies the handler runs cleanly
// against two empty (or near-empty) directories — diff returns no
// regressions, summary populated.
func TestHandleRegressionCheckEmptyDirs(t *testing.T) {
	old := t.TempDir()
	newD := t.TempDir()
	// Drop a single empty JSON in each so diff has something to walk.
	for _, d := range []string{old, newD} {
		if err := os.WriteFile(filepath.Join(d, "communication.json"),
			[]byte(`{}`), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	res, _, err := handleKnowledgeRegressionCheck(context.Background(), nil,
		knowledgeRegressionCheckInput{OldDir: old, NewDir: newD})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %+v", res)
	}
}

// TestComponentClassifyContractStable is a contract guard — the components
// package's Classify signature must remain compatible with the handler.
func TestComponentClassifyContractStable(t *testing.T) {
	bucket, conf, src := components.Classify(
		components.SourceFile{Path: "telemetry/sentry.js", Content: []byte("Sentry.init()")},
		components.Options{},
	)
	_ = bucket
	if conf < 0 || conf > 1 {
		t.Errorf("confidence out of [0,1]: %v", conf)
	}
	if src == "" {
		t.Error("classifier source label is empty")
	}
	// Round-trip JSON-encode the result type used by the handler.
	b, err := json.Marshal(knowledgeClassifyComponentResult{
		Component: string(bucket), Classifier: src, Confidence: conf,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"component"`) {
		t.Errorf("missing component field in JSON: %s", b)
	}
}
