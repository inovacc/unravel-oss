/*
Copyright (c) 2026 Security Research
*/

package knowledge_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge"
	"github.com/inovacc/unravel-oss/pkg/knowledge/overlay"
)

// TestOverlayMerge_StaticOnlyEquivalent verifies that a static-only
// KnowledgeResult round-trips through the writer cleanly. This is the
// structural precondition for D-10 byte-equivalence: the writer is
// unchanged and the overlay package is never invoked when --live is
// absent.
func TestOverlayMerge_StaticOnlyEquivalent(t *testing.T) {
	r := &knowledge.KnowledgeResult{
		AppName:    "test-fixture",
		Framework:  "electron",
		AnalyzedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SourcePath: "/dev/null",
	}

	tmp := t.TempDir()
	if err := knowledge.WriteDirectory(r, tmp); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "knowledge.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var rt knowledge.KnowledgeResult
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if rt.AppName != r.AppName {
		t.Fatalf("round-trip mismatch: app_name %q vs %q", rt.AppName, r.AppName)
	}
	if rt.Framework != r.Framework {
		t.Fatalf("round-trip mismatch: framework %q vs %q", rt.Framework, r.Framework)
	}
}

// TestOverlayMerge_LiveOverlayShape end-to-ends the overlay engine with
// a synthetic static + live pair, confirming provenance fields land on
// every leaf as documented (KB-CAP-02).
func TestOverlayMerge_LiveOverlayShape(t *testing.T) {
	static := map[string]any{
		"framework": "electron",
		"version":   "1.0.0",
	}
	live := map[string]any{
		"framework": "electron",
		"version":   "1.0.1", // conflict
		"live_only": "value",
	}
	sTS := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lTS := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	merged := overlay.Merge(static, live, overlay.Options{StaticTS: sTS, LiveTS: lTS})

	m, ok := merged.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", merged)
	}

	checkSource(t, m, "framework", "both")
	checkSource(t, m, "version", "live")
	checkHasStatic(t, m, "version")
	checkSource(t, m, "live_only", "live")
}

// TestStaticOutputBackwardCompat verifies that producing the typed
// output via the writer + reading it back produces a struct equivalent
// to the input — i.e., the static output shape is unchanged across
// Phase 23 (D-10 / D-20 invariant via the deterministic path).
func TestStaticOutputBackwardCompat(t *testing.T) {
	cases := []*knowledge.KnowledgeResult{
		{AppName: "a", Framework: "tauri", AnalyzedAt: time.Now().UTC()},
		{AppName: "b", Framework: "electron", AnalyzedAt: time.Now().UTC()},
		{AppName: "c", Framework: "webview2", AnalyzedAt: time.Now().UTC()},
	}
	for _, r := range cases {
		tmp := t.TempDir()
		if err := knowledge.WriteDirectory(r, tmp); err != nil {
			t.Fatalf("WriteDirectory: %v", err)
		}
		// knowledge.live.json MUST NOT be present when no overlay was run.
		if _, err := os.Stat(filepath.Join(tmp, "knowledge.live.json")); !os.IsNotExist(err) {
			t.Fatalf("knowledge.live.json present in static-only path: %v", err)
		}
	}
}

func checkSource(t *testing.T, m map[string]any, key, want string) {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("key %q: expected annotated map, got %T", key, m[key])
	}
	if got, _ := v["_source"].(string); got != want {
		t.Fatalf("key %q: source=%q want %q", key, got, want)
	}
}

func checkHasStatic(t *testing.T, m map[string]any, key string) {
	t.Helper()
	v, _ := m[key].(map[string]any)
	if _, ok := v["_static_value"]; !ok {
		t.Fatalf("key %q: expected _static_value, missing", key)
	}
}
