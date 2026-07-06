/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRewriteCachedMetadata_RewritesAllInputNamingFields verifies DSC-06 /
// 13-06 closure: a cache-hit workspace whose metadata.json + dissect.json
// were materialised with input A's identity must, after rewriteCachedMetadata
// runs against input B's abs path, carry input B's identity in every
// input-naming field.
func TestRewriteCachedMetadata_RewritesAllInputNamingFields(t *testing.T) {
	pathA := filepath.Join(os.TempDir(), "discord-app-A")
	pathB := filepath.Join(os.TempDir(), "whatsapp-app-B")

	wsDir := t.TempDir()

	// Seed a cached workspace as if a prior run against pathA had populated it.
	mdSeed := map[string]any{
		"app_name":    filepath.Base(pathA),
		"app_path":    pathA,
		"asar_path":   pathA + "/resources/app.asar",
		"analyzed_at": "2025-01-01T00:00:00Z",
		"host":        "old-host",
		"risk_level":  "MEDIUM",
		"risk_score":  42,
	}
	mdData, _ := json.MarshalIndent(mdSeed, "", "  ")
	if err := os.WriteFile(filepath.Join(wsDir, "metadata.json"), mdData, 0644); err != nil {
		t.Fatalf("seed metadata.json: %v", err)
	}

	djSeed := map[string]any{
		"path":        pathA,
		"file_name":   filepath.Base(pathA),
		"source_path": pathA,
		"started_at":  "2025-01-01T00:00:00Z",
		"detection": map[string]any{
			"path": pathA,
			"name": filepath.Base(pathA),
		},
	}
	djData, _ := json.MarshalIndent(djSeed, "", "  ")
	if err := os.WriteFile(filepath.Join(wsDir, "dissect.json"), djData, 0644); err != nil {
		t.Fatalf("seed dissect.json: %v", err)
	}

	// Act: simulate the cache-hit fork — rewrite everything from current input B.
	if err := rewriteCachedMetadata(wsDir, pathB); err != nil {
		t.Fatalf("rewriteCachedMetadata: %v", err)
	}

	// Assert metadata.json reflects pathB.
	mdBytes, _ := os.ReadFile(filepath.Join(wsDir, "metadata.json"))
	var md map[string]any
	if err := json.Unmarshal(mdBytes, &md); err != nil {
		t.Fatalf("re-read metadata.json: %v", err)
	}
	if got, want := md["app_path"], pathB; got != want {
		t.Errorf("metadata.json app_path = %v, want %v", got, want)
	}
	if got, want := md["app_name"], filepath.Base(pathB); got != want {
		t.Errorf("metadata.json app_name = %v, want %v", got, want)
	}
	// asar_path was inside pathA, must be cleared (not pointing into pathB).
	if v, _ := md["asar_path"].(string); v != "" && strings.HasPrefix(v, pathA) {
		t.Errorf("metadata.json asar_path still points into cached pathA: %v", v)
	}
	// Untouched fields preserved.
	if got, want := md["risk_level"], "MEDIUM"; got != want {
		t.Errorf("metadata.json risk_level mutated: got %v want %v", got, want)
	}
	// analyzed_at was rewritten.
	if got := md["analyzed_at"]; got == "2025-01-01T00:00:00Z" {
		t.Errorf("metadata.json analyzed_at not rewritten")
	}

	// Assert dissect.json reflects pathB.
	djBytes, _ := os.ReadFile(filepath.Join(wsDir, "dissect.json"))
	var dj map[string]any
	if err := json.Unmarshal(djBytes, &dj); err != nil {
		t.Fatalf("re-read dissect.json: %v", err)
	}
	if got, want := dj["path"], pathB; got != want {
		t.Errorf("dissect.json path = %v, want %v", got, want)
	}
	if got, want := dj["file_name"], filepath.Base(pathB); got != want {
		t.Errorf("dissect.json file_name = %v, want %v", got, want)
	}
	if got, want := dj["source_path"], pathB; got != want {
		t.Errorf("dissect.json source_path = %v, want %v", got, want)
	}
	det, ok := dj["detection"].(map[string]any)
	if !ok {
		t.Fatalf("dissect.json detection not a map")
	}
	if got, want := det["path"], pathB; got != want {
		t.Errorf("dissect.json detection.path = %v, want %v", got, want)
	}
	if got, want := det["name"], filepath.Base(pathB); got != want {
		t.Errorf("dissect.json detection.name = %v, want %v", got, want)
	}

	// Negative: pathA must not appear anywhere in either rewritten file.
	for _, b := range [][]byte{mdBytes, djBytes} {
		if strings.Contains(string(b), pathA) {
			t.Errorf("rewritten file still contains cached pathA reference:\n%s", string(b))
		}
	}
}

// TestRewriteCachedMetadata_NoOpOnFreshRun confirms calling
// rewriteCachedMetadata with the same path the workspace was just written
// for is a safe no-op (idempotent).
func TestRewriteCachedMetadata_NoOpOnFreshRun(t *testing.T) {
	wsDir := t.TempDir()
	cur := filepath.Join(os.TempDir(), "fresh-app")

	mdSeed := map[string]any{
		"app_name": filepath.Base(cur),
		"app_path": cur,
	}
	mdData, _ := json.MarshalIndent(mdSeed, "", "  ")
	if err := os.WriteFile(filepath.Join(wsDir, "metadata.json"), mdData, 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := rewriteCachedMetadata(wsDir, cur); err != nil {
		t.Fatalf("rewriteCachedMetadata: %v", err)
	}

	mdBytes, _ := os.ReadFile(filepath.Join(wsDir, "metadata.json"))
	var md map[string]any
	_ = json.Unmarshal(mdBytes, &md)
	if got, want := md["app_path"], cur; got != want {
		t.Errorf("app_path mutated: got %v want %v", got, want)
	}
}
