/*
Copyright (c) 2026 Security Research

Tests for ComputeDepth: equal-weight 12-dim score formula and stable
covered/missing slice ordering.

License: BSD-3-Clause.
*/
package depth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeKnowledgeJSON helper writes a knowledge.json fixture into ksDir.
func writeKnowledgeJSON(t *testing.T, ksDir string, payload map[string]any) {
	t.Helper()
	if err := os.MkdirAll(ksDir, 0o755); err != nil {
		t.Fatalf("mkdir ksDir: %v", err)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ksDir, "knowledge.json"), b, 0o644); err != nil {
		t.Fatalf("write knowledge.json: %v", err)
	}
}

// makeFixtureN crafts a ksDir that satisfies exactly the first n FS-only
// probes from AllProbes (skipping identity which needs DB). Order matches
// AllProbes minus identity. Returns the ksDir path.
func makeFixtureN(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	// FS-only probes in AllProbes order (skipping identity at index 0).
	// We add coverage incrementally; n counts FS-probes covered.
	if n <= 0 {
		return dir
	}
	// 1: framework
	payload := map[string]any{}
	if n >= 1 {
		payload["framework"] = "electron"
	}
	if n >= 2 {
		payload["dependencies"] = []any{"react"}
	}
	writeKnowledgeJSON(t, dir, payload)
	if n >= 3 {
		// ui
		uiDir := filepath.Join(dir, "sources", "ui")
		_ = os.MkdirAll(uiDir, 0o755)
		_ = os.WriteFile(filepath.Join(uiDir, "App.tsx"), []byte("ui"), 0o644)
	}
	if n >= 4 {
		// managed_source: 10 files in decompiled/
		decomp := filepath.Join(dir, "decompiled")
		_ = os.MkdirAll(decomp, 0o755)
		for i := range 10 {
			_ = os.WriteFile(filepath.Join(decomp, "f"+itoa(i)+".java"), []byte("x"), 0o644)
		}
	}
	if n >= 5 {
		// wire_protocol: a .proto file
		_ = os.WriteFile(filepath.Join(dir, "api.proto"), []byte("syntax=\"proto3\";"), 0o644)
	}
	if n >= 6 {
		// auth: sources/auth/
		_ = os.MkdirAll(filepath.Join(dir, "sources", "auth"), 0o755)
	}
	if n >= 7 {
		// native: lib/foo.so
		libDir := filepath.Join(dir, "lib")
		_ = os.MkdirAll(libDir, 0o755)
		_ = os.WriteFile(filepath.Join(libDir, "foo.so"), []byte("\x7fELF"), 0o644)
	}
	if n >= 8 {
		// webview/
		_ = os.MkdirAll(filepath.Join(dir, "webview"), 0o755)
	}
	if n >= 9 {
		// storage/
		_ = os.MkdirAll(filepath.Join(dir, "storage"), 0o755)
	}
	if n >= 10 {
		// telemetry/ with file
		td := filepath.Join(dir, "telemetry")
		_ = os.MkdirAll(td, 0o755)
		_ = os.WriteFile(filepath.Join(td, "ga.txt"), []byte("ga"), 0o644)
	}
	if n >= 11 {
		// runtime: capture.json
		_ = os.WriteFile(filepath.Join(dir, "capture.json"), []byte("{}"), 0o644)
	}
	return dir
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

func TestComputeDepth_Empty(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	score, covered, missing, err := ComputeDepth(ctx, dir, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if score != 0 {
		t.Errorf("score: got %d want 0", score)
	}
	if len(covered) != 0 {
		t.Errorf("covered: got %v want []", covered)
	}
	if len(missing) != 12 {
		t.Errorf("missing len: got %d want 12", len(missing))
	}
	// Verify missing matches AllProbes order.
	for i, p := range AllProbes {
		if missing[i] != p.Name {
			t.Errorf("missing[%d]: got %s want %s", i, missing[i], p.Name)
		}
	}
}

func TestComputeDepth_AllCovered(t *testing.T) {
	ctx := context.Background()
	// 11 FS probes covered + identity unavailable (nil conn) = 11 covered.
	// To hit 12, we'd need DB. Instead, simulate "all covered" with n=11
	// then verify formula on n=11.
	dir := makeFixtureN(t, 11)
	score, covered, missing, err := ComputeDepth(ctx, dir, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(covered) != 11 {
		t.Errorf("covered len: got %d want 11; covered=%v missing=%v", len(covered), covered, missing)
	}
	if score != 92 { // round(11/12*100) = 92
		t.Errorf("score: got %d want 92", score)
	}
	if len(missing) != 1 || missing[0] != "identity" {
		t.Errorf("missing: got %v want [identity]", missing)
	}
}

func TestComputeDepth_HalfCovered(t *testing.T) {
	ctx := context.Background()
	// 6 FS probes covered → score=50.
	dir := makeFixtureN(t, 6)
	score, covered, missing, err := ComputeDepth(ctx, dir, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(covered) != 6 {
		t.Errorf("covered len: got %d want 6; covered=%v", len(covered), covered)
	}
	if len(missing) != 6 {
		t.Errorf("missing len: got %d want 6; missing=%v", len(missing), missing)
	}
	if score != 50 {
		t.Errorf("score: got %d want 50", score)
	}
	// Union of covered+missing must equal AllProbes names.
	seen := make(map[string]bool, 12)
	for _, n := range covered {
		seen[n] = true
	}
	for _, n := range missing {
		if seen[n] {
			t.Errorf("dim %q in both covered and missing", n)
		}
		seen[n] = true
	}
	for _, p := range AllProbes {
		if !seen[p.Name] {
			t.Errorf("dim %q missing from union", p.Name)
		}
	}
}

func TestComputeDepth_OneCovered(t *testing.T) {
	ctx := context.Background()
	dir := makeFixtureN(t, 1)
	score, covered, _, err := ComputeDepth(ctx, dir, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(covered) != 1 {
		t.Errorf("covered len: got %d want 1", len(covered))
	}
	if score != 8 { // round(1/12*100) = 8.333 → 8
		t.Errorf("score: got %d want 8", score)
	}
}

func TestComputeDepth_ElevenCovered(t *testing.T) {
	ctx := context.Background()
	dir := makeFixtureN(t, 11)
	score, _, _, err := ComputeDepth(ctx, dir, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if score != 92 { // round(11/12*100) = 91.666 → 92
		t.Errorf("score: got %d want 92", score)
	}
}

func TestComputeDepth_StableOrder(t *testing.T) {
	ctx := context.Background()
	dir := makeFixtureN(t, 3)
	_, covered1, missing1, _ := ComputeDepth(ctx, dir, nil)
	_, covered2, missing2, _ := ComputeDepth(ctx, dir, nil)
	if len(covered1) != len(covered2) || len(missing1) != len(missing2) {
		t.Fatalf("instability detected")
	}
	for i := range covered1 {
		if covered1[i] != covered2[i] {
			t.Errorf("covered[%d] unstable: %s vs %s", i, covered1[i], covered2[i])
		}
	}
	for i := range missing1 {
		if missing1[i] != missing2[i] {
			t.Errorf("missing[%d] unstable: %s vs %s", i, missing1[i], missing2[i])
		}
	}
}
