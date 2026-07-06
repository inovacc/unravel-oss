/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"strings"
	"testing"
	"time"
)

// ── sessionField ──────────────────────────────────────────────────────────────

func TestSessionField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		session map[string]any
		key     string
		want    string
	}{
		{name: "nil session", session: nil, key: "file_type", want: ""},
		{name: "key present string", session: map[string]any{"file_type": "PE32"}, key: "file_type", want: "PE32"},
		{name: "key absent", session: map[string]any{"other": "x"}, key: "file_type", want: ""},
		{name: "key present non-string", session: map[string]any{"file_type": 42}, key: "file_type", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := &SessionDetail{Session: tc.session}
			got := sessionField(d, tc.key)
			if got != tc.want {
				t.Errorf("sessionField key=%q = %q; want %q", tc.key, got, tc.want)
			}
		})
	}
}

// ── sessionDuration ───────────────────────────────────────────────────────────

func TestSessionDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		session map[string]any
		want    int64
	}{
		{name: "nil session", session: nil, want: 0},
		{name: "duration present", session: map[string]any{"duration_ms": float64(1234)}, want: 1234},
		{name: "duration absent", session: map[string]any{"other": "x"}, want: 0},
		{name: "duration non-float", session: map[string]any{"duration_ms": "fast"}, want: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := &SessionDetail{Session: tc.session}
			got := sessionDuration(d)
			if got != tc.want {
				t.Errorf("sessionDuration = %d; want %d", got, tc.want)
			}
		})
	}
}

// ── mapSteps ─────────────────────────────────────────────────────────────────

func TestMapSteps(t *testing.T) {
	t.Parallel()

	steps := []StepMetadata{
		{StepName: "alpha", Status: "ok", DurationMs: 10},
		{StepName: "beta", Status: "error", DurationMs: 20},
	}

	m := mapSteps(steps)

	if len(m) != 2 {
		t.Fatalf("mapSteps len = %d; want 2", len(m))
	}
	if m["alpha"].DurationMs != 10 {
		t.Errorf("alpha DurationMs = %d; want 10", m["alpha"].DurationMs)
	}
	if m["beta"].Status != "error" {
		t.Errorf("beta Status = %q; want error", m["beta"].Status)
	}

	// Empty slice
	empty := mapSteps(nil)
	if len(empty) != 0 {
		t.Errorf("mapSteps(nil) len = %d; want 0", len(empty))
	}
}

// ── mergeKeys ────────────────────────────────────────────────────────────────

func TestMergeKeys(t *testing.T) {
	t.Parallel()

	a := map[string]StepMetadata{"x": {}, "y": {}}
	b := map[string]StepMetadata{"y": {}, "z": {}}

	keys := mergeKeys(a, b)

	seen := make(map[string]int)
	for _, k := range keys {
		seen[k]++
	}
	for _, k := range []string{"x", "y", "z"} {
		if seen[k] != 1 {
			t.Errorf("key %q appeared %d times; want 1", k, seen[k])
		}
	}
	if len(keys) != 3 {
		t.Errorf("mergeKeys len = %d; want 3", len(keys))
	}
}

func TestMergeKeys_EmptyMaps(t *testing.T) {
	t.Parallel()

	keys := mergeKeys(nil, nil)
	if len(keys) != 0 {
		t.Errorf("mergeKeys(nil,nil) len = %d; want 0", len(keys))
	}
}

// ── PrintDebugList ────────────────────────────────────────────────────────────
// NOTE: captureStdout redirects global os.Stdout; these tests must NOT run
// in parallel with other captureStdout callers.

func TestPrintDebugList_EmptySessions(t *testing.T) {
	out := captureStdout(t, func() {
		PrintDebugList(nil)
	})
	if !strings.Contains(out, "0 session(s)") {
		t.Errorf("expected '0 session(s)' in output, got:\n%s", out)
	}
}

func TestPrintDebugList_WithSessions(t *testing.T) {
	sessions := []SessionSummary{
		{
			Name:     "sess-001",
			FileType: "PE32",
			Steps:    3,
			Errors:   1,
			Duration: 500,
			Input:    "/tmp/app.exe",
		},
		{
			Name:  "sess-002",
			Steps: 1,
		},
	}

	out := captureStdout(t, func() {
		PrintDebugList(sessions)
	})

	checks := []string{
		"sess-001",
		"(latest)",
		"type=PE32",
		"steps=3",
		"errors=1",
		"duration=500ms",
		"sess-002",
		"2 session(s)",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("expected %q in PrintDebugList output, got:\n%s", c, out)
		}
	}
}

// ── PrintDebugShow ────────────────────────────────────────────────────────────

func TestPrintDebugShow_MinimalDetail(t *testing.T) {
	detail := &SessionDetail{
		Name: "my-session",
		Path: "/tmp/debug/my-session",
	}

	out := captureStdout(t, func() {
		PrintDebugShow(detail)
	})

	if !strings.Contains(out, "my-session") {
		t.Errorf("expected session name in output, got:\n%s", out)
	}
	if !strings.Contains(out, "/tmp/debug/my-session") {
		t.Errorf("expected path in output, got:\n%s", out)
	}
}

func TestPrintDebugShow_WithMetadataAndSteps(t *testing.T) {
	now := time.Now()
	detail := &SessionDetail{
		Name: "full-session",
		Path: "/tmp/debug/full-session",
		Session: map[string]any{
			"timestamp":    "2026-01-01T00:00:00Z",
			"input":        "/app/foo.exe",
			"file_type":    "PE32",
			"category":     "binary",
			"duration_ms":  float64(1234),
			"errors_count": float64(2),
		},
		Files: []string{"session.json", "detect.json"},
		Steps: []StepMetadata{
			{StepName: "detect", Status: "ok", DurationMs: 50, StartTime: now, EndTime: now},
			{StepName: "disasm", Status: "error", DurationMs: 10, Error: "failed to load"},
			{StepName: "ai", Status: "ok", DurationMs: 200, Model: "claude", InputTokens: 100, OutputTokens: 50},
			{StepName: "skip-step", Status: "skipped", DurationMs: 0},
		},
	}

	out := captureStdout(t, func() {
		PrintDebugShow(detail)
	})

	checks := []string{
		"full-session",
		"2026-01-01",
		"PE32",
		"1234ms",
		"session.json",
		"detect",
		"disasm",
		"failed to load",
		"claude",
		"/tmp/debug/full-session",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("expected %q in PrintDebugShow output", c)
		}
	}
}

// ── PrintDebugDiff ────────────────────────────────────────────────────────────

func TestPrintDebugDiff_Basic(t *testing.T) {
	s1 := &SessionDetail{
		Name: "session-A",
		Session: map[string]any{
			"file_type":   "PE32",
			"duration_ms": float64(1000),
		},
		Steps: []StepMetadata{
			{StepName: "detect", DurationMs: 100},
			{StepName: "only-in-A", DurationMs: 50},
		},
	}

	s2 := &SessionDetail{
		Name: "session-B",
		Session: map[string]any{
			"file_type":   "ELF64",
			"duration_ms": float64(2000),
		},
		Steps: []StepMetadata{
			{StepName: "detect", DurationMs: 200},
			{StepName: "only-in-B", DurationMs: 75},
		},
	}

	out := captureStdout(t, func() {
		PrintDebugDiff(s1, s2)
	})

	checks := []string{"session-A", "session-B", "PE32", "ELF64"}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("expected %q in PrintDebugDiff output, got:\n%s", c, out)
		}
	}
}

func TestPrintDebugDiff_SameFileType(t *testing.T) {
	s1 := &SessionDetail{
		Name:    "A",
		Session: map[string]any{"file_type": "PE32", "duration_ms": float64(100)},
	}
	s2 := &SessionDetail{
		Name:    "B",
		Session: map[string]any{"file_type": "PE32", "duration_ms": float64(200)},
	}

	out := captureStdout(t, func() {
		PrintDebugDiff(s1, s2)
	})

	if !strings.Contains(out, "PE32") {
		t.Errorf("expected PE32 in diff output, got:\n%s", out)
	}
}
