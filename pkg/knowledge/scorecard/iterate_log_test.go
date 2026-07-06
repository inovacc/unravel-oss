/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fullRichRecord constructs an IterationRecord populated with every
// snake_case field for byte-level fidelity assertions (B1).
func fullRichRecord(id string, n int) IterationRecord {
	return IterationRecord{
		ID:       id,
		Iter:     n,
		TS:       "2026-05-07T12:34:56Z",
		WeakDims: []string{"wire", "auth", "ipc", "state_machines"},
		Dispatched: []DispatchResult{
			{Pass: "wire", TargetDims: []string{"wire"}, DurationMs: 3200, FramesCaptured: 42, OK: true, Note: ""},
			{Pass: "auth", TargetDims: []string{"auth"}, DurationMs: 100, FramesCaptured: 0, OK: false, Note: "no frames"},
		},
		Bumps:                     map[string]int{"wire": 85, "auth": 80, "ipc": 80, "state_machines": 80},
		Mean:                      72,
		Coverage:                  7,
		PostMean:                  81,
		PostCoverage:              12,
		RuntimeCaptureUnavailable: false,
		CitationsOK:               false,
	}
}

func TestWriteIterationRecord_RichSchemaFidelity(t *testing.T) {
	dir := t.TempDir()
	rec := fullRichRecord("iter-1", 1)
	if err := writeIterationRecord(dir, rec); err != nil {
		t.Fatalf("write: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "iterations.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(b)
	for _, field := range []string{
		`"id":"iter-1"`, `"iter":1`, `"ts":"2026-05-07T12:34:56Z"`,
		`"weak_dims"`, `"dispatched"`, `"bumps"`, `"mean":72`, `"coverage":7`,
		`"post_mean":81`, `"post_coverage":12`,
		`"runtime_capture_unavailable":false`, `"citations_ok":false`,
		`"target_dims"`, `"duration_ms":3200`, `"frames_captured":42`,
	} {
		if !strings.Contains(s, field) {
			t.Errorf("missing snake_case field %s in %s", field, s)
		}
	}

	// Decode back; assert DispatchResult is structured (not a string).
	var out IterationRecord
	line := strings.TrimSpace(s)
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Dispatched) != 2 || out.Dispatched[0].Pass != "wire" {
		t.Fatalf("DispatchResult not structured: %+v", out.Dispatched)
	}
}

func TestWriteIterationRecord_AppendWithinOneRun(t *testing.T) {
	dir := t.TempDir()
	for i := 1; i <= 2; i++ {
		if err := writeIterationRecord(dir, fullRichRecord("iter-1", i)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "iterations.jsonl"))
	if cnt := strings.Count(string(b), "\n"); cnt != 2 {
		t.Fatalf("want 2 lines, got %d", cnt)
	}
}

// W2 — append-mode ACROSS multiple Iterate invocations against the same dir.
func TestWriteIterationRecord_AppendAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	// "Run 1" — 2 records.
	for i := 1; i <= 2; i++ {
		if err := writeIterationRecord(dir, fullRichRecord("iter-1", i)); err != nil {
			t.Fatalf("run1 %d: %v", i, err)
		}
	}
	// "Run 2" — 3 more records, same dir, no truncation.
	for i := 1; i <= 3; i++ {
		if err := writeIterationRecord(dir, fullRichRecord("iter-2", i)); err != nil {
			t.Fatalf("run2 %d: %v", i, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "iterations.jsonl"))
	if cnt := strings.Count(string(b), "\n"); cnt != 5 {
		t.Fatalf("want 5 lines after cross-run append, got %d", cnt)
	}
}

func TestWriteIterationRecord_AutoCreatesDir(t *testing.T) {
	parent := t.TempDir()
	nested := filepath.Join(parent, "kb", "deep", "subdir")
	if err := writeIterationRecord(nested, fullRichRecord("iter-1", 1)); err != nil {
		t.Fatalf("write nested: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nested, "iterations.jsonl")); err != nil {
		t.Fatalf("expected file in auto-created dir: %v", err)
	}
}

func TestWriteIterationRecord_RejectsTraversal(t *testing.T) {
	for _, bad := range []string{"../foo", "x/../../etc", "/x/.."} {
		if err := writeIterationRecord(bad, fullRichRecord("iter-1", 1)); err == nil {
			t.Errorf("expected traversal reject for %q", bad)
		}
	}
}

func TestHighestExistingIterID_AbsentReturnsZero(t *testing.T) {
	dir := t.TempDir()
	n, err := highestExistingIterID(dir)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 0 {
		t.Errorf("want 0, got %d", n)
	}
}

func TestHighestExistingIterID_TracksMax(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"iter-3", "iter-1", "iter-7", "iter-2"} {
		rec := fullRichRecord(id, 0)
		if err := writeIterationRecord(dir, rec); err != nil {
			t.Fatalf("write %s: %v", id, err)
		}
	}
	n, err := highestExistingIterID(dir)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 7 {
		t.Errorf("want 7, got %d", n)
	}
}

func TestWriteIterationLog_Bulk(t *testing.T) {
	dir := t.TempDir()
	log := &IterationLog{Records: []IterationRecord{
		fullRichRecord("iter-1", 1),
		fullRichRecord("iter-2", 2),
	}}
	if err := writeIterationLog(dir, log); err != nil {
		t.Fatalf("bulk write: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "iterations.jsonl"))
	if cnt := strings.Count(string(b), "\n"); cnt != 2 {
		t.Fatalf("want 2 lines, got %d", cnt)
	}
}
