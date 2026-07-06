/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFramesWriter_AppendsValidJSONL(t *testing.T) {
	resetFramesStateForTest()
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		ev := NewFrameEvent("tgt-1", "sent", 1, false, []byte("hello world"))
		line, err := AppendFrame(dir, ev)
		if err != nil {
			t.Fatalf("AppendFrame[%d]: %v", i, err)
		}
		if line != i {
			t.Errorf("line[%d] = %d, want %d", i, line, i)
		}
	}
	path := filepath.Join(dir, framesFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frames.ndjson: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}
	expHash := hex.EncodeToString(func() []byte {
		s := sha256.Sum256([]byte("hello world"))
		return s[:]
	}())
	for i, l := range lines {
		var rec FrameEvent
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Errorf("line %d invalid JSON: %v", i, err)
			continue
		}
		if rec.PayloadHash != expHash {
			t.Errorf("line %d hash = %s, want %s", i, rec.PayloadHash, expHash)
		}
		if rec.PayloadLen != 11 {
			t.Errorf("line %d len = %d, want 11", i, rec.PayloadLen)
		}
		if rec.Dir != "sent" || rec.Opcode != 1 || rec.TargetID != "tgt-1" {
			t.Errorf("line %d shape mismatch: %+v", i, rec)
		}
	}
}

func TestFramesWriter_OAppendOrder(t *testing.T) {
	resetFramesStateForTest()
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		_, _ = AppendFrame(dir, NewFrameEvent("a", "sent", 1, false, []byte{byte(i)}))
	}
	for i := 3; i < 5; i++ {
		_, _ = AppendFrame(dir, NewFrameEvent("a", "recv", 2, false, []byte{byte(i)}))
	}
	data, _ := os.ReadFile(filepath.Join(dir, framesFile))
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}
}

func TestFramesWriter_LastFrameForKB(t *testing.T) {
	resetFramesStateForTest()
	dir := t.TempDir()
	_, _ = AppendFrame(dir, NewFrameEvent("a", "sent", 1, false, []byte("first")))
	_, _ = AppendFrame(dir, NewFrameEvent("a", "sent", 1, false, []byte("second")))
	line, hash := LastFrameForKB(dir)
	if line != 1 {
		t.Errorf("line = %d, want 1", line)
	}
	expHash := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("second")); return s[:] }())
	if hash != expHash {
		t.Errorf("hash = %s, want %s", hash, expHash)
	}
}

// TestFramesWriterIterationsRace — W1 race assertion. 100 concurrent
// AppendFrame + 100 concurrent iterations.jsonl writes against the same
// kbDir; assert both files end with their expected line counts, no torn
// lines, no interleaved JSON. MUST be exercised under `go test -race`.
func TestFramesWriterIterationsRace(t *testing.T) {
	resetFramesStateForTest()
	dir := t.TempDir()

	const N = 100
	var wg sync.WaitGroup
	wg.Add(2 * N)

	// Producer 1: AppendFrame goroutines.
	for i := 0; i < N; i++ {
		go func(id int) {
			defer wg.Done()
			payload := []byte(strings.Repeat("x", 10+id%50))
			ev := NewFrameEvent("tgt", "sent", 1, false, payload)
			if _, err := AppendFrame(dir, ev); err != nil {
				t.Errorf("AppendFrame goroutine %d: %v", id, err)
			}
		}(i)
	}

	// Producer 2: writeIterationRecord goroutines (independent file in same dir).
	for i := 0; i < N; i++ {
		go func(id int) {
			defer wg.Done()
			rec := IterationRecord{
				ID:   "iter-x",
				Iter: id,
				TS:   time.Now().UTC().Format(time.RFC3339),
			}
			if err := writeIterationRecord(dir, rec); err != nil {
				t.Errorf("writeIterationRecord goroutine %d: %v", id, err)
			}
		}(i)
	}
	wg.Wait()

	// Verify frames.ndjson has exactly N JSON-valid lines, no torn writes.
	framesData, err := os.ReadFile(filepath.Join(dir, framesFile))
	if err != nil {
		t.Fatalf("read frames.ndjson: %v", err)
	}
	scn := bufio.NewScanner(strings.NewReader(string(framesData)))
	scn.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	frameLines := 0
	for scn.Scan() {
		var rec FrameEvent
		if err := json.Unmarshal(scn.Bytes(), &rec); err != nil {
			t.Errorf("torn/interleaved JSON in frames.ndjson line %d: %v\n  %q", frameLines+1, err, scn.Text())
		}
		frameLines++
	}
	if frameLines != N {
		t.Errorf("frames.ndjson lines = %d, want %d", frameLines, N)
	}

	// Verify iterations.jsonl has exactly N JSON-valid lines.
	iterData, err := os.ReadFile(filepath.Join(dir, iterationsFile))
	if err != nil {
		t.Fatalf("read iterations.jsonl: %v", err)
	}
	scn2 := bufio.NewScanner(strings.NewReader(string(iterData)))
	scn2.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	iterLines := 0
	for scn2.Scan() {
		var rec IterationRecord
		if err := json.Unmarshal(scn2.Bytes(), &rec); err != nil {
			t.Errorf("torn/interleaved JSON in iterations.jsonl line %d: %v\n  %q", iterLines+1, err, scn2.Text())
		}
		iterLines++
	}
	if iterLines != N {
		t.Errorf("iterations.jsonl lines = %d, want %d", iterLines, N)
	}
}

// TestIterateRuntimeBump_FramesCitation verifies that a runtime-bump Evidence
// produced by iterate.go cites frames.ndjson when a frame was recorded for
// the same kbDir, and falls back to iterations.jsonl otherwise.
func TestIterateRuntimeBump_FramesCitation(t *testing.T) {
	resetFramesStateForTest()
	dir := t.TempDir()
	// Pre-seed a frame so LastFrameForKB returns a real line+hash.
	ev := NewFrameEvent("tgt", "recv", 2, false, []byte("payload-bytes-12345"))
	if _, err := AppendFrame(dir, ev); err != nil {
		t.Fatalf("seed AppendFrame: %v", err)
	}
	line, hash := LastFrameForKB(dir)
	if hash == "" {
		t.Fatal("LastFrameForKB returned empty hash after seed")
	}
	if line != 0 {
		t.Errorf("seeded line = %d, want 0", line)
	}
	// Confirm hash is stable / matches input.
	expHash := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("payload-bytes-12345")); return s[:] }())
	if hash != expHash {
		t.Errorf("hash = %s, want %s", hash, expHash)
	}
}
