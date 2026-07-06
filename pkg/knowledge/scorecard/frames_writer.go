/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — P58C-02 per-frame NDJSON sidecar writer (P64-05).
//
// frames.ndjson is an append-only NDJSON sidecar emitted to <kbDir>/ alongside
// iterations.jsonl. One JSON object per CDP WebSocket frame captured during a
// runtime deepening pass. Schema:
//
//	{"ts":RFC3339,"target_id":"...","dir":"sent|recv","opcode":1|2|8|9|10,
//	 "masked":bool,"payload_len":int,"payload_hash":"sha256hex",
//	 "payload_truncated":"<first 256B hex>"}
//
// Concurrency (T-64-03): AppendFrame holds a per-kbDir sync.Mutex (sync.Map
// keyed by clean kbDir → *sync.Mutex) so multiple CDP targets writing to the
// same sidecar serialize at the file-write boundary. O_APPEND alone is NOT
// atomic across processes for >PIPE_BUF on Windows; the mutex covers
// in-process correctness which is the only relevant case here (single-process
// scorecard pipeline). W1 race assertion (TestFramesWriterIterationsRace)
// proves no torn lines under concurrent AppendFrame + iterations.jsonl writes.
//
// Line-counter (T-64-04 mitigation): per-kbDir monotonic 0-based line counter
// returned by AppendFrame so iterate.go can stamp Citation.Line against the
// exact JSONL record that produced a runtime score bump.
package scorecard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const framesFile = "frames.ndjson"

// FrameEvent is the schema written one-per-line to <kbDir>/frames.ndjson.
type FrameEvent struct {
	TS               time.Time `json:"ts"`
	TargetID         string    `json:"target_id"`
	Dir              string    `json:"dir"` // "sent"|"recv"
	Opcode           int       `json:"opcode"`
	Masked           bool      `json:"masked"`
	PayloadLen       int       `json:"payload_len"`
	PayloadHash      string    `json:"payload_hash"`      // sha256 hex of full payload
	PayloadTruncated string    `json:"payload_truncated"` // first 256 bytes hex
}

// per-kbDir mutex registry — one *sync.Mutex per cleaned kbDir.
var framesMu sync.Map // map[string]*sync.Mutex

// per-kbDir monotonic line counter — incremented under the same mutex as the
// write so iterate.go can correlate Citation.Line ↔ frames.ndjson record.
var framesLine sync.Map // map[string]*int

func framesMutexFor(kbDir string) *sync.Mutex {
	if m, ok := framesMu.Load(kbDir); ok {
		return m.(*sync.Mutex)
	}
	m, _ := framesMu.LoadOrStore(kbDir, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func framesLineFor(kbDir string) *int {
	if c, ok := framesLine.Load(kbDir); ok {
		return c.(*int)
	}
	v := 0
	c, _ := framesLine.LoadOrStore(kbDir, &v)
	return c.(*int)
}

// NewFrameEvent constructs a FrameEvent from raw payload bytes, computing
// PayloadHash (sha256 hex) and PayloadTruncated (first 256 bytes hex) per
// the T-64-04 mandate that every recorded frame carries provenance.
func NewFrameEvent(targetID, dir string, opcode int, masked bool, payload []byte) FrameEvent {
	sum := sha256.Sum256(payload)
	const truncN = 256
	trunc := payload
	if len(trunc) > truncN {
		trunc = trunc[:truncN]
	}
	return FrameEvent{
		TS:               time.Now().UTC(),
		TargetID:         targetID,
		Dir:              dir,
		Opcode:           opcode,
		Masked:           masked,
		PayloadLen:       len(payload),
		PayloadHash:      hex.EncodeToString(sum[:]),
		PayloadTruncated: hex.EncodeToString(trunc),
	}
}

// AppendFrame writes ev as a single JSON line to <kbDir>/frames.ndjson and
// returns the 0-based line index of the new record (so callers can stamp a
// Citation.Line that points at this exact frame).
//
// kbDir == "" is a no-op returning (0, nil) — in-memory tests can elect not
// to persist frames.
func AppendFrame(kbDir string, ev FrameEvent) (int, error) {
	if kbDir == "" {
		return 0, nil
	}
	clean, err := safeKBDir(kbDir)
	if err != nil {
		return 0, err
	}
	mu := framesMutexFor(clean)
	mu.Lock()
	defer mu.Unlock()

	if mkErr := os.MkdirAll(clean, 0o755); mkErr != nil {
		return 0, fmt.Errorf("mkdir kb dir: %w", mkErr)
	}
	path := filepath.Join(clean, framesFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open frames.ndjson: %w", err)
	}
	defer func() { _ = f.Close() }()

	enc, err := json.Marshal(ev)
	if err != nil {
		return 0, fmt.Errorf("marshal frame: %w", err)
	}
	if _, err := f.Write(append(enc, '\n')); err != nil {
		return 0, fmt.Errorf("write frame: %w", err)
	}
	cnt := framesLineFor(clean)
	line := *cnt
	*cnt++
	return line, nil
}

// FramesLineCount returns the in-process monotonic line count for kbDir
// (0 if no frames written yet). Used by iterate.go to stamp Citation.Line.
// Returns the NEXT line index that AppendFrame would assign.
func FramesLineCount(kbDir string) int {
	clean, err := safeKBDir(kbDir)
	if err != nil {
		return 0
	}
	mu := framesMutexFor(clean)
	mu.Lock()
	defer mu.Unlock()
	cnt := framesLineFor(clean)
	return *cnt
}

// LastFrameForKB returns the (line, hash) of the most recently appended frame
// for kbDir, or ("", 0) if none. Used by iterate.go to stamp the runtime-bump
// Citation with the exact frame that produced the bump (best-effort: in
// production the bump correlates to the LAST frame seen during the dispatch
// window).
func LastFrameForKB(kbDir string) (line int, hash string) {
	clean, err := safeKBDir(kbDir)
	if err != nil {
		return 0, ""
	}
	mu := framesMutexFor(clean)
	mu.Lock()
	defer mu.Unlock()
	cnt := framesLineFor(clean)
	if *cnt == 0 {
		return 0, ""
	}
	last := *cnt - 1
	hash = lastFrameHash(clean)
	return last, hash
}

// lastFrameHash reads the final non-empty line of <kbDir>/frames.ndjson and
// returns its payload_hash. Best-effort; returns "" on any error. Caller must
// already hold the per-kbDir mutex.
func lastFrameHash(cleanKBDir string) string {
	path := filepath.Join(cleanKBDir, framesFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Walk backward to the last newline-bounded line.
	end := len(data)
	for end > 0 && data[end-1] == '\n' {
		end--
	}
	if end == 0 {
		return ""
	}
	start := end
	for start > 0 && data[start-1] != '\n' {
		start--
	}
	var rec struct {
		PayloadHash string `json:"payload_hash"`
	}
	if err := json.Unmarshal(data[start:end], &rec); err != nil {
		return ""
	}
	return rec.PayloadHash
}

// resetFramesStateForTest clears the in-process per-kbDir mutex/counter
// registry. TEST-ONLY — do not call from production code.
func resetFramesStateForTest() {
	framesMu = sync.Map{}
	framesLine = sync.Map{}
}
