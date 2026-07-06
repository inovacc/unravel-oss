/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — P57 iteration JSONL writer.
//
// iterations.jsonl is APPEND-ONLY across multiple Iterate invocations against
// the same KBOutputDir (W2). Records from successive runs concatenate; consumers
// must use record.ID + record.TS to disambiguate runs.
//
// Path safety (T-57-01): kbOutputDir is filepath.Clean'd and rejected if it
// contains ".." after cleaning. The directory is mkdir-p'd before open.
package scorecard

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const iterationsFile = "iterations.jsonl"

// writeIterationRecord appends one JSON-encoded line (with trailing \n) to
// <kbOutputDir>/iterations.jsonl. Open mode O_CREATE|O_APPEND|O_WRONLY 0644.
// Caller is Rubric.Iterate, invoked once per iteration for crash-safety.
//
// kbOutputDir == "" is a no-op (in-memory tests can elect not to write).
func writeIterationRecord(kbOutputDir string, rec IterationRecord) error {
	if kbOutputDir == "" {
		return nil
	}
	clean, err := safeKBDir(kbOutputDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(clean, 0o755); err != nil {
		return fmt.Errorf("mkdir kb dir: %w", err)
	}
	path := filepath.Join(clean, iterationsFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open iterations.jsonl: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("close iterations.jsonl", "err", cerr)
		}
	}()
	enc, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	if _, err := f.Write(append(enc, '\n')); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	return nil
}

// writeIterationLog is a bulk helper used by tests; production path uses
// writeIterationRecord per iteration for crash safety.
func writeIterationLog(kbOutputDir string, log *IterationLog) error {
	if log == nil {
		return nil
	}
	for _, rec := range log.Records {
		if err := writeIterationRecord(kbOutputDir, rec); err != nil {
			return err
		}
	}
	return nil
}

// highestExistingIterID scans <kbOutputDir>/iterations.jsonl (if present) and
// returns the highest "iter-N" id found. Returns 0 if file is absent or empty
// or if no parseable id is found.
func highestExistingIterID(kbOutputDir string) (int, error) {
	if kbOutputDir == "" {
		return 0, nil
	}
	clean, err := safeKBDir(kbOutputDir)
	if err != nil {
		return 0, err
	}
	path := filepath.Join(clean, iterationsFile)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("open iterations.jsonl: %w", err)
	}
	defer func() { _ = f.Close() }()

	max := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if !strings.HasPrefix(rec.ID, "iter-") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(rec.ID, "iter-"))
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	if err := sc.Err(); err != nil {
		return max, fmt.Errorf("scan iterations.jsonl: %w", err)
	}
	return max, nil
}

// safeKBDir cleans the path and rejects traversal sequences. Returns the
// cleaned absolute-or-relative path on success.
func safeKBDir(kbOutputDir string) (string, error) {
	if kbOutputDir == "" {
		return "", fmt.Errorf("kbOutputDir empty")
	}
	// Reject ".." in the RAW input BEFORE Clean. filepath.Clean resolves a
	// segment like "/x/.." down to the filesystem root ("/" or "\\"), erasing
	// the ".." that the post-Clean scan would otherwise catch — a path-
	// traversal guard bypass. Split on both separators so it holds on every OS.
	for _, part := range strings.FieldsFunc(kbOutputDir, func(r rune) bool {
		return r == '/' || r == filepath.Separator
	}) {
		if part == ".." {
			return "", fmt.Errorf("kbOutputDir contains traversal: %q", kbOutputDir)
		}
	}
	clean := filepath.Clean(kbOutputDir)
	// Defense in depth: reject any ".." that survives Clean (e.g. a leading
	// "../foo" in a relative path).
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("kbOutputDir contains traversal: %q", kbOutputDir)
		}
	}
	return clean, nil
}
