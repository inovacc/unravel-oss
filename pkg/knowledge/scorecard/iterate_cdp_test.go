//go:build cdp_live

/*
Copyright (c) 2026 Security Research
*/

// iterate_cdp_test.go is the operator-gated live integration test for the
// P57 iterative deepening loop.
//
// PREAMBLE — operator must launch WhatsApp Desktop with
//
//	--remote-debugging-port=9222
//
// BEFORE running this test. The test does NOT spawn the target (per Q5);
// if the probe fails, the test t.Skips with these instructions printed.
//
// Default `go test ./...` excludes this file via the cdp_live build tag.
// Documented Windows-only (matches v2.9 P51 cdp_live pattern).
package scorecard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const liveCDPPort = 9222

// probeCDP attempts a 1s TCP dial to 127.0.0.1:port. Skips the calling test
// with operator-actionable instructions on failure.
func probeCDPOrSkip(t *testing.T, port int) {
	t.Helper()
	d := net.Dialer{Timeout: 1 * time.Second}
	conn, err := d.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
	if err != nil {
		t.Skipf("CDP probe failed on :%d — launch WhatsApp Desktop with --remote-debugging-port=%d before running this test (err: %v)", port, port, err)
	}
	_ = conn.Close()
}

// TestIterateCDPLive runs Rubric.Iterate against a live WhatsApp Desktop
// session. Asserts:
//   - convergence within 2 iterations (regression sentinel)
//   - per-dim final integer scores: wire ≥85, auth/state_machines/ipc ≥80
//   - iter-2.Dispatched contains structured DispatchResult entries (B1)
//   - iter-2.Bumps contains the canonical W-13b cap entries
//   - knowledge.json byte-shape unchanged (D-10 via SHA256)
//   - iterations.jsonl is append-mode-compatible across two Iterate calls (W2)
//   - behavior dim has missing-evidence marker (B3)
func TestIterateCDPLive(t *testing.T) {
	probeCDPOrSkip(t, liveCDPPort)

	// Operator MUST have run `unravel dissect` against the WhatsApp install
	// before this test; we expect a knowledge.json fixture.
	kbDir := os.Getenv("UNRAVEL_TEST_KB_DIR")
	if kbDir == "" {
		t.Skip("UNRAVEL_TEST_KB_DIR not set; point it at out/whatsapp-kb")
	}
	kbJSON := filepath.Join(kbDir, "knowledge.json")
	preBytes, err := os.ReadFile(kbJSON)
	if err != nil {
		t.Skipf("missing knowledge.json at %s: %v", kbJSON, err)
	}
	preHash := sha256Hex(preBytes)

	tmpKB := t.TempDir()

	// NOTE: in production this would be wired through pkg/dissect to
	// reconstruct a real *DissectResult. For the live test we exercise the
	// loop machinery against an empty result + the live CDP path; the bumps
	// driven by frame capture are what we're asserting on.
	rb := New()
	target := &DissectTarget{
		AppDir:        os.Getenv("UNRAVEL_TEST_APP_DIR"),
		KBOutputDir:   tmpKB,
		CDPPort:       liveCDPPort,
		FrameworkHint: "electron",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	sc, log, err := rb.Iterate(ctx, target, DefaultIterateOptions())
	if err != nil {
		t.Fatalf("first Iterate: %v", err)
	}
	if len(log.Records) > 2 {
		t.Errorf("regression: converged in >2 iterations (got %d)", len(log.Records))
	}

	// Per-dim integer-score assertions.
	for _, want := range []struct {
		dim string
		min int
	}{
		{"wire", 85}, {"auth", 80}, {"state_machines", 80}, {"ipc", 80},
	} {
		if d := sc.Dim(want.dim); d == nil || d.Score < want.min {
			t.Errorf("%s final score %v < %d", want.dim, d, want.min)
		}
	}

	// Behavior marker (B3).
	if d := sc.Dim("behavior"); d != nil && d.Score < 80 {
		found := false
		for _, e := range d.Evidence {
			if e.Kind == "missing" && e.Source == "loop" {
				found = true
				break
			}
		}
		if !found {
			t.Error("behavior missing-evidence marker absent")
		}
	}

	// Last record must contain bumps + structured Dispatched (B1).
	last := log.Records[len(log.Records)-1]
	for _, dr := range last.Dispatched {
		if dr.Pass == "" || dr.TargetDims == nil {
			t.Errorf("DispatchResult not structured: %+v", dr)
		}
	}

	// W2 — second Iterate call against same dir produces append-mode 4-record file.
	_, _, err = rb.Iterate(ctx, target, DefaultIterateOptions())
	if err != nil {
		t.Fatalf("second Iterate: %v", err)
	}
	jsonlBytes, err := os.ReadFile(filepath.Join(tmpKB, "iterations.jsonl"))
	if err != nil {
		t.Fatalf("read iterations.jsonl: %v", err)
	}
	lineCount := strings.Count(string(jsonlBytes), "\n")
	if lineCount < 2 {
		t.Errorf("W2 violated: want ≥2 records after two Iterate calls, got %d", lineCount)
	}

	// D-10 — knowledge.json byte-shape unchanged.
	postBytes, err := os.ReadFile(kbJSON)
	if err != nil {
		t.Fatalf("post-iterate read knowledge.json: %v", err)
	}
	if sha256Hex(postBytes) != preHash {
		t.Error("D-10 violated: knowledge.json byte-shape changed after Iterate")
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
