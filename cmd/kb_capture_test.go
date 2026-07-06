/*
Copyright (c) 2026 Security Research

Unit tests for cmd/kb_capture.go: summary formatting (plain + JSON +
skipped), --help text guarantees, and a source-level guard that the
file does NOT import os/exec (INGE-01 in-process requirement,
T-30-04-07 mitigation).
*/

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/ingest"
)

func TestPrintSummary_Plain(t *testing.T) {
	risk := 73
	res := &ingest.Result{
		KBID:         "abcd1234abcd1234",
		KSID:         "abcd1234abcd1234:1.0.0:1700000000",
		Epoch:        int64(2),
		RiskScore:    &risk,
		RiskLevel:    "high",
		DepthScore:   3,
		DiffsWritten: 4,
	}
	var buf bytes.Buffer
	if err := printSummary(&buf, res, false); err != nil {
		t.Fatalf("printSummary: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"kb_id=abcd1234abcd1234", "epoch=2", "risk_score=73", "risk_level=high", "diffs=4"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q: got %q", want, got)
		}
	}
}

func TestPrintSummary_JSON(t *testing.T) {
	res := &ingest.Result{
		KBID:      "abcd1234abcd1234",
		KSID:      "abcd1234abcd1234:1.0.0:1700000000",
		Epoch:     int64(2),
		RiskLevel: "low",
	}
	var buf bytes.Buffer
	if err := printSummary(&buf, res, true); err != nil {
		t.Fatalf("printSummary: %v", err)
	}
	var got ingest.Result
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, buf.String())
	}
	if got.Epoch != int64(2) {
		t.Errorf("epoch round-trip: want int64(2), got %v", got.Epoch)
	}
	if got.KBID != res.KBID {
		t.Errorf("kb_id round-trip: want %q got %q", res.KBID, got.KBID)
	}
}

func TestPrintSummary_Skipped(t *testing.T) {
	res := &ingest.Result{
		KBID:          "abcd1234abcd1234",
		Skipped:       true,
		SkippedReason: "already ingested at epoch 3",
	}
	var buf bytes.Buffer
	if err := printSummary(&buf, res, false); err != nil {
		t.Fatalf("printSummary: %v", err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, "skipped") {
		t.Errorf("want skipped prefix, got %q", got)
	}
	if !strings.Contains(got, "already ingested at epoch 3") {
		t.Errorf("want skipped reason in output, got %q", got)
	}
}

func TestCaptureCmd_HelpMentionsPhaseBoundaries(t *testing.T) {
	long := kbCaptureCmd.Long
	for _, want := range []string{"Phase 32", "Phase 34", "force", "orphan"} {
		if !strings.Contains(long, want) {
			t.Errorf("kbCaptureCmd.Long missing %q", want)
		}
	}
}

func TestCaptureCmd_AllFlagsRegistered(t *testing.T) {
	for _, name := range []string{"tag", "reason", "by", "json", "verbose"} {
		if kbCaptureCmd.Flag(name) == nil {
			t.Errorf("flag %q not registered on kbCaptureCmd", name)
		}
	}
}

// TestStageAnalysis_NoExecImport asserts at the source level that
// cmd/kb_capture.go does NOT import "os/exec" and does NOT spawn the
// `unravel knowledge` subprocess. INGE-01 in-process requirement +
// T-30-04-07 mitigation.
func TestStageAnalysis_NoExecImport(t *testing.T) {
	src, err := os.ReadFile("kb_capture.go")
	if err != nil {
		t.Fatalf("read kb_capture.go: %v", err)
	}
	body := string(src)
	if strings.Contains(body, `"os/exec"`) {
		t.Errorf(`cmd/kb_capture.go must NOT import "os/exec" (INGE-01 in-process requirement)`)
	}
	for _, banned := range []string{"exec.Command(", "exec.CommandContext("} {
		if strings.Contains(body, banned) {
			t.Errorf("cmd/kb_capture.go must not call %s (INGE-01 in-process requirement)", banned)
		}
	}
	// Defense in depth — the wrong analyzer entry name MUST NOT appear.
	if strings.Contains(body, "knowledge.RunAnalysis(") {
		t.Errorf("cmd/kb_capture.go references knowledge.RunAnalysis (does not exist); use knowledge.Run")
	}
	// Positive control — confirm we DO call the in-process entry.
	if !strings.Contains(body, "knowledge.Run(") {
		t.Errorf("cmd/kb_capture.go must call knowledge.Run (the pinned in-process entry)")
	}
}
