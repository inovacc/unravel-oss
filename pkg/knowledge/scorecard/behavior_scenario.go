/*
Copyright (c) 2026 Security Research
*/

// Plan 69-02 (SCRG-05D) — scenario-replay seam.
//
// Reads <scorecardBaseDir>/<MSIXInfo.PackageName>/frames.ndjson (the literal
// filename emitted by frames_writer.go:39) and classifies each FrameEvent by
// payload_truncated hex shape into one of five scenario buckets. Each bucket
// contributes its Weight at most once; the sum is capped at 30 and added
// additively past the legacy 70 UWP cap in scorer_behavior.go.
//
// D-69-06 invariant: this file MUST NOT change the FrameEvent schema or
// frames_writer.go. Classification works purely from the existing fields
// (Opcode, Dir, PayloadLen, PayloadTruncated hex).
//
// Missing file is NOT an error — returns 0 and contributes nothing, which
// keeps the legacy TestBehaviorScorer table byte-identical (no fixture there
// ever materialises a frames.ndjson sidecar).
package scorecard

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// scorecardBaseDir is the parent of per-kb output directories. Each kb run
// emits <scorecardBaseDir>/<PackageName>-kb/frames.ndjson (written by
// frames_writer.go); the scorer reads from the same canonical location so the
// runbook does not need to copy frames around. Tests override via the
// package-private hook.
var scorecardBaseDir = "out"

// Scenario classifies a single FrameEvent by payload_truncated hex shape.
type Scenario struct {
	Name   string
	Match  func(FrameEvent) bool
	Weight int
}

// Hex-encoded CDP method markers — payload_truncated is hex of the first 256
// payload bytes, so we substring-match the hex of the method name.
const (
	hexTargetAttached = "5461726765742e6174746163686564546f546172676574"     // "Target.attachedToTarget"
	hexPageNavigated  = "506167652e6672616d654e6176696761746564"             // "Page.frameNavigated"
	hexNetworkRequest = "4e6574776f726b2e7265717565737457696c6c426553656e74" // "Network.requestWillBeSent"
)

func matchTargetAttached(ev FrameEvent) bool {
	return strings.Contains(ev.PayloadTruncated, hexTargetAttached)
}

func matchPageNavigated(ev FrameEvent) bool {
	return strings.Contains(ev.PayloadTruncated, hexPageNavigated)
}

func matchNetworkRequest(ev FrameEvent) bool {
	return strings.Contains(ev.PayloadTruncated, hexNetworkRequest)
}

func matchWebSocketText(ev FrameEvent) bool {
	return ev.Opcode == 1 && ev.Dir == "sent" && ev.PayloadLen > 0
}

func matchSessionClose(ev FrameEvent) bool {
	return ev.Opcode == 8
}

// defaultScenarios — 5 classes × 6 pts = 30 max contribution.
var defaultScenarios = []Scenario{
	{Name: "target_attached", Match: matchTargetAttached, Weight: 6},
	{Name: "page_navigated", Match: matchPageNavigated, Weight: 6},
	{Name: "network_request", Match: matchNetworkRequest, Weight: 6},
	{Name: "websocket_text", Match: matchWebSocketText, Weight: 6},
	{Name: "session_close", Match: matchSessionClose, Weight: 6},
}

const scenarioCap = 30

// packageFamilyKey normalizes a packaged-app identifier down to the package
// FAMILY key the kb writer used for the -kb directory (72-EVIDENCE.md H4
// PRIMARY ROOT CAUSE). A full MSIX package identity is
// "Name_Version_Architecture__PublisherId" (the version+arch middle segments
// are split by single "_" and the publisher is preceded by "__"). The
// canonical Package Family Name — which frames_writer.go's caller keys the
// -kb dir off — is "Name_PublisherId". This drops the version+arch middle
// segments while preserving the Name and the "__PublisherId" suffix.
//
// Idempotent: an input that is already a family key (no "__PublisherId"
// segment) or a bare Name (no "_") is returned unchanged, so callers that
// already pass the writer's key are unaffected and the additive-only
// silent-zero invariant (D-69-06) is preserved.
func packageFamilyKey(id string) string {
	const pubSep = "__"
	pubIdx := strings.LastIndex(id, pubSep)
	if pubIdx < 0 {
		// No publisher segment: already a family key or a bare Name.
		return id
	}
	publisher := id[pubIdx+len(pubSep):]
	name, _, ok := strings.Cut(id[:pubIdx], "_")
	if !ok || name == "" || publisher == "" {
		// Not a recognizable full identity — leave it untouched.
		return id
	}
	return name + "_" + publisher
}

// scoreBehaviorScenarios resolves frames.ndjson under
// <scorecardBaseDir>/<packageFamily>-kb/ (the canonical kb output dir written
// by frames_writer.go, keyed off the package FAMILY). The incoming
// packageName may be the full MSIX identity (MSIXInfo.PackageName) — it is
// normalized to the family key so the reader resolves the same directory the
// writer used (72-EVIDENCE.md H4 fix). Empty packageName, missing file, and
// malformed lines all map to silent no-error zero/partial contributions per
// the additive-only invariant (D-69-06).
func scoreBehaviorScenarios(packageName string) int {
	if packageName == "" {
		return 0
	}
	family := packageFamilyKey(packageName)
	path := filepath.Join(scorecardBaseDir, family+"-kb", "frames.ndjson")
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	return scoreScenariosFromReader(f, defaultScenarios)
}

// scoreScenariosFromReader is the package-private constructor used by tests
// to drive scenarios from an in-memory NDJSON stream. The public API surface
// remains scoreBehaviorScenarios(packageName string) int.
func scoreScenariosFromReader(r io.Reader, scenarios []Scenario) int {
	hits := make([]bool, len(scenarios))
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev FrameEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		for i, s := range scenarios {
			if hits[i] {
				continue
			}
			if s.Match(ev) {
				hits[i] = true
			}
		}
	}
	total := 0
	for i, s := range scenarios {
		if hits[i] {
			total += s.Weight
		}
	}
	if total > scenarioCap {
		total = scenarioCap
	}
	return total
}
