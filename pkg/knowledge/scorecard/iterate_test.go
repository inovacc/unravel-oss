/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// withSeams substitutes the package-level test seams for one test and returns
// a restore func. Run via defer.
func withSeams(t *testing.T, electronOK, webview2OK bool, dial dialerFn, src frameSource) func() {
	t.Helper()
	origE, origW := detectElectron, detectWebView2
	origDial := defaultDialer
	origFactory := defaultFrameSourceFactory
	detectElectron = func(string) bool { return electronOK }
	detectWebView2 = func(string) bool { return webview2OK }
	if dial != nil {
		defaultDialer = dial
	}
	if src != nil {
		defaultFrameSourceFactory = func(*DissectTarget) frameSource { return src }
	}
	return func() {
		detectElectron = origE
		detectWebView2 = origW
		defaultDialer = origDial
		defaultFrameSourceFactory = origFactory
	}
}

// makeStaticScorecard builds a synthetic scorecard with explicit per-dim
// scores for testing — bypasses real scorers via a test rubric.
type fixedScorer struct {
	id    string
	name  string
	score int
}

func (f fixedScorer) ID() string   { return f.id }
func (f fixedScorer) Name() string { return f.name }
func (f fixedScorer) Score(_ *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	return DimScore{ID: f.id, Name: f.name, Score: f.score}
}

// fixedRubric returns a *Rubric whose ordered slice is the supplied fixed scorers.
func fixedRubric(scoresByDim map[string]int) *Rubric {
	rb := &Rubric{}
	for _, dim := range CanonicalDims {
		rb.ordered = append(rb.ordered, fixedScorer{id: dim, name: dim, score: scoresByDim[dim]})
	}
	return rb
}

// allEighty is a baseline scorecard where every dim already meets threshold —
// useful for converged-on-arrival cases.
func allEighty() map[string]int {
	m := map[string]int{}
	for _, d := range CanonicalDims {
		m[d] = 80
	}
	return m
}

// whatsappShape is the canonical mock: static mean ~72, weak dims wire/auth/
// state_machines/ipc, behavior < threshold, others ≥ threshold.
func whatsappShape() map[string]int {
	m := allEighty()
	m["wire"] = 60
	m["auth"] = 65
	m["state_machines"] = 60
	m["ipc"] = 60
	m["behavior"] = 70 // <80 so the missing-marker must be applied
	return m
}

type capturingFrameSource struct {
	frames int
	err    error
	calls  int
}

func (c *capturingFrameSource) Capture(ctx context.Context, port int, dur time.Duration) (int, error) {
	c.calls++
	return c.frames, c.err
}

// (a) static-only target — framework gate miss
func TestRubricIterate_StaticOnlyFrameworkMiss(t *testing.T) {
	dir := t.TempDir()
	src := &capturingFrameSource{frames: 99}
	dialCalls := 0
	dial := func(ctx context.Context, port int) error { dialCalls++; return nil }
	defer withSeams(t, false, false, dial, src)()

	rb := fixedRubric(whatsappShape())
	sc, log, err := rb.Iterate(context.Background(), &DissectTarget{KBOutputDir: dir, AppDir: "/tmp/none"}, DefaultIterateOptions())
	if err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if dialCalls != 0 {
		t.Errorf("W1 violated: port dial occurred (%d calls)", dialCalls)
	}
	if src.calls != 0 {
		t.Errorf("frameSource invoked on static-only path: %d calls", src.calls)
	}
	if len(log.Records) != 1 {
		t.Fatalf("want 1 record, got %d", len(log.Records))
	}
	rec := log.Records[0]
	if !rec.RuntimeCaptureUnavailable {
		t.Error("RuntimeCaptureUnavailable=true expected")
	}
	// B3 — behavior missing marker present
	bd := sc.Dim("behavior")
	if bd == nil || !hasBehaviorMissing(bd.Evidence) {
		t.Errorf("behavior missing marker absent: %+v", bd)
	}
}

// (b) WhatsApp-shape: 1 dispatch iter lifts all 4 weak dims to caps
func TestRubricIterate_WhatsAppConvergesIn2(t *testing.T) {
	dir := t.TempDir()
	src := &capturingFrameSource{frames: 50}
	defer withSeams(t, true, false, func(ctx context.Context, port int) error { return nil }, src)()

	// Force behavior to 80 so it doesn't block convergence (still < threshold check uses RequireAll12).
	scores := whatsappShape()
	scores["behavior"] = 80
	rb := fixedRubric(scores)
	opts := DefaultIterateOptions()
	sc, log, err := rb.Iterate(context.Background(), &DissectTarget{KBOutputDir: dir, AppDir: "/tmp/electron-app", CDPPort: 9222}, opts)
	if err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if len(log.Records) < 1 {
		t.Fatalf("want ≥1 record, got %d", len(log.Records))
	}
	// After bumps applied, all 4 weak dims should be at their caps.
	if d := sc.Dim("wire"); d == nil || d.Score < 85 {
		t.Errorf("wire not bumped to 85: %+v", d)
	}
	for _, dim := range []string{"auth", "state_machines", "ipc"} {
		if d := sc.Dim(dim); d == nil || d.Score < 80 {
			t.Errorf("%s not bumped to 80: %+v", dim, d)
		}
	}
	last := log.Records[len(log.Records)-1]
	if last.Bumps["wire"] != 85 {
		t.Errorf("Bumps[wire]=%d want 85", last.Bumps["wire"])
	}
	if last.PostMean < opts.Threshold {
		t.Errorf("PostMean=%d below threshold", last.PostMean)
	}
	// Confirm iterations.jsonl exists.
	if _, err := readJSONLLines(filepath.Join(dir, "iterations.jsonl")); err != nil {
		t.Errorf("iterations.jsonl missing: %v", err)
	}
}

// (b') behavior < threshold on CDP path → marker present
func TestRubricIterate_WhatsAppBehaviorMarkerOnCDPPath(t *testing.T) {
	dir := t.TempDir()
	src := &capturingFrameSource{frames: 50}
	defer withSeams(t, true, false, func(ctx context.Context, port int) error { return nil }, src)()

	rb := fixedRubric(whatsappShape()) // behavior=70
	sc, _, err := rb.Iterate(context.Background(), &DissectTarget{KBOutputDir: dir, AppDir: "/x", CDPPort: 9222}, DefaultIterateOptions())
	if err != nil {
		t.Fatalf("iterate: %v", err)
	}
	bd := sc.Dim("behavior")
	if bd == nil || !hasBehaviorMissing(bd.Evidence) {
		t.Errorf("B3 violated on CDP-attached path: %+v", bd)
	}
}

// (c) MaxIter exhausted without convergence (zero frames every pass → no bumps)
func TestRubricIterate_MaxIterExhausted(t *testing.T) {
	dir := t.TempDir()
	src := &capturingFrameSource{frames: 0}
	defer withSeams(t, true, false, func(ctx context.Context, port int) error { return nil }, src)()

	rb := fixedRubric(whatsappShape())
	sc, log, err := rb.Iterate(context.Background(), &DissectTarget{KBOutputDir: dir, AppDir: "/x", CDPPort: 9222}, DefaultIterateOptions())
	if err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if len(log.Records) != 5 {
		t.Errorf("want 5 records on MaxIter exhaustion, got %d", len(log.Records))
	}
	if d := sc.Dim("behavior"); d == nil || !hasBehaviorMissing(d.Evidence) {
		t.Error("behavior marker missing in final scorecard")
	}
}

// (d) ctx cancel mid-loop
func TestRubricIterate_CtxCancel(t *testing.T) {
	dir := t.TempDir()
	src := &capturingFrameSource{frames: 0}
	defer withSeams(t, true, false, func(ctx context.Context, port int) error { return nil }, src)()

	rb := fixedRubric(whatsappShape())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := rb.Iterate(ctx, &DissectTarget{KBOutputDir: dir, AppDir: "/x", CDPPort: 9222}, DefaultIterateOptions())
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected wrapped ctx.Canceled, got %v", err)
	}
}

// (e) per-iter timeout suppression — synthetic timeout DispatchResult recorded; loop continues
func TestRubricIterate_PerIterTimeoutSuppressed(t *testing.T) {
	dir := t.TempDir()
	src := timeoutSource{}
	defer withSeams(t, true, false, func(ctx context.Context, port int) error { return nil }, src)()

	rb := fixedRubric(whatsappShape())
	opts := DefaultIterateOptions()
	opts.PerIterTimeout = 50 * time.Millisecond
	opts.MaxIter = 2
	_, log, err := rb.Iterate(context.Background(), &DissectTarget{KBOutputDir: dir, AppDir: "/x", CDPPort: 9222}, opts)
	if err != nil {
		t.Fatalf("expected nil err on timeout suppression, got %v", err)
	}
	foundTimeout := false
	for _, rec := range log.Records {
		for _, dr := range rec.Dispatched {
			if dr.Pass == "timeout" && dr.Note == "per-iter timeout" {
				foundTimeout = true
			}
		}
	}
	if !foundTimeout {
		t.Errorf("expected synthetic timeout DispatchResult; records=%+v", log.Records)
	}
}

// (f) framework miss → no port dial (already covered in test (a) via dialCalls assertion)

// timeoutSource always returns context.DeadlineExceeded after a brief sleep —
// simulates a CDP capture exceeding PerIterTimeout.
type timeoutSource struct{}

func (timeoutSource) Capture(ctx context.Context, port int, dur time.Duration) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(200 * time.Millisecond):
		return 0, context.DeadlineExceeded
	}
}

// helpers

func readJSONLLines(path string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := [][]byte{}
	for _, line := range bytesSplit(b, '\n') {
		if len(line) == 0 {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func bytesSplit(b []byte, sep byte) [][]byte {
	out := [][]byte{}
	start := 0
	for i, c := range b {
		if c == sep {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func hasBehaviorMissing(evs []Evidence) bool {
	for _, e := range evs {
		if e.Kind == behaviorMissingKind && e.Source == behaviorMissingSource && e.Detail == behaviorMissingDetail {
			return true
		}
	}
	return false
}
