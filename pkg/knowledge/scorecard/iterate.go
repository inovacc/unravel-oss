/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — P57 iterative deepening loop.
//
// Rubric.Iterate wraps the P56 static rubric in a goal-seeking loop:
//
//  1. Static score via r.Score(target.Result, target.AnalysisSet).
//  2. Framework gate (W1): electron.Detect || webview2.Detect on target.AppDir
//     runs BEFORE any CDP port dial. Static-only targets short-circuit without
//     network I/O. The 1s probe timeout is independent of PerIterTimeout.
//  3. Behavior missing-evidence marker (B3): appended on every iteration on
//     BOTH the static-only and CDP-attached paths whenever behavior < threshold.
//  4. Weak-dim dispatch via dispatch.go (frameSeconds=180), with PerIterTimeout
//     enforced via context.WithTimeout (W3 — DeadlineExceeded is suppressed and
//     recorded as a synthetic timeout DispatchResult; loop continues).
//  5. Post-hoc capped INTEGER bumps (B2 / W-13b): wire=85, others=80. Recompute
//     PostMean (truncated int) + PostCoverage. Append rich IterationRecord.
//
// EXIT: mean ≥ Threshold AND (RequireAll12 ⇒ all 12 dims ≥ Threshold), OR
// MaxIter reached, OR ctx.Done. Static-only targets exit after iter-1 with
// runtime_capture_unavailable=true.
//
// Wall-clock bound: MaxIter (5) × PerIterTimeout (4min) = 20min worst case.
//
// INTEGER-ONLY (B2): no floating-point types in this file.
//
// JSONL id continuity: writeIterationRecord (iterate_log.go) opens in append
// mode; on the first iter of each Iterate call, we scan the existing file (if
// present) and continue numbering from the highest "iter-N" id found, so two
// successive Iterate calls against the same KBOutputDir produce iter-1..iter-N
// followed by iter-(N+1)..iter-(N+M).
package scorecard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/inject/electron"
	"github.com/inovacc/unravel-oss/pkg/inject/webview2"
)

// Test seams (W1) — package-level vars so tests can substitute deterministic
// implementations without an interface refactor.
var (
	detectElectron = electron.Detect
	detectWebView2 = webview2.Detect
)

// dialerFn is the test seam for the CDP port probe. Returns nil on success.
type dialerFn func(ctx context.Context, port int) error

// defaultDialer dials 127.0.0.1:<port> with a fixed 1s timeout (independent of
// PerIterTimeout per W3 doc).
var defaultDialer dialerFn = func(ctx context.Context, port int) error {
	if port == 0 {
		return fmt.Errorf("cdp port not configured")
	}
	d := net.Dialer{Timeout: 1 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// frameSourceFactory is the test seam for the runtime frameSource used by
// dispatch. Tests substitute a deterministic mock.
type frameSourceFactory func(target *DissectTarget) frameSource

// defaultFrameSourceFactory returns a placeholder source that fails gracefully
// — production wiring lives in P59 (CLI surface). For P57 default we return
// a "no frames" source that records the lack of a live runtime path; the
// cdp_live test (57-06) injects a real CDP-backed source via this seam.
var defaultFrameSourceFactory frameSourceFactory = func(target *DissectTarget) frameSource {
	return noopFrameSource{}
}

type noopFrameSource struct{}

func (noopFrameSource) Capture(ctx context.Context, port int, dur time.Duration) (int, error) {
	return 0, nil
}

const (
	behaviorMissingDetail = "no deepening pass available for behavior in P57"
	behaviorMissingKind   = "missing"
	behaviorMissingSource = "loop"
)

// Dim returns a pointer to the DimScore with the given id within the
// Scorecard's Dimensions slice (auto-fix #3 — slice, not map). nil if absent.
func (s *Scorecard) Dim(id string) *DimScore {
	for i := range s.Dimensions {
		if s.Dimensions[i].ID == id {
			return &s.Dimensions[i]
		}
	}
	return nil
}

// Iterate runs the goal-seeking deepening loop. See package doc for semantics.
func (rb *Rubric) Iterate(ctx context.Context, target *DissectTarget, opts IterateOptions) (*Scorecard, *IterationLog, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if target == nil {
		return nil, nil, fmt.Errorf("iterate: nil target")
	}
	if opts.MaxIter <= 0 || opts.Threshold <= 0 || opts.PerIterTimeout <= 0 {
		opts = DefaultIterateOptions()
	}
	log := slog.With("phase", "p57-iterate")

	sc := rb.Score(target.Result, target.AnalysisSet)
	scorecard := &sc

	// Framework gate (W1): runs once at the top — runtime availability is a
	// per-target property, not per-iteration.
	runtimeUnavailable := false
	if !detectElectron(target.AppDir) && !detectWebView2(target.AppDir) {
		runtimeUnavailable = true
		log.Info("framework gate miss; runtime capture unavailable", "app_dir", target.AppDir)
	} else {
		probeCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		err := defaultDialer(probeCtx, target.CDPPort)
		cancel()
		if err != nil {
			runtimeUnavailable = true
			log.Info("CDP probe failed; runtime capture unavailable", "port", target.CDPPort, "err", err)
		}
	}

	// P84 Task 3 — when runtime capture is available, additively pull live
	// JS/CSS source over the SAME CDP endpoint and apply it onto
	// target.Result, then re-score so the byte-unchanged source_layer / crypto
	// scorers light up off the enriched result. Frame capture (dispatch ->
	// src.Capture) is untouched; the VOPR/frames.ndjson contract is unchanged.
	// Non-fatal: any pull error is recorded on result.Errors (or logged) and
	// the loop proceeds with the static score.
	if !runtimeUnavailable && target.Result != nil && target.CDPPort != 0 {
		pullCtx, pcancel := context.WithTimeout(ctx, 30*time.Second)
		ps, perr := PullSourcesOverCDP(pullCtx, "127.0.0.1", target.CDPPort, 30*time.Second)
		pcancel()
		if perr != nil {
			note := fmt.Sprintf("cdp source pull (live pass): %v", perr)
			target.Result.Errors = append(target.Result.Errors, note)
			log.Warn("cdp source pull failed; continuing with static score", "port", target.CDPPort, "err", perr)
		} else if ps != nil {
			applyPulledToResult(target.Result, ps)
			// Re-score off the enriched result so source_layer/crypto reflect
			// the live-pulled JS/CSS. Honest-empty pulls leave JSAnalysis /
			// RecoveredCSS nil, so this is a no-op vs. the static score.
			sc = rb.Score(target.Result, target.AnalysisSet)
			scorecard = &sc
		}
	}

	logOut := &IterationLog{Records: make([]IterationRecord, 0, opts.MaxIter)}

	// Determine starting id offset for JSONL continuity (W2 across runs).
	idOffset, err := highestExistingIterID(target.KBOutputDir)
	if err != nil {
		log.Warn("could not read existing iterations.jsonl; starting at iter-1", "err", err)
	}

	src := defaultFrameSourceFactory(target)

	for iter := 1; iter <= opts.MaxIter; iter++ {
		if err := ctx.Err(); err != nil {
			return scorecard, logOut, fmt.Errorf("iterate ctx: %w", err)
		}

		preMean, preCov := summary(scorecard)
		weakDims := weakDimsOf(scorecard, opts.Threshold)

		rec := IterationRecord{
			ID:                        fmt.Sprintf("iter-%d", idOffset+iter),
			Iter:                      iter,
			TS:                        time.Now().UTC().Format(time.RFC3339),
			WeakDims:                  weakDims,
			Dispatched:                []DispatchResult{},
			Bumps:                     map[string]int{},
			Mean:                      preMean,
			Coverage:                  preCov,
			PostMean:                  preMean,
			PostCoverage:              preCov,
			RuntimeCaptureUnavailable: runtimeUnavailable,
			CitationsOK:               false,
		}

		// B3 — behavior missing-evidence marker (always, both paths).
		applyBehaviorMissingMarker(scorecard, opts.Threshold)

		// Static-only short-circuit. P58: compute citations_ok before exit so
		// the IterationRecord reflects gate state even on the W1 short-circuit
		// path. Note: static-only exit is INDEPENDENT of CitationsOK (W1
		// contract — runtime_capture_unavailable=true exits regardless).
		if runtimeUnavailable {
			rec.CitationsOK = ComputeCitationsOK(scorecard)
			if err := writeIterationRecord(target.KBOutputDir, rec); err != nil {
				return scorecard, logOut, fmt.Errorf("write iter record: %w", err)
			}
			logOut.Records = append(logOut.Records, rec)
			return scorecard, logOut, nil
		}

		// Exit if already converged. P58: convergedAt now requires citations_ok.
		if convergedAt(scorecard, opts) {
			rec.CitationsOK = scorecard.CitationsOK // set as side effect of convergedAt
			if err := writeIterationRecord(target.KBOutputDir, rec); err != nil {
				return scorecard, logOut, fmt.Errorf("write iter record: %w", err)
			}
			logOut.Records = append(logOut.Records, rec)
			return scorecard, logOut, nil
		}

		// Dispatch only the dims that have a deepening pass in P57.
		dispatchDims := filterDispatchable(weakDims)
		if len(dispatchDims) == 0 {
			// nothing actionable; record and exit
			rec.CitationsOK = ComputeCitationsOK(scorecard)
			if err := writeIterationRecord(target.KBOutputDir, rec); err != nil {
				return scorecard, logOut, fmt.Errorf("write iter record: %w", err)
			}
			logOut.Records = append(logOut.Records, rec)
			return scorecard, logOut, nil
		}

		passCtx, cancel := context.WithTimeout(ctx, opts.PerIterTimeout)
		results, dispErr := dispatch(passCtx, target, dispatchDims, src)
		cancel()

		if dispErr != nil {
			if errors.Is(dispErr, context.DeadlineExceeded) {
				// W3 — suppress and synthesize a timeout DispatchResult.
				results = append(results, DispatchResult{
					Pass: "timeout", TargetDims: dispatchDims,
					DurationMs:     opts.PerIterTimeout.Milliseconds(),
					FramesCaptured: 0, OK: false,
					Note: "per-iter timeout",
				})
			} else {
				return scorecard, logOut, fmt.Errorf("dispatch: %w", dispErr)
			}
		}
		rec.Dispatched = results

		// Apply post-hoc capped integer bumps.
		for _, dr := range results {
			if !dr.OK || dr.FramesCaptured == 0 {
				continue
			}
			cap := capFor(dr.Pass)
			if cap == 0 {
				continue
			}
			ds := scorecard.Dim(dr.Pass)
			if ds == nil {
				continue
			}
			newScore := ds.Score
			if cap > newScore {
				newScore = cap
			}
			if newScore != ds.Score {
				ds.Score = newScore
				// P58C-02 (P64-05): runtime-bump Evidence cites the per-frame
				// NDJSON sidecar — Citation.File="frames.ndjson",
				// Line = 0-based index of the LAST frame seen during this
				// dispatch window, Hash = that frame's PayloadHash. Falls
				// back to iterations.jsonl Citation when no frames were
				// recorded for this kbDir (e.g. fake-CDP test paths that
				// don't write the sidecar).
				var cite *Citation
				if line, hash := LastFrameForKB(target.KBOutputDir); hash != "" {
					cite = &Citation{File: framesFile, Line: line, Hash: hash}
				} else {
					cite = newCitation(target.KBOutputDir, filepath.Join(target.KBOutputDir, "iterations.jsonl"), iter)
				}
				ds.Evidence = append(ds.Evidence, Evidence{
					Kind:     "runtime",
					Source:   "cdp",
					Detail:   fmt.Sprintf("post-hoc bump to %d via %d frames", cap, dr.FramesCaptured),
					Citation: cite,
				})
				rec.Bumps[dr.Pass] = newScore
			}
		}

		// B3 (CDP-attached path also requires the marker).
		applyBehaviorMissingMarker(scorecard, opts.Threshold)

		// Recompute coverage from updated PerDim.
		scorecard.Coverage = computeCoverage(scorecard.Dimensions)
		rec.PostMean, rec.PostCoverage = summary(scorecard)

		// P58 — compute citations_ok AFTER post-hoc bumps applied.
		rec.CitationsOK = ComputeCitationsOK(scorecard)

		if err := writeIterationRecord(target.KBOutputDir, rec); err != nil {
			return scorecard, logOut, fmt.Errorf("write iter record: %w", err)
		}
		logOut.Records = append(logOut.Records, rec)

		if convergedAt(scorecard, opts) {
			return scorecard, logOut, nil
		}
	}

	return scorecard, logOut, nil
}

// summary returns the (truncated integer mean, dims-meeting-80 count) pair.
func summary(sc *Scorecard) (mean, coverage int) {
	if sc == nil || len(sc.Dimensions) == 0 {
		return 0, 0
	}
	sum := 0
	for _, d := range sc.Dimensions {
		sum += d.Score
	}
	mean = sum / len(sc.Dimensions) // INTEGER truncation per B2
	coverage = computeCoverage(sc.Dimensions)
	return
}

func weakDimsOf(sc *Scorecard, threshold int) []string {
	out := make([]string, 0, 4)
	for _, d := range sc.Dimensions {
		if d.Score < threshold {
			out = append(out, d.ID)
		}
	}
	return out
}

func filterDispatchable(dims []string) []string {
	out := make([]string, 0, len(dims))
	for _, d := range dims {
		switch d {
		case "wire", "auth", "state_machines", "ipc", "behavior":
			out = append(out, d)
		}
	}
	return out
}

// convergedAt is the EXIT gate.
//
// P58: now requires mean >= Threshold AND coverage (when RequireAll12)
// AND scorecard-level citations_ok. ComputeCitationsOK is invoked here as
// a side effect — it sets DimScore.MissingCitations and sc.CitationsOK so
// callers can read the gate state from the scorecard directly.
func convergedAt(sc *Scorecard, opts IterateOptions) bool {
	if sc == nil {
		return false
	}
	mean, _ := summary(sc)
	if mean < opts.Threshold {
		return false
	}
	if opts.RequireAll12 {
		for _, d := range sc.Dimensions {
			if d.Score < opts.Threshold {
				return false
			}
		}
	}
	if !ComputeCitationsOK(sc) {
		return false
	}
	return true
}

// applyBehaviorMissingMarker appends the canonical missing-evidence marker
// to scorecard.Dim("behavior") when behavior < threshold and the marker is
// not already present (idempotent — safe to call on every iteration on both
// paths). B3.
func applyBehaviorMissingMarker(sc *Scorecard, threshold int) {
	d := sc.Dim("behavior")
	if d == nil {
		return
	}
	if d.Score >= threshold {
		return
	}
	for _, e := range d.Evidence {
		if e.Kind == behaviorMissingKind && e.Source == behaviorMissingSource &&
			strings.Contains(e.Detail, "no deepening pass available for behavior") {
			return
		}
	}
	d.Evidence = append(d.Evidence, Evidence{
		Kind:   behaviorMissingKind,
		Source: behaviorMissingSource,
		Detail: behaviorMissingDetail,
	})
}
