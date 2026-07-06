/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
	"github.com/inovacc/unravel-oss/pkg/knowledge/scorecard"
)

// scoreJSONEnvelope is the on-disk shape of _score.json. It wraps the
// in-memory Scorecard with consumer-facing fields (package, coverage object,
// threshold). Mirrors the v2.9 W-loop envelope the corpus_validation tests
// + heatmap reader were authored against.
type scoreJSONEnvelope struct {
	KbID        string               `json:"kb_id"`
	Package     string               `json:"package"`
	Threshold   string               `json:"threshold"`
	Dimensions  []scorecard.DimScore `json:"dimensions"`
	Coverage    scoreJSONCoverage    `json:"coverage"`
	CitationsOK bool                 `json:"citations_ok"`
}

type scoreJSONCoverage struct {
	DimsAt80  int `json:"dimensions_at_80"`
	MeanScore int `json:"mean_score"` // mean10 (e.g. 487 = 48.7%)
}

// emitScoreJSON writes the machine-readable _score.json sidecar alongside
// SCORECARD.md. The corpus_validation tests (VOPR-01..03) read this file
// to assert per-dim values; without it they SKIP rather than PASS. P63
// live-extension; complementary to EmitScorecardMD.
//
// D-10 invariant: knowledge.json byte-shape unchanged — _score.json is a
// sidecar in the same outDir.
func emitScoreJSON(outDir string, sc *scorecard.Scorecard, packageID string) error {
	// Compute mean10 from the dimensions slice (no float arithmetic; matches
	// emitter's integer-only convention).
	var sum int
	for _, d := range sc.Dimensions {
		sum += d.Score
	}
	mean10 := 0
	if len(sc.Dimensions) > 0 {
		mean10 = sum * 10 / len(sc.Dimensions)
	}
	env := scoreJSONEnvelope{
		KbID:       sc.KbID,
		Package:    packageID,
		Threshold:  ">=10/12 dimensions at >=80% AND every spec line cites evidence",
		Dimensions: sc.Dimensions,
		Coverage: scoreJSONCoverage{
			DimsAt80:  sc.Coverage,
			MeanScore: mean10,
		},
		CitationsOK: sc.CitationsOK,
	}
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("scorecard: marshal _score.json: %w", err)
	}
	dst := filepath.Join(outDir, "_score.json")
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		return fmt.Errorf("scorecard: write _score.json: %w", err)
	}
	return nil
}

// emitScorecardSidecar writes SCORECARD.md next to knowledge.json. P59-04a.
//
// D-10 invariant: knowledge.json byte shape is unchanged. The emitter only
// writes a sidecar file. Errors during scoring or writing are logged but
// never bubble up — static knowledge output must not be blocked.
//
// Implementation: re-runs dissect (cache-hit fast on second call) to obtain
// a *DissectResult for Rubric.Score. The shipped knowledge.Run intentionally
// does not expose the underlying DissectResult; revising that signature is
// out of P59 scope.
func emitScorecardSidecar(path, outDir string, kr *knowledge.KnowledgeResult) {
	dr, err := dissect.Run(path, dissect.Options{Verbose: false})
	if err != nil {
		slog.Warn("scorecard: dissect failed; emitting placeholder SCORECARD.md", "err", err)
	}

	rb := scorecard.New()
	sc := rb.Score(dr, nil)

	title := ""
	if kr != nil {
		title = kr.AppName
	}
	if title == "" {
		title = filepath.Base(filepath.Clean(outDir))
	}
	// PackageID derivation from typed dissect fields is intentionally
	// minimal in P59 — falls back to title until a per-platform extractor
	// is wired in a follow-up phase. Header still renders the package line.
	pkg := title

	header := scorecard.EmitHeader{
		KbID:      sc.KbID,
		Title:     title,
		PackageID: pkg,
		Generated: time.Now(),
	}
	if err := scorecard.EmitScorecardMD(outDir, &sc, nil, header); err != nil {
		slog.Warn("scorecard: emit failed", "err", err, "outDir", outDir)
		return
	}
	if err := emitScoreJSON(outDir, &sc, pkg); err != nil {
		slog.Warn("scorecard: _score.json emit failed", "err", err, "outDir", outDir)
	}
	if verbose {
		fmt.Printf("Scorecard written to: %s\n", filepath.Join(outDir, "SCORECARD.md"))
	}
}

// emitScorecardSidecarIterate is the iterate-path sibling of
// emitScorecardSidecar (P61 CLSR-01). When --iterate=true, this dispatches to
// Rubric.Iterate, persists iterations.jsonl (handled inside Iterate), AND
// refreshes SCORECARD.md via EmitScorecardMD so the sidecar reflects the
// iteration log instead of a stale static-only render.
//
// D-10 invariant: knowledge.json byte-shape unchanged — this writes ONLY the
// sidecar (.md + .jsonl) under outDir. Errors during dissect / iterate /
// emit are logged and bubbled up to the caller, which decides whether to
// surface them; static knowledge output is never blocked because the caller
// invokes this AFTER knowledge.Run has succeeded.
func emitScorecardSidecarIterate(
	ctx context.Context,
	path, outDir string,
	kr *knowledge.KnowledgeResult,
	opts scorecard.IterateOptions,
	cdpPort int,
) error {
	dr, err := dissect.Run(path, dissect.Options{Verbose: false})
	if err != nil {
		// Mirror emitScorecardSidecar: degraded run is preferable to no
		// scorecard at all. Iterate handles a nil/empty Result gracefully.
		slog.Warn("scorecard-iterate: dissect failed; continuing degraded", "err", err)
	}

	target := &scorecard.DissectTarget{
		Result:        dr,
		AppDir:        path,
		KBOutputDir:   outDir,
		CDPPort:       cdpPort,
		FrameworkHint: "",
	}

	// P63 — install the production CDP frame source when --cdp-port is set.
	// Without this the iterate loop silently runs noopFrameSource{} and
	// emits frames_captured:0 on every weak-dim pass.
	if cdpPort != 0 {
		scorecard.InstallProductionCDPFactory(fmt.Sprintf("127.0.0.1:%d", cdpPort))
	}

	rub := scorecard.New()
	sc, log, ierr := rub.Iterate(ctx, target, opts)
	if ierr != nil {
		slog.Warn("scorecard-iterate: iterate failed", "err", ierr)
		return ierr
	}

	title := ""
	if kr != nil {
		title = kr.AppName
	}
	if title == "" {
		title = filepath.Base(filepath.Clean(outDir))
	}

	header := scorecard.EmitHeader{
		KbID:      sc.KbID,
		Title:     title,
		PackageID: title,
		Generated: time.Now(),
	}
	if eerr := scorecard.EmitScorecardMD(outDir, sc, log, header); eerr != nil {
		slog.Warn("scorecard-iterate: emit failed", "err", eerr, "outDir", outDir)
		return eerr
	}
	if jerr := emitScoreJSON(outDir, sc, header.PackageID); jerr != nil {
		slog.Warn("scorecard-iterate: _score.json emit failed", "err", jerr, "outDir", outDir)
	}
	if verbose {
		fmt.Printf("Iterate scorecard written to: %s\n", filepath.Join(outDir, "SCORECARD.md"))
	}
	return nil
}
