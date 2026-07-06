/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — P59 SCORECARD.md emitter (EMIT-01).
//
// EmitScorecardMD writes a six-section markdown report next to knowledge.json.
// All math is integer-only (B2 invariant): the mean is computed as
//
//	mean10 = sum * 10 / 12
//
// where sum is the integer sum of the 12 dim scores (each 0..100). The mean
// is printed as `%d.%d%%` from `mean10/10` and `mean10%10`. There is no
// floating-point arithmetic in this file (CI grep `float[36][24]` returns
// zero). Per-dim bar glyphs render exactly 10 cells: floor(score/10) blocks
// (`█`, U+2588) followed by the remaining dots (`·`, U+00B7).
//
// EmitHeader is INPUT-ONLY to the emitter. It is NOT a field on
// dissect.DissectResult — see d10_guard_test.go for the negative tripwire.
package scorecard

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EmitHeader carries presentation-only metadata into the SCORECARD.md
// formatter. Title falls back to filepath.Base(outputDir) when empty;
// PackageID falls back to Title. Threshold is the literal RESEARCH Q2
// string (not parameterized).
type EmitHeader struct {
	KbID      string
	Title     string
	PackageID string
	Generated time.Time
	Threshold string
}

// canonicalThreshold is the locked-literal Threshold line per RESEARCH Q2.
const canonicalThreshold = ">=10/12 dimensions at >=80% AND every spec line cites evidence"

// loop-decision locked literals (RESEARCH §6).
const (
	loopExitLine           = "**EXIT.** All dimensions above threshold AND every spec file cites evidence. Bundle `spec/` for shipping."
	loopContinueRuntime    = "**CONTINUE.** Runtime capture unavailable for this target. Static scores accepted; bumps deferred."
	loopContinueMaxIterFmt = "**CONTINUE.** Max iterations (%d) reached without convergence. Inspect lowest-scoring dimensions before re-running."
)

// EmitScorecardMD writes <outputDir>/SCORECARD.md (LF newlines, 0o644).
//
// All booleans render as PascalCase "True" / "False" (NOT strconv.FormatBool's
// lowercase). The header field separator is "  ·  " (two-space U+00B7
// two-space). The mean is integer-derived per the package doc-comment.
func EmitScorecardMD(outputDir string, sc *Scorecard, log *IterationLog, header EmitHeader) error {
	if sc == nil {
		return fmt.Errorf("scorecard nil")
	}
	clean, err := safeKBDir(outputDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(clean, 0o755); err != nil {
		return fmt.Errorf("mkdir output dir: %w", err)
	}
	path := filepath.Join(clean, "SCORECARD.md")

	body := renderScorecardMD(sc, log, header)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write SCORECARD.md: %w", err)
	}
	return nil
}

// renderScorecardMD produces the markdown body. Exposed at package scope
// for testability (the golden test calls it directly without filesystem I/O).
func renderScorecardMD(sc *Scorecard, log *IterationLog, header EmitHeader) string {
	title := header.Title
	if title == "" {
		title = "Unknown"
	}
	pkg := header.PackageID
	if pkg == "" {
		pkg = title
	}
	threshold := header.Threshold
	if threshold == "" {
		threshold = canonicalThreshold
	}

	// Aggregates derived from sc.Dimensions (A1).
	sum := 0
	at80, at50, at20 := 0, 0, 0
	for _, d := range sc.Dimensions {
		sum += d.Score
		if d.Score >= 80 {
			at80++
		}
		if d.Score >= 50 {
			at50++
		}
		if d.Score >= 20 {
			at20++
		}
	}
	mean10 := 0
	if len(sc.Dimensions) > 0 {
		// Locked to /12 per RESEARCH and W-## clean-room rubric — even
		// when fewer than 12 dims are present, the denominator is the
		// canonical 12. Integer math, no floats.
		mean10 = sum * 10 / 12
	}

	// LoopExit derivation: last record where post_coverage>=10 and
	// post_mean>=80 and citations_ok counts as exit; in absence of records
	// fall back to sc.CitationsOK && at80 >= 10.
	loopExit := false
	maxIter := 0
	runtimeUnavailable := false
	if log != nil && len(log.Records) > 0 {
		last := log.Records[len(log.Records)-1]
		runtimeUnavailable = last.RuntimeCaptureUnavailable
		if last.CitationsOK && last.PostCoverage >= 10 && last.PostMean >= 80 {
			loopExit = true
		}
		for _, rec := range log.Records {
			if rec.Iter > maxIter {
				maxIter = rec.Iter
			}
		}
	} else {
		loopExit = sc.CitationsOK && at80 >= 10
	}

	var b strings.Builder

	// §1 Header
	fmt.Fprintf(&b, "# %s clean-room KB scorecard\n\n", title)
	fmt.Fprintf(&b, "**Generated:** %s\n", header.Generated.Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "**kb_id:** `%s`  ·  **package:** `%s`\n", header.KbID, pkg)
	fmt.Fprintf(&b, "**Threshold:** %s\n", threshold)
	fmt.Fprintf(&b, "**Citations OK:** %s\n", boolPascal(sc.CitationsOK))
	fmt.Fprintf(&b, "**Loop exit:** %s\n\n", boolPascal(loopExit))

	// §2 Coverage summary
	b.WriteString("## Coverage summary\n\n")
	fmt.Fprintf(&b, "- Mean score: %d.%d%%\n", mean10/10, mean10%10)
	fmt.Fprintf(&b, "- Dimensions ≥80%%: %d/12\n", at80)
	fmt.Fprintf(&b, "- Dimensions ≥50%%: %d/12\n", at50)
	fmt.Fprintf(&b, "- Dimensions ≥20%%: %d/12\n\n", at20)

	// §3 Per-dimension table
	b.WriteString("## Per-dimension\n\n")
	b.WriteString("| # | Dimension | Score | Bar |\n")
	b.WriteString("|---|-----------|-------|-----|\n")
	for i, d := range sc.Dimensions {
		fmt.Fprintf(&b, "| %d | %s | %d%% | %s |\n", i+1, d.Name, d.Score, barGlyph(d.Score))
	}
	b.WriteString("\n")

	// §4 Iterations executed
	b.WriteString("## Iterations executed\n\n")
	b.WriteString("| ID | When | Notes |\n")
	b.WriteString("|----|------|-------|\n")
	if log != nil {
		for _, rec := range log.Records {
			when := formatIterTime(rec.TS)
			notes := iterNotes(rec)
			fmt.Fprintf(&b, "| %s | %s | %s |\n", rec.ID, when, notes)
		}
	}
	b.WriteString("\n")

	// §5 Lowest-scoring dimensions
	b.WriteString("## Lowest-scoring dimensions (next iteration targets)\n\n")
	for _, line := range lowestDims(sc, log) {
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// §6 Loop decision
	b.WriteString("## Loop decision\n\n")
	switch {
	case loopExit:
		b.WriteString(loopExitLine)
	case runtimeUnavailable:
		b.WriteString(loopContinueRuntime)
	default:
		fmt.Fprintf(&b, loopContinueMaxIterFmt, maxIter)
	}
	b.WriteString("\n")

	return b.String()
}

// boolPascal returns "True" / "False" — PascalCase per RESEARCH §1 (NOT
// strconv.FormatBool's lowercase output).
func boolPascal(v bool) string {
	if v {
		return "True"
	}
	return "False"
}

// barGlyph renders a 10-cell progress bar. Filled count = floor(score/10);
// remainder is rendered as U+00B7 (·). Score is clamped to [0..100].
func barGlyph(score int) string {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	filled := score / 10
	if filled > 10 {
		filled = 10
	}
	return strings.Repeat("█", filled) + strings.Repeat("·", 10-filled)
}

// formatIterTime parses RFC3339Nano TS and returns UTC "01/02/2006 15:04:05".
// UTC is locked (not Local) so emitter output is timezone-deterministic
// across CI machines (W2 byte-equality requirement).
func formatIterTime(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		// Try plain RFC3339 as fallback.
		t, err = time.Parse(time.RFC3339, ts)
		if err != nil {
			return ts
		}
	}
	return t.UTC().Format("01/02/2006 15:04:05")
}

// iterNotes builds the alphabetized "k=v; k=v" Notes column for an iteration
// record. Truncates to 120 chars with U+2026 (…) suffix when overlong.
func iterNotes(rec IterationRecord) string {
	type kv struct{ k, v string }
	var pairs []kv
	pairs = append(pairs,
		kv{"mean", fmt.Sprintf("%d", rec.Mean)},
		kv{"post_mean", fmt.Sprintf("%d", rec.PostMean)},
		kv{"coverage", fmt.Sprintf("%d", rec.Coverage)},
		kv{"post_coverage", fmt.Sprintf("%d", rec.PostCoverage)},
	)
	if len(rec.WeakDims) > 0 {
		pairs = append(pairs, kv{"weak_dims", strings.Join(rec.WeakDims, " ")})
	}
	if len(rec.Bumps) > 0 {
		bumpKeys := make([]string, 0, len(rec.Bumps))
		for k := range rec.Bumps {
			bumpKeys = append(bumpKeys, k)
		}
		sort.Strings(bumpKeys)
		var sb strings.Builder
		for i, k := range bumpKeys {
			if i > 0 {
				sb.WriteByte(' ')
			}
			fmt.Fprintf(&sb, "%s->%d", k, rec.Bumps[k])
		}
		pairs = append(pairs, kv{"bumps", sb.String()})
	}
	if rec.RuntimeCaptureUnavailable {
		pairs = append(pairs, kv{"runtime_capture_unavailable", "true"})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.k+"="+p.v)
	}
	notes := strings.Join(parts, "; ")
	return truncate120(notes)
}

// truncate120 clips an iteration-notes string to ≤120 runes with a trailing
// U+2026 (…) when truncated. Operates on runes to stay UTF-8-safe.
func truncate120(s string) string {
	const limit = 120
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit-1]) + "…"
}

// lowestDims selects up to 5 dims where Score < 100, ascending by Score, ties
// broken by canonical-dim order. Each line: `- **<Name>** at N%% ← owner: <owner>`.
func lowestDims(sc *Scorecard, log *IterationLog) []string {
	type entry struct {
		idx int // canonical index (lower = earlier in sc.Dimensions)
		dim DimScore
	}
	var pool []entry
	for i, d := range sc.Dimensions {
		if d.Score < 100 {
			pool = append(pool, entry{i, d})
		}
	}
	sort.SliceStable(pool, func(i, j int) bool {
		if pool[i].dim.Score != pool[j].dim.Score {
			return pool[i].dim.Score < pool[j].dim.Score
		}
		return pool[i].idx < pool[j].idx
	})
	if len(pool) > 5 {
		pool = pool[:5]
	}

	out := make([]string, 0, len(pool))
	for _, e := range pool {
		owner := lookupOwner(e.dim.ID, log)
		out = append(out, fmt.Sprintf("- **%s** at %d%% ← owner: %s", e.dim.Name, e.dim.Score, owner))
	}
	return out
}

// lookupOwner finds the most-recent iter record where dimID appears in
// WeakDims or Bumps. Returns "iter-N (<weak|bump>)" or "-" if none.
func lookupOwner(dimID string, log *IterationLog) string {
	if log == nil {
		return "-"
	}
	for i := len(log.Records) - 1; i >= 0; i-- {
		rec := log.Records[i]
		for _, w := range rec.WeakDims {
			if w == dimID {
				return fmt.Sprintf("iter-%d (weak_dims)", rec.Iter)
			}
		}
		if _, ok := rec.Bumps[dimID]; ok {
			return fmt.Sprintf("iter-%d (bumps)", rec.Iter)
		}
	}
	return "-"
}
