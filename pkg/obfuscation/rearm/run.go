/*
Copyright (c) 2026 Security Research
*/
package rearm

import (
	"context"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// Run is the single orchestrator invoked during KB generation. Honest-empty:
// zero candidates => r.ObfuscationReport stays nil. AI failure for a candidate
// => recorded with the heuristic mechanism hint + status, with NO source
// overwrite (decision A). All errors are non-fatal (appended to r.Errors).
func Run(ctx context.Context, r *dissect.DissectResult, b Beautifier, opts Options) {
	if r == nil || b == nil {
		return
	}
	cands := RankAndBound(CollectCandidates(r), opts.Bounds)
	if len(cands) == 0 {
		return
	}
	rep := &dissect.ObfuscationReport{}
	for _, c := range cands {
		mech, conf, code, err := rearmOne(ctx, b, c)
		if err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("rearm %s %s: %v", c.Lang, c.ModuleRef, err))
			rep.Modules = append(rep.Modules, dissect.RearmedModule{
				Lang: c.Lang, ModuleRef: c.ModuleRef, Mechanism: c.HeuristicHint,
				Status: "not_rearmed_ai_unavailable",
			})
			continue
		}
		rep.Modules = append(rep.Modules, dissect.RearmedModule{
			Lang: c.Lang, ModuleRef: c.ModuleRef, Mechanism: mech, Confidence: conf,
			Status: "rearmed", Provenance: "ai-mcp-sampling", Model: "mcp-sampling",
		})
		if mech != "" {
			rep.Mechanisms = append(rep.Mechanisms, dissect.MechanismFinding{
				Lang: c.Lang, Name: mech, Confidence: conf, ModuleRef: c.ModuleRef,
			})
		}
		if code != "" {
			materialize(r, c, code)
		}
	}
	if len(rep.Modules) > 0 {
		r.ObfuscationReport = rep
	}
}

// materialize writes reconstructed code into the language's existing beautify
// field; the ObfuscationReport remains the authoritative provenance source.
func materialize(r *dissect.DissectResult, c Candidate, code string) {
	if c.Lang == "js" {
		r.BeautifiedJS = code
	}
	// dotnet/java keep their own existing AI-beautify materialization path;
	// here they are report-only (their reconstructed text is recorded via the
	// RearmedModule entry). JS is the materialization target for this subsystem.
}
