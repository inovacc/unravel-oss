/*
Copyright (c) 2026 Security Research

Phase 10 D-28: Dispatch helper that composes the three Phase-10 primitives
(10-01 renderHTML, 10-02 BuildPrompt/ParseMCPResponse/Cache*, 10-03
BuildRegressionSection) onto a single HTMLRenderOptions surface. Called from
cmd/forensic.go when --html (or --ai, which implies --html) is set.

D-25: default no-flag path remains Markdown-only; this helper is opt-in.
B2 closure: forensic.MCPClient seam (10-00) is the locked delegation API —
no `delegateMCP` placeholder.
*/
package forensic

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// HTMLRenderOptions is the CLI-facing options struct for the new dispatch
// path. cmd/forensic.go constructs it from its flags and passes it to
// WriteHTMLReportFull.
type HTMLRenderOptions struct {
	// KBDir is the knowledge-base / teardown root used by 10-01 to discover
	// screenshots under <kb>/visual/latest for inline base64 embedding.
	KBDir string
	// IncludeImages, when false, suppresses base64 image embedding even when
	// KBDir is set (useful for headless CI / golden tests).
	IncludeImages bool

	// AI gates the executive-summary path. When true, BuildPrompt is called,
	// the cache is consulted (D-26 model-id discriminated), and on a miss the
	// MCPClient is invoked. Failures degrade gracefully (D-25): the report
	// renders without the exec-summary section.
	AI        bool
	MCPClient MCPClient // injected from cmd/forensic.go; NilMCPClient() when AI=false

	// DiffOld / DiffNew / Rubric drive the regression section (D-19).
	// Both DiffOld and DiffNew must be set together; the validation lives in
	// cmd/forensic.go to keep the user-facing error message early.
	DiffOld string
	DiffNew string
	Rubric  string
}

// WriteHTMLReportFull is the dispatch entry point for the new --html path.
// It composes the three primitives:
//
//  1. 10-02 exec-summary (when opts.AI): BuildPrompt -> CacheLookup ->
//     MCPClient.Summarize -> ParseMCPResponse -> CacheStore. Failures are
//     degraded to "render without summary" per D-25.
//  2. 10-03 regression section (when opts.DiffOld and opts.DiffNew set):
//     BuildRegressionSection composes Phase 7 KB diff + Phase 8 visual diff.
//  3. 10-01 renderHTML / WriteHTMLReport: writes the final report.html.
//
// On success, <outDir>/report.html exists (atomic write via knowledge.WriteFileAtomic).
// On total failure, the existing Markdown report.md remains the user's deliverable.
func WriteHTMLReportFull(ctx context.Context, r *Report, opts HTMLRenderOptions, outDir string) error {
	htmlOpts := HTMLOptions{
		KBDir:         opts.KBDir,
		IncludeImages: opts.IncludeImages,
	}

	// --ai path: build prompt, check cache, delegate via injected MCPClient seam,
	// parse, attach to opts. Mirrors pkg/frida/enrich/enrich.go:108 call site.
	if opts.AI {
		mcp := opts.MCPClient
		if mcp == nil {
			mcp = NilMCPClient()
		}
		findingsJSON, err := FindingsJSON(r)
		if err != nil {
			slog.Warn("exec-summary findings marshal failed", "err", err)
		} else {
			modelID := os.Getenv("UNRAVEL_MCP_MODEL") // D-26 model-id discriminator
			key := ComputeCacheKey(findingsJSON, modelID)
			if cached, ok := CacheLookup(key); ok {
				htmlOpts.ExecSummary = &cached
			} else {
				prompt, perr := BuildPrompt(r)
				if perr != nil {
					slog.Warn("build exec-summary prompt failed", "err", perr)
				} else {
					rawJSON, mErr := mcp.Summarize(ctx, prompt)
					if mErr != nil {
						// D-25 graceful degrade.
						slog.Warn("exec-summary mcp delegation failed; rendering without summary", "err", mErr)
					} else {
						sum, sErr := ParseMCPResponse(rawJSON)
						if sErr != nil {
							slog.Warn("exec-summary parse failed", "err", sErr)
						} else {
							htmlOpts.ExecSummary = &sum
							_ = CacheStore(key, sum)
						}
					}
				}
			}
		}
	}

	// --diff path: compose Phase 7 KB diff + Phase 8 visual diff into the regression section.
	if opts.DiffOld != "" && opts.DiffNew != "" {
		reg, err := BuildRegressionSection(opts.DiffOld, opts.DiffNew, opts.Rubric)
		if err != nil {
			return fmt.Errorf("regression section: %w", err)
		}
		htmlOpts.Regression = reg
	}

	// 10-01 final write.
	if err := WriteHTMLReport(r, htmlOpts, outDir); err != nil {
		return fmt.Errorf("write html report: %w", err)
	}
	return nil
}
