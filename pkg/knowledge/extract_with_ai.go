/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/knowledge/components"
	"github.com/inovacc/unravel-oss/pkg/store"
)

// orchestratorMaxInputBytes is the per-source upper bound enforced before a
// beautify track is invoked under --with-ai (T-07-06). Inputs above the cap
// are skipped with a warning so the orchestrator returns the sweep result +
// a note instead of stalling MCP on a giant bundle. Phase 1/6 chunkers
// further bound any in-flight payload internally.
const orchestratorMaxInputBytes = 10 << 20 // 10 MiB

// ExtractOptions controls the source-fidelity orchestrator (Plan 07-02).
//
// Default-cheap path (D-12): WithAI=false sweeps TeardownDir for already
// beautified outputs (D-04) and never invokes MCP. WithAI=true triggers
// the hardcoded switch over Java / JS / C# tracks (D-15) — CSS bypasses
// (D-16); JS handler internally calls the bundle reconstructor (D-17) so
// the orchestrator never references the bundle package directly.
type ExtractOptions struct {
	// WithAI enables the per-language beautify tracks. Off by default
	// (D-12); the user opts in via the `unravel knowledge --with-ai` flag.
	WithAI bool

	// TeardownDir is the post-dissect directory the sweep walks. When
	// empty, sweep is skipped and only the in-memory dissect result is
	// projected into the KB.
	TeardownDir string

	// Beautify is the per-track function-pointer set used by the
	// orchestrator. Non-nil values override the package-level production
	// adapters; tests inject counting stubs here.
	Beautify *beautifyDeps

	// Store is the cache backend. nil means a default store rooted at
	// %LOCALAPPDATA%/Unravel/cache.
	Store *store.Store

	// BeautifyInputs supplies the per-language source bodies the
	// orchestrator routes through the cache + track switch. In production
	// this is populated by the dissect pipeline (Phase 1) before Extract
	// is called; the test seam constructs it directly.
	BeautifyInputs *BeautifyInputs

	// Enrich (Phase 14) opt-in: when true, dependency lists declared by the
	// app are sent to OSV/NVD/GHSA/grype via pkg/cve and the resulting
	// EnrichedDep records are written to <OutputDir>/dependencies/. Off by
	// default per D-08 audit-trail. Honors EnrichIncludePrivate to override
	// the default "skip private/scoped packages" behavior.
	Enrich               bool
	EnrichIncludePrivate bool

	// AppDir is the on-disk directory of the dissected app, fed to
	// per-ecosystem DepExtractor.Detect/Extract calls. When empty,
	// extraction falls back to dr.Path.
	AppDir string

	// OutputDir is the KB output directory (parent of dependencies/).
	// Required when Enrich is true; ignored otherwise.
	OutputDir string
}

// BeautifyInputs is a per-language bundle of source bodies the dissect
// pipeline produced (raw decompiler output for Java/C#, raw bundles for
// JS). Defined locally to avoid coupling pkg/dissect to the source-
// fidelity workflow; parallel plan 07-03 modifies pkg/knowledge/diff
// without touching this file or pkg/dissect.
type BeautifyInputs struct {
	Java   []BeautifyInput
	JS     []BeautifyInput
	CSharp []BeautifyInput
	// CSS is captured for completeness but the orchestrator routes it
	// directly to extract_css.go (D-16). It is NOT read in this file.
	CSS []BeautifyInput
}

// BeautifyInput is one per-language source body. Path is informational
// (used for the cache Entry's SourcePath / SourceFile.Path); Content is
// the bytes the beautifier will operate on. Hash is computed from
// Content so the same file in different teardowns deduplicates.
type BeautifyInput struct {
	Path    string
	Content []byte
}

// beautifyDeps is the function-pointer test seam. The orchestrator never
// calls the production Phase 5/6 entry points directly; it always goes
// through these fields. defaultBeautifyDeps wires the production
// adapters; tests overwrite the fields with counting stubs.
//
// Per D-15 this is NOT a plugin registry: there is no Register call and
// no map of names to functions. The set of tracks is hardcoded at three
// (Java / JS / C#); CSS is intentionally absent (D-16).
type beautifyDeps struct {
	jBeautify  func(ctx context.Context, in []byte) ([]byte, error) // pkg/java/beautify
	jsBeautify func(ctx context.Context, in []byte) ([]byte, error) // pkg/jsdeob (bundle is internal — D-17)
	csBeautify func(ctx context.Context, in []byte) ([]byte, error) // pkg/dotnet/decompile
}

// defaultBeautifyDeps wires the production adapter set. The adapters are
// minimal: they pass the input through and rely on the production
// pipeline being invoked by the dissect/CLI layer for the actual MCP
// call. Plan 07-04 (CLI wiring) will replace these stubs with calls into
// pkg/java/beautify, pkg/jsdeob, pkg/dotnet/decompile.
//
// Resolved entry signatures (closes 07-RESEARCH A6) — recorded in summary:
//   - pkg/java/beautify.Beautifier.Beautify(ctx, prompt, input) (string, error)
//     plus pkg/java/beautify.BeautifyFile orchestration; the adapter wraps
//     these as ([]byte) -> ([]byte, error).
//   - pkg/jsdeob.BeautifyAI(ctx, opts BeautifyAIOptions, body []byte) — bundle
//     detection happens inside this entry (D-17). Adapter wraps to []byte->[]byte.
//   - pkg/dotnet/decompile.Orchestrator.Run(ctx, BeautifyOptions, RunOptions) —
//     directory-mode; the adapter shims the per-source body case as a
//     pass-through pending Plan 07-04 wiring.
var defaultBeautifyDeps = &beautifyDeps{
	jBeautify:  passthroughAdapter("phase6-java"),
	jsBeautify: passthroughAdapter("phase6-js"),
	csBeautify: passthroughAdapter("phase5-csharp"),
}

// passthroughAdapter returns an adapter that emits the input unchanged.
// Production wiring (Plan 07-04) replaces this with the real beautifier
// entry. The orchestrator's correctness — cache namespacing, track
// dispatch, classifier injection — is fully exercised by the test
// seam without needing live MCP.
func passthroughAdapter(_ string) func(ctx context.Context, in []byte) ([]byte, error) {
	return func(_ context.Context, in []byte) ([]byte, error) {
		return in, nil
	}
}

// ExtractWithOptions is the source-fidelity entry that augments Extract
// with sweep + beautify-track dispatch. Returns the same KnowledgeResult
// shape; SourceFiles is populated from sweep (default) or sweep + beautify
// outputs (--with-ai). Errors are non-fatal and logged via slog.
func ExtractWithOptions(dr *dissect.DissectResult, opts ExtractOptions) *KnowledgeResult {
	kr := Extract(dr)

	// --with-ai path: run the three tracks (D-15), populate cache, then
	// sweep so subsequent runs are zero-MCP (D-13). Errors per track are
	// logged; a partial result is still emitted.
	if opts.WithAI {
		if err := runWithAI(context.Background(), kr, opts); err != nil {
			slog.Warn("runWithAI completed with errors", "error", err)
		}
	}

	// Sweep is run in BOTH modes:
	// - Default (D-12): sweep is the only source of SourceFiles.
	// - --with-ai: sweep picks up newly-emitted beautified outputs in
	//   addition to the in-memory results runWithAI just produced.
	if opts.TeardownDir != "" {
		swept, err := SweepTeardown(opts.TeardownDir)
		if err != nil {
			slog.Warn("sweep failed", "dir", opts.TeardownDir, "error", err)
		}
		kr.SourceFiles = mergeSourceFiles(kr.SourceFiles, swept)
	}

	// Phase 14 dependency enrichment (D-07/D-08). Opt-in; default-cheap.
	// WARN-degrades on offline/timeout/ratelimit so KB still ships.
	if opts.Enrich {
		appDir := opts.AppDir
		if appDir == "" {
			appDir = dr.Path
		}
		if err := runDepEnrichment(context.Background(), appDir, opts); err != nil {
			slog.Warn("dependency enrichment failed", "error", err)
		}
	}
	return kr
}

// runWithAI walks each beautify input under --with-ai and dispatches it to
// the appropriate track via the function-pointer seam. Cache lookups are
// keyed by (SourceHash, Type) so beautify-java vs beautify-js never
// collide (D-13, Pitfall 4). CSS is never touched here (D-16).
func runWithAI(ctx context.Context, kr *KnowledgeResult, opts ExtractOptions) error {
	if opts.BeautifyInputs == nil {
		return nil
	}
	deps := opts.Beautify
	if deps == nil {
		deps = defaultBeautifyDeps
	}
	s := opts.Store
	if s == nil {
		s = store.New()
	}

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Java track. Each input goes through beautifyCacheLookup with
	// type="beautify-java"; runTrack handles the lookup, dispatch and
	// beautifyCachePut.
	for _, in := range opts.BeautifyInputs.Java {
		sf, err := runTrack(ctx, s, "beautify-java", "phase6-java", in, deps.jBeautify)
		record(err)
		if sf != nil {
			kr.SourceFiles = append(kr.SourceFiles, *sf)
		}
	}
	// JS track. Each input goes through beautifyCacheLookup with
	// type="beautify-js"; bundle reconstruction is internal to the JS
	// beautifier (D-17 — this orchestrator MUST NOT invoke the bundle
	// reconstructor directly).
	for _, in := range opts.BeautifyInputs.JS {
		sf, err := runTrack(ctx, s, "beautify-js", "phase6-js", in, deps.jsBeautify)
		record(err)
		if sf != nil {
			kr.SourceFiles = append(kr.SourceFiles, *sf)
		}
	}
	// C# track. Each input goes through beautifyCacheLookup with
	// type="beautify-csharp".
	for _, in := range opts.BeautifyInputs.CSharp {
		sf, err := runTrack(ctx, s, "beautify-csharp", "phase5-csharp", in, deps.csBeautify)
		record(err)
		if sf != nil {
			kr.SourceFiles = append(kr.SourceFiles, *sf)
		}
	}
	return firstErr
}

// runTrack handles cache lookup, beautify dispatch, cache write, and
// SourceFile assembly for one input. The cache namespacing is the load-
// bearing piece: lookups always include typ so beautify-java and
// beautify-js cannot collide on the same SourceHash.
func runTrack(
	ctx context.Context,
	s *store.Store,
	typ, provenance string,
	in BeautifyInput,
	beautify func(context.Context, []byte) ([]byte, error),
) (*SourceFile, error) {
	if beautify == nil {
		return nil, errors.New("nil beautify function")
	}
	if len(in.Content) == 0 {
		return nil, nil
	}
	if len(in.Content) > orchestratorMaxInputBytes {
		slog.Warn("beautify input exceeds orchestrator cap; skipping",
			"path", in.Path, "size", len(in.Content), "cap", orchestratorMaxInputBytes)
		return nil, nil
	}
	hash := computeSourceHash(in.Content)

	// Cache lookup: hit -> zero MCP. The cache key is (hash, typ); the
	// type field is the namespace fence.
	if cached, hit, err := beautifyCacheLookup(s, hash, typ); err != nil {
		slog.Warn("cache lookup error; will re-beautify", "type", typ, "error", err)
	} else if hit {
		return &SourceFile{
			Path:               in.Path,
			Original:           in.Path,
			Size:               int64(len(cached)),
			Content:            cached,
			BeautifyProvenance: provenance + " (cached)",
		}, nil
	}

	// Cache miss: run the track.
	out, err := beautify(ctx, in.Content)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", typ, err)
	}
	if err := beautifyCachePut(s, hash, typ, in.Path, out); err != nil {
		// Cache failure is non-fatal — return the beautified payload but
		// log so subsequent runs notice they will re-beautify.
		slog.Warn("cache put failed", "type", typ, "error", err)
	}
	return &SourceFile{
		Path:               in.Path,
		Original:           in.Path,
		Size:               int64(len(out)),
		Content:            out,
		BeautifyProvenance: provenance,
	}, nil
}

// classifierOptionsFor builds the components.Options the writer hands the
// classifier. WithAI -> non-nil MCPClassify (Plan 07-04 will swap the
// classifyMCPAdapter stub for a real MCP-backed call); !WithAI -> nil
// MCPClassify so the classifier degrades cleanly to BucketUnknown.
func classifierOptionsFor(opts ExtractOptions) components.Options {
	if !opts.WithAI {
		return components.Options{}
	}
	return components.Options{
		WithAI:      true,
		MCPClassify: classifyMCPAdapter,
	}
}

// classifyMCPAdapter is the MCPClassify function pointer. It is a stub:
// returns (BucketUnknown, 0, nil) so the classifier flows to its
// fallthrough. Plan 07-04 wires this through the MCP client. For 07-02
// the contract is "non-nil under WithAI=true so the classifier's MCP
// fallback is reachable" — exercised by TestExtractInjectsClassifierMCP.
func classifyMCPAdapter(_ context.Context, _ components.SourceFile) (components.Bucket, float64, error) {
	return components.BucketUnknown, 0, nil
}

// mergeSourceFiles concatenates beautified-track outputs with sweep
// results, preferring the in-memory beautified version when both surface
// the same path so a fresh --with-ai run wins over a stale sweep entry.
func mergeSourceFiles(beautified, swept []SourceFile) []SourceFile {
	have := make(map[string]bool, len(beautified))
	for _, sf := range beautified {
		have[sf.Path] = true
	}
	out := append([]SourceFile(nil), beautified...)
	for _, sf := range swept {
		if have[sf.Path] {
			continue
		}
		out = append(out, sf)
	}
	return out
}
