package converter

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"golang.org/x/tools/imports"

	"github.com/inovacc/unravel-oss/pkg/transpile/audit"
	"github.com/inovacc/unravel-oss/pkg/transpile/core/adapt"
	"github.com/inovacc/unravel-oss/pkg/transpile/core/codegen"
	"github.com/inovacc/unravel-oss/pkg/transpile/core/debug"
	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages"
)

// guardStage wraps a pipeline stage so a panic in the parser/lowerer/codegen
// (typically triggered by adversarial real-world input, threat T-08-05) is
// recovered and converted into a STRUCTURED per-unit error instead of crashing
// the process. Critically (threat T-08-06, D-03 invariant) the recovered panic
// is SURFACED — routed through fr.SetError (debug per-unit error) AND
// a.AddError (run/audit trail) — and the non-nil error is returned. It is
// NEVER swallowed: a recovered unit that emits neither output nor a surfaced
// error is a silent-failure violation, so this helper must not `return nil`
// on the recover path. Mirrors the no-silent-failure invariant at
// orchestrator.go:206 (keep the unit visible, surface the error).
func guardStage(stage string, fr *debug.FileRecorder, a *audit.Auditor, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in %s: %v", stage, r)
			if fr != nil {
				fr.SetError(err)
			}

			if a != nil {
				a.AddError(err.Error())
			}
		}
	}()

	return fn()
}

// PromptResult holds the output of a conversion: either generated Go code
// (deterministic pipeline) or system+user prompts for the host LLM.
type PromptResult struct {
	Language     string `json:"language"`
	File         string `json:"file"`
	Mode         string `json:"mode"`
	Path         string `json:"path,omitempty"` // "deterministic" | "llm-only" (additive, D-03/D-05/JAVA-02)
	SystemPrompt string `json:"system_prompt,omitempty"`
	UserPrompt   string `json:"user_prompt,omitempty"`
	GoCode       string `json:"go_code,omitempty"`

	// Confidence tracks what fraction of IR nodes were converted deterministically
	// (vs. RawStmt/RawExpr needing LLM). Only set for deterministic/hybrid modes.
	Confidence *ConfidenceScore `json:"confidence,omitempty"`

	// OutputCompiles reports whether the emitted Go passed the post-codegen
	// parse gate (TRANSPILE-PHASE2-GAPS C7). Additive honesty signal: true means
	// the deterministic GoCode parses with go/parser. CompileError carries the
	// parse failure (with source position) when it does not. Both are only
	// meaningful on the deterministic path (GoCode set).
	OutputCompiles bool   `json:"output_compiles,omitempty"`
	CompileError   string `json:"compile_error,omitempty"`

	// LoopStateJSON carries the host-carried loop state blob (Phase 5, Q1 resolved).
	// The host reads this field and passes it back on the next Advance call.
	// omitempty so non-loop callers are unaffected.
	LoopStateJSON string `json:"loop_state_json,omitempty"`
}

// ConfidenceScore measures deterministic conversion coverage.
type ConfidenceScore struct {
	TotalNodes         int     `json:"total_nodes"`
	DeterministicNodes int     `json:"deterministic_nodes"`
	RawNodes           int     `json:"raw_nodes"`
	Ratio              float64 `json:"ratio"` // 0.0–1.0
}

// Format returns a structured text representation of the prompt result,
// suitable for output to stdout or an MCP tool result.
func (pr *PromptResult) Format() string {
	if pr.GoCode != "" {
		var buf strings.Builder
		if pr.Confidence != nil {
			_, _ = fmt.Fprintf(&buf, "// Confidence: %.0f%% deterministic (%d/%d nodes)\n\n",
				pr.Confidence.Ratio*100, pr.Confidence.DeterministicNodes, pr.Confidence.TotalNodes)
		}
		buf.WriteString(pr.GoCode)
		return buf.String()
	}

	var buf strings.Builder

	_, _ = fmt.Fprintf(&buf, "=== TOGO CONVERSION PROMPTS ===\n")
	_, _ = fmt.Fprintf(&buf, "Language: %s\n", pr.Language)
	_, _ = fmt.Fprintf(&buf, "File: %s\n", pr.File)
	_, _ = fmt.Fprintf(&buf, "Mode: %s\n", pr.Mode)
	if pr.Confidence != nil {
		_, _ = fmt.Fprintf(&buf, "Confidence: %.0f%% deterministic (%d/%d nodes, %d need LLM)\n",
			pr.Confidence.Ratio*100, pr.Confidence.DeterministicNodes, pr.Confidence.TotalNodes, pr.Confidence.RawNodes)
	}
	_, _ = fmt.Fprintf(&buf, "\n")
	_, _ = fmt.Fprintf(&buf, "=== SYSTEM PROMPT ===\n%s\n\n", pr.SystemPrompt)
	_, _ = fmt.Fprintf(&buf, "=== USER PROMPT ===\n%s\n\n", pr.UserPrompt)
	_, _ = fmt.Fprintf(&buf, "=== INSTRUCTIONS ===\n")
	_, _ = fmt.Fprintf(&buf, "Generate the Go code based on the system and user prompts above.\n")
	_, _ = fmt.Fprintf(&buf, "Return ONLY the Go source code, no markdown fences.\n")

	return buf.String()
}

// Option configures the Converter.
type Option func(*Converter)

// WithDebug sets the debug recorder for artifact dumping.
func WithDebug(rec *debug.Recorder) Option {
	return func(c *Converter) {
		c.debug = rec
	}
}

// Converter orchestrates source-to-Go conversion using the language plugin system.
type Converter struct {
	adapt   *adapt.Engine
	codegen *codegen.Generator
	logger  *slog.Logger
	debug   *debug.Recorder
	// auditor, when set, receives recover-guard panic errors so they surface
	// in the run/audit trail (D-03). Optional: nil is a valid no-op.
	auditor *audit.Auditor
}

// WithAuditor wires an Auditor so recover-guard panics (D-03) are surfaced to
// the run/audit trail via Auditor.AddError in addition to fr.SetError.
func WithAuditor(a *audit.Auditor) Option {
	return func(c *Converter) {
		c.auditor = a
	}
}

// WithLLM enables LLM-assisted adaptation for complex patterns.
func WithLLM(client adapt.LLMClient) Option {
	return func(c *Converter) {
		adapt.WithLLM(client)(c.adapt)
	}
}

// New creates a new converter.
func New(logger *slog.Logger, opts ...Option) *Converter {
	c := &Converter{
		adapt:   adapt.NewEngine(logger),
		codegen: codegen.New(),
		logger:  logger,
		debug:   debug.NopRecorder(),
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// convCtx bundles per-file conversion state shared across all pipeline methods.
type convCtx struct {
	fr        *debug.FileRecorder
	sourceStr string
}

// beginConversion initializes debug recording for a file conversion.
// The caller must defer cc.finish(c.logger) to finalize the recording.
func (c *Converter) beginConversion(lang languages.Language, filename string, source []byte, mode string) *convCtx {
	fr := c.debug.FileRecorder(filename)
	fr.Start()
	fr.SetMode(mode)
	fr.RecordInput(filename, source)

	sourceStr := string(source)
	if c.debug.Enabled() {
		fr.RecordIncludes(lang.DetectImports(sourceStr), nil)
	}

	return &convCtx{fr: fr, sourceStr: sourceStr}
}

// finish finalizes the debug recording.
func (cc *convCtx) finish(logger *slog.Logger) {
	if err := cc.fr.Finish(); err != nil {
		logger.Warn("debug: failed to write metadata", "error", err)
	}
}

// resolveSystemPrompt returns the system prompt enriched with context rules.
func (c *Converter) resolveSystemPrompt(ctx context.Context, lang languages.Language, source string) string {
	sp, err := lang.SystemPromptFor(ctx, source)
	if err != nil {
		c.logger.Warn("failed to load context rules, using base prompt", "error", err)
		return lang.SystemPrompt()
	}

	return sp
}

// ConvertWithLanguage converts source code using a Language implementation in raw mode.
func (c *Converter) ConvertWithLanguage(ctx context.Context, lang languages.Language, filename string, source []byte) (*PromptResult, error) {
	c.logger.Info("converting file (raw mode)", "language", lang.Name(), "file", filename, "size", len(source))

	cc := c.beginConversion(lang, filename, source, "raw")
	defer cc.finish(c.logger)

	var systemPrompt, userPrompt string

	if gErr := guardStage("raw", cc.fr, c.auditor, func() error {
		systemPrompt = c.resolveSystemPrompt(ctx, lang, cc.sourceStr)
		userPrompt = lang.ConvertRawPrompt(filename, cc.sourceStr)

		return nil
	}); gErr != nil {
		return nil, gErr
	}

	cc.fr.RecordSystemPrompt(systemPrompt)
	cc.fr.RecordUserPrompt(userPrompt)

	return &PromptResult{
		Language:     lang.Name(),
		File:         filename,
		Mode:         "raw",
		Path:         "llm-only",
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
	}, nil
}

// ConvertWithLanguageAST converts source code using an ASTLanguage in AST mode.
func (c *Converter) ConvertWithLanguageAST(ctx context.Context, lang languages.ASTLanguage, filename string, source []byte) (*PromptResult, error) {
	c.logger.Info("converting file (AST mode)", "language", lang.Name(), "file", filename)

	cc := c.beginConversion(lang, filename, source, "ast")
	defer cc.finish(c.logger)

	var (
		module   any
		parseErr error
	)

	if gErr := guardStage("ast:parse", cc.fr, c.auditor, func() error {
		module, parseErr = lang.ParseFile(filename, source)

		return nil
	}); gErr != nil {
		return nil, gErr
	}

	systemPrompt := c.resolveSystemPrompt(ctx, lang, cc.sourceStr)

	// If parsing fails, fall back to raw-mode prompts with AST context.
	if parseErr != nil {
		c.logger.Warn("AST parse failed, falling back to raw prompt", "file", filename, "error", parseErr)
		cc.fr.SetMode("ast-fallback")

		userPrompt := lang.ConvertRawPrompt(filename, cc.sourceStr)

		cc.fr.RecordSystemPrompt(systemPrompt)
		cc.fr.RecordUserPrompt(userPrompt)

		return &PromptResult{
			Language:     lang.Name(),
			File:         filename,
			Mode:         "ast-fallback",
			Path:         "llm-only",
			SystemPrompt: systemPrompt,
			UserPrompt:   userPrompt,
		}, nil
	}

	cc.fr.RecordAST(module)

	userPrompt, err := lang.ConvertModulePrompt(module)
	if err != nil {
		cc.fr.SetError(err)
		return nil, fmt.Errorf("build prompt: %w", err)
	}

	userPrompt += "\n\nOriginal " + lang.Name() + " source for reference:\n" + cc.sourceStr

	cc.fr.RecordSystemPrompt(systemPrompt)
	cc.fr.RecordUserPrompt(userPrompt)

	return &PromptResult{
		Language:     lang.Name(),
		File:         filename,
		Mode:         "ast",
		Path:         "llm-only",
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
	}, nil
}

// ConvertWithDeterministic converts source code using the full deterministic pipeline.
// Pipeline: parse → lower to IR → adapt → codegen → Go code.
func (c *Converter) ConvertWithDeterministic(ctx context.Context, lang languages.DeterministicLanguage, filename string, source []byte) (*PromptResult, error) {
	c.logger.Info("converting file (deterministic mode)", "language", lang.Name(), "file", filename)

	cc := c.beginConversion(lang, filename, source, "ast")
	defer cc.finish(c.logger)

	// Stage 1: Parse source → AST (recover-guarded — D-03)
	var module any

	var err error

	if gErr := guardStage("deterministic:parse", cc.fr, c.auditor, func() error {
		module, err = lang.ParseFile(filename, source)

		return nil
	}); gErr != nil {
		return nil, gErr
	}

	if err != nil {
		// Parse failure on the deterministic seam must NOT be fatal: mirror
		// ConvertWithLanguageAST's graceful degradation and emit a stable,
		// fully-deterministic `ast-fallback` raw prompt (source-derived, no
		// map/pointer ordering). Without this, parse-failing inputs (e.g.
		// Python files using grammar the ANTLR parser cannot handle) produce
		// empty stdout + a fatal error, diverging from the recorded golden
		// baseline — the D-02 "non-determinism". General path fix, not
		// per-file output pinning.
		c.logger.Warn("deterministic parse failed, falling back to raw prompt", "file", filename, "error", err)
		cc.fr.SetMode("ast-fallback")

		systemPrompt := c.resolveSystemPrompt(ctx, lang, cc.sourceStr)
		userPrompt := lang.ConvertRawPrompt(filename, cc.sourceStr)

		cc.fr.RecordSystemPrompt(systemPrompt)
		cc.fr.RecordUserPrompt(userPrompt)

		return &PromptResult{
			Language:     lang.Name(),
			File:         filename,
			Mode:         "ast-fallback",
			Path:         "llm-only",
			SystemPrompt: systemPrompt,
			UserPrompt:   userPrompt,
		}, nil
	}

	cc.fr.RecordAST(module)

	// Stage 2: Lower AST → IR (recover-guarded — D-03)
	var lowered any

	if gErr := guardStage("deterministic:lower", cc.fr, c.auditor, func() error {
		lowered, err = lang.LowerToIR(module)

		return nil
	}); gErr != nil {
		return nil, gErr
	}

	if err != nil {
		cc.fr.SetError(err)
		return nil, fmt.Errorf("lower %s: %w", filename, err)
	}

	mod, ok := lowered.(*ir.Module)
	if !ok {
		cc.fr.SetError(fmt.Errorf("expected *ir.Module from LowerToIR, got %T", lowered))
		return nil, fmt.Errorf("lower %s: expected *ir.Module, got %T", filename, lowered)
	}

	c.logger.Info("lowered to IR",
		"imports", len(mod.Imports),
		"decls", len(mod.Decls),
	)

	cc.fr.RecordIR(mod)

	// Stage 3: Adapt (heuristics + rules)
	mod = c.adapt.Adapt(ctx, mod)

	cc.fr.RecordAdaptedIR(mod)

	// Compute confidence score
	confidence := computeConfidence(mod)

	c.logger.Info("confidence score",
		"total", confidence.TotalNodes,
		"deterministic", confidence.DeterministicNodes,
		"raw", confidence.RawNodes,
		"ratio", fmt.Sprintf("%.0f%%", confidence.Ratio*100),
	)

	// Check if any nodes need LLM fallback
	needsLLM := slices.ContainsFunc(mod.Decls, c.adapt.NeedsLLMFallback)

	if needsLLM {
		c.logger.Info("some IR nodes need LLM assistance, using hybrid mode")
		cc.fr.SetMode("hybrid")
		cc.fr.SetLLMFallback(true)

		pr, err := c.buildIRPrompts(ctx, lang, mod, cc.sourceStr, filename, cc.fr)
		if err == nil {
			pr.Confidence = confidence
		}

		return pr, err
	}

	// Stage 4: Codegen (deterministic, recover-guarded — D-03)
	var result string

	if gErr := guardStage("deterministic:codegen", cc.fr, c.auditor, func() error {
		result, err = c.codegen.Generate(mod)

		return nil
	}); gErr != nil {
		return nil, gErr
	}

	if err != nil {
		c.logger.Warn("codegen failed, falling back to LLM prompts", "error", err)
		cc.fr.SetLLMFallback(true)

		pr, pErr := c.buildIRPrompts(ctx, lang, mod, cc.sourceStr, filename, cc.fr)
		if pErr == nil {
			pr.Confidence = confidence
		}

		return pr, pErr
	}

	// Stage 5: Compile gate (honesty — C7, TRANSPILE-PHASE2-GAPS). Assert the
	// EMITTED Go actually parses with go/parser before claiming success. A
	// codegen bug that produces invalid Go would otherwise pass the coverage
	// metric unnoticed. On failure, surface a slog.Warn (stderr) with the parse
	// location and degrade to LLM prompts rather than emitting broken Go.
	var gateErr error

	if gErr := guardStage("deterministic:compile-gate", cc.fr, c.auditor, func() error {
		gateErr = assertGoParses([]byte(result))

		return nil
	}); gErr != nil {
		gateErr = gErr
	}

	if gateErr != nil {
		c.logger.Warn("generated Go failed the compile gate, falling back to LLM prompts",
			"file", filename, "error", gateErr)
		cc.fr.SetLLMFallback(true)

		pr, pErr := c.buildIRPrompts(ctx, lang, mod, cc.sourceStr, filename, cc.fr)
		if pErr == nil {
			pr.Confidence = confidence
			pr.OutputCompiles = false
			pr.CompileError = gateErr.Error()
		}

		return pr, pErr
	}

	cc.fr.RecordCodegenOutput(result)

	c.logger.Info("code generation complete (deterministic)")

	return &PromptResult{
		Language:       lang.Name(),
		File:           filename,
		Mode:           "deterministic",
		Path:           "deterministic",
		GoCode:         result,
		Confidence:     confidence,
		OutputCompiles: true,
	}, nil
}

// ConvertWithASTRewrite builds prompts for a two-pass AI conversion.
func (c *Converter) ConvertWithASTRewrite(ctx context.Context, lang languages.ASTRewriteLanguage, filename string, source []byte) (*PromptResult, error) {
	c.logger.Info("converting file (AST rewrite mode, pass 1)", "language", lang.Name(), "file", filename)

	cc := c.beginConversion(lang, filename, source, "ast-rewrite")
	defer cc.finish(c.logger)

	// Stage 1: Parse source → AST (recover-guarded — D-03)
	var module any

	var err error

	if gErr := guardStage("ast-rewrite:parse", cc.fr, c.auditor, func() error {
		module, err = lang.ParseFile(filename, source)

		return nil
	}); gErr != nil {
		return nil, gErr
	}

	if err != nil {
		cc.fr.SetError(err)
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}

	cc.fr.RecordAST(module)

	// Stage 2: Build rewrite prompt from AST JSON (recover-guarded — D-03)
	var rewriteSystem, rewriteUser string

	if gErr := guardStage("ast-rewrite:prompt", cc.fr, c.auditor, func() error {
		rewriteSystem, rewriteUser, err = lang.RewriteASTPrompt(module)

		return nil
	}); gErr != nil {
		return nil, gErr
	}

	if err != nil {
		cc.fr.SetError(err)
		return nil, fmt.Errorf("build rewrite prompt: %w", err)
	}

	cc.fr.RecordSystemPrompt(rewriteSystem)
	cc.fr.RecordUserPrompt(rewriteUser)

	return &PromptResult{
		Language:     lang.Name(),
		File:         filename,
		Mode:         "ast-rewrite",
		Path:         "llm-only",
		SystemPrompt: rewriteSystem,
		UserPrompt:   rewriteUser,
	}, nil
}

// ConvertRewrittenAST handles pass 2 of AST rewrite conversion.
func (c *Converter) ConvertRewrittenAST(ctx context.Context, lang languages.ASTRewriteLanguage, filename string, source []byte, rewrittenJSON string) (*PromptResult, error) {
	c.logger.Info("converting file (AST rewrite mode, pass 2)", "language", lang.Name(), "file", filename)

	sourceStr := string(source)

	// Parse rewritten AST back to module (recover-guarded — D-03). This
	// entrypoint has no per-file debug recorder, so the guard routes panics
	// to the audit trail (fr=nil) and still returns a non-nil error — never
	// swallowed.
	jsonData := extractJSON(rewrittenJSON)

	var (
		rewrittenModule any
		err             error
	)

	if gErr := guardStage("ast-rewrite-codegen:parse", nil, c.auditor, func() error {
		rewrittenModule, err = lang.ParseRewrittenAST([]byte(jsonData))
		if err != nil {
			c.logger.Warn("failed to parse rewritten AST, falling back to original parse", "error", err)

			rewrittenModule, err = lang.ParseFile(filename, source)
		}

		return nil
	}); gErr != nil {
		return nil, gErr
	}

	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}

	// Build codegen prompts from rewritten AST (recover-guarded — D-03)
	var userPrompt string

	if gErr := guardStage("ast-rewrite-codegen:prompt", nil, c.auditor, func() error {
		userPrompt, err = lang.ConvertModulePrompt(rewrittenModule)

		return nil
	}); gErr != nil {
		return nil, gErr
	}

	if err != nil {
		return nil, fmt.Errorf("build final prompt: %w", err)
	}

	userPrompt += "\n\nOriginal " + lang.Name() + " source for reference:\n" + sourceStr

	systemPrompt := c.resolveSystemPrompt(ctx, lang, sourceStr)

	return &PromptResult{
		Language:     lang.Name(),
		File:         filename,
		Mode:         "ast-rewrite-codegen",
		Path:         "llm-only",
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
	}, nil
}

// buildIRPrompts builds LLM prompts from an adapted IR module.
func (c *Converter) buildIRPrompts(ctx context.Context, lang languages.DeterministicLanguage, mod *ir.Module, sourceStr, filename string, fr *debug.FileRecorder) (*PromptResult, error) {
	systemPrompt := c.resolveSystemPrompt(ctx, lang, sourceStr)

	userPrompt, err := lang.ConvertModulePrompt(mod)
	if err != nil {
		fr.SetError(err)
		return nil, fmt.Errorf("build prompt: %w", err)
	}

	// Add original source as context
	userPrompt += "\n\nOriginal " + lang.Name() + " source for reference:\n" + sourceStr

	fr.RecordSystemPrompt(systemPrompt)
	fr.RecordUserPrompt(userPrompt)

	return &PromptResult{
		Language:     lang.Name(),
		File:         filename,
		Mode:         "deterministic (LLM fallback)",
		Path:         "deterministic",
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
	}, nil
}

// extractJSON attempts to extract a JSON object or array from a potentially
// markdown-wrapped response.
func extractJSON(raw string) string {
	raw = strings.TrimSpace(raw)

	// Strip markdown code fences
	if after, ok := strings.CutPrefix(raw, "```json"); ok {
		raw = strings.TrimSuffix(strings.TrimSpace(after), "```")
		raw = strings.TrimSpace(raw)
	} else if after, ok := strings.CutPrefix(raw, "```"); ok {
		raw = strings.TrimSuffix(strings.TrimSpace(after), "```")
		raw = strings.TrimSpace(raw)
	}

	// Find first { or [ and last } or ]
	start := -1

	for i, c := range raw {
		if c == '{' || c == '[' {
			start = i
			break
		}
	}

	if start < 0 {
		return raw
	}

	end := -1

	for i := len(raw) - 1; i >= start; i-- {
		if raw[i] == '}' || raw[i] == ']' {
			end = i + 1
			break
		}
	}

	if end < 0 {
		return raw
	}

	return raw[start:end]
}

// extractGoCode strips markdown code fences if Claude wraps the output.
func extractGoCode(raw string) string {
	raw = strings.TrimSpace(raw)
	if after, ok := strings.CutPrefix(raw, "```go"); ok {
		raw = after
		raw = strings.TrimSuffix(raw, "```")
		raw = strings.TrimSpace(raw)
	} else if after, ok := strings.CutPrefix(raw, "```"); ok {
		raw = after
		raw = strings.TrimSuffix(raw, "```")
		raw = strings.TrimSpace(raw)
	}

	return raw
}

// computeConfidence walks the IR tree and counts deterministic vs raw nodes.
func computeConfidence(mod *ir.Module) *ConfidenceScore {
	var total, raw int
	countNodes(mod.Decls, &total, &raw)

	if total == 0 {
		return &ConfidenceScore{Ratio: 1.0}
	}

	det := total - raw

	return &ConfidenceScore{
		TotalNodes:         total,
		DeterministicNodes: det,
		RawNodes:           raw,
		Ratio:              float64(det) / float64(total),
	}
}

// countNodes recursively counts IR nodes, tracking raw (LLM-needed) nodes.
func countNodes(nodes []ir.Node, total, raw *int) {
	for _, n := range nodes {
		*total++
		switch v := n.(type) {
		case *ir.RawStmt:
			*raw++
		case *ir.ExprStmt:
			if _, ok := v.Expr.(*ir.RawExpr); ok {
				*raw++
			}
		case *ir.FuncDecl:
			countNodes(v.Body, total, raw)
		case *ir.TypeDecl:
			for _, m := range v.Methods {
				*total++
				countNodes(m.Body, total, raw)
			}
		case *ir.IfStmt:
			countNodes(v.Then, total, raw)
			countNodes(v.Else, total, raw)
		case *ir.ForStmt:
			countNodes(v.Body, total, raw)
		case *ir.RangeStmt:
			countNodes(v.Body, total, raw)
		case *ir.SwitchStmt:
			for _, c := range v.Cases {
				countNodes(c.Body, total, raw)
			}
		case *ir.Block:
			countNodes(v.Stmts, total, raw)
		case *ir.ReturnStmt:
			for _, e := range v.Values {
				if _, ok := e.(*ir.RawExpr); ok {
					*raw++
				}
			}
		}
	}
}

// formatGoCode runs goimports-style formatting on the generated Go source.
func formatGoCode(src string) (string, error) {
	out, err := imports.Process("output.go", []byte(src), nil)
	if err != nil {
		return "", fmt.Errorf("goimports: %w", err)
	}

	return string(out), nil
}
