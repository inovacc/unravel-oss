package adapt

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
)

// LLMClient abstracts the Claude API for LLM-assisted adaptation.
type LLMClient interface {
	Convert(ctx context.Context, system, user string) (string, error)
}

// NilLLMClient returns an LLMClient that always errors, signalling
// that no MCP session is wired.
func NilLLMClient() LLMClient { return nilLLMClient{} }

type nilLLMClient struct{}

func (nilLLMClient) Convert(_ context.Context, _, _ string) (string, error) {
	return "", errors.New("transpile/adapt: no MCP sampling client wired")
}

// Engine orchestrates the three adaptation strategies: rules, heuristics, and LLM.
type Engine struct {
	rules      *RuleSet
	heuristics []*Heuristic
	llm        LLMClient
	logger     *slog.Logger
	useLLM     bool
}

// Option configures the adaptation engine.
type Option func(*Engine)

// WithLLM enables LLM-assisted adaptation for complex patterns.
func WithLLM(client LLMClient) Option {
	return func(e *Engine) {
		e.llm = client
		e.useLLM = true
	}
}

// WithRuleSet provides a custom rule set.
func WithRuleSet(rs *RuleSet) Option {
	return func(e *Engine) {
		e.rules = rs
	}
}

// WithHeuristics provides a custom set of heuristics.
func WithHeuristics(h []*Heuristic) Option {
	return func(e *Engine) {
		e.heuristics = h
	}
}

// NewEngine creates a new adaptation engine.
func NewEngine(logger *slog.Logger, opts ...Option) *Engine {
	e := &Engine{
		rules:      NewRuleSet(),
		heuristics: DefaultHeuristics(),
		logger:     logger,
	}
	for _, opt := range opts {
		opt(e)
	}

	return e
}

// Adapt transforms an IR module by applying rules, heuristics, and optionally LLM.
func (e *Engine) Adapt(_ context.Context, mod *ir.Module) *ir.Module {
	e.logger.Info("adapting IR module", "source", mod.SourceFile, "decls", len(mod.Decls))

	// Phase 1: Apply heuristics to all nodes
	mod.Decls = e.applyHeuristics(mod.Decls)

	// Phase 2: Rules are applied at the prompt level (enriching system prompt)
	// They don't modify IR directly but guide the LLM fallback.

	e.logger.Info("adaptation complete", "decls", len(mod.Decls))

	return mod
}

// applyHeuristics walks the IR tree and applies matching heuristics.
func (e *Engine) applyHeuristics(nodes []ir.Node) []ir.Node {
	result := make([]ir.Node, 0, len(nodes))

	for _, node := range nodes {
		transformed := e.transformNode(node)
		result = append(result, transformed)
	}

	return result
}

// transformNode applies heuristics to a single node and recurses into children.
func (e *Engine) transformNode(node ir.Node) ir.Node {
	// Try each heuristic
	for _, h := range e.heuristics {
		if h.Match(node) {
			e.logger.Debug("heuristic matched", "heuristic", h.Name)
			node = h.Apply(node)
		}
	}

	// Recurse into child nodes
	switch n := node.(type) {
	case *ir.FuncDecl:
		n.Body = e.applyHeuristics(n.Body)
	case *ir.TypeDecl:
		for i, m := range n.Methods {
			n.Methods[i] = e.transformNode(m).(*ir.FuncDecl)
		}
	case *ir.IfStmt:
		n.Then = e.applyHeuristics(n.Then)
		n.Else = e.applyHeuristics(n.Else)
	case *ir.ForStmt:
		n.Body = e.applyHeuristics(n.Body)
	case *ir.RangeStmt:
		n.Body = e.applyHeuristics(n.Body)
	case *ir.SwitchStmt:
		for _, c := range n.Cases {
			c.Body = e.applyHeuristics(c.Body)
		}
	case *ir.Block:
		n.Stmts = e.applyHeuristics(n.Stmts)
	}

	return node
}

// NeedsLLMFallback checks if an IR node is too complex for deterministic codegen.
func (e *Engine) NeedsLLMFallback(node ir.Node) bool {
	switch n := node.(type) {
	case *ir.RawStmt:
		return n.Text != "" && n.Comment == ""
	case *ir.RawExpr:
		return true
	case *ir.FuncDecl:
		// Functions with raw statements in their body need LLM help
		if slices.ContainsFunc(n.Body, e.NeedsLLMFallback) {
			return true
		}
	}

	return false
}

// DetectedLibraries returns rule names matching the includes found in source.
func (e *Engine) DetectedLibraries(includes []string) []string {
	return e.rules.MatchIncludes(includes)
}
