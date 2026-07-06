/*
Copyright (c) 2026 Security Research

Classifier mode selector — turns the --classifier=auto|rule|mcp CLI flag
into a concrete Classifier strategy. Phase 45 / LLMC-02.

D-45-CLASSIFY-FALLBACK-ORDER: explicit modes ("rule", "mcp") never
fall back; "auto" composes MCP→rule when the host advertises sampling
capability, otherwise returns plain rule.

The hasSampling probe is injected as a function so tests can drive both
branches without spinning up a real internal/mcp session. The CLI wires
in internal/mcp.HasSamplingCapability + internal/mcp.ClassifyClient.
*/
package classify

import (
	"context"
	"errors"
	"fmt"
)

// SelectOptions parameterizes Select for testability and to keep the
// classify package free of an internal/mcp import (D-45-CLASSIFY-NO-DIRECT-CLIENT).
type SelectOptions struct {
	// Mode is the raw flag value: "auto" (or ""), "rule", or "mcp".
	Mode string

	// HasSampling reports whether the MCP host advertises sampling
	// capability. nil => treat as false. Production wiring passes
	// internal/mcp.HasSamplingCapability.
	HasSampling func(ctx context.Context) bool

	// MCPClient builds the ClassifyMCPClient lazily. nil => MCP modes
	// receive a nil client and surface ErrNoClient on first Classify.
	// Production wiring passes a closure returning internal/mcp.ClassifyClient().
	MCPClient func() ClassifyMCPClient
}

// Select resolves the user's --classifier flag into a Classifier strategy.
// Returns the chosen Classifier and a "source" string suitable for one-shot
// log emission ("flag" for explicit modes, "auto" for the auto branch).
//
// Errors only on an unrecognized mode string; other inputs gracefully
// degrade per D-45-CLASSIFY-FALLBACK-ORDER.
func Select(ctx context.Context, opts SelectOptions) (Classifier, string, error) {
	mode := opts.Mode
	switch mode {
	case "rule":
		return RuleClassifier{}, "flag", nil
	case "mcp":
		c := callIfNotNil(opts.MCPClient)
		if c == nil {
			return nil, "", errors.New("--classifier=mcp requires an MCP session; run via `unravel mcp serve` or use --classifier=auto")
		}
		return MCPClassifier{Client: c}, "flag", nil
	case "", "auto":
		hasCap := false
		if opts.HasSampling != nil {
			hasCap = opts.HasSampling(ctx)
		}
		if !hasCap {
			return RuleClassifier{}, "auto", nil
		}
		return NewComposite(
			MCPClassifier{Client: callIfNotNil(opts.MCPClient)},
			RuleClassifier{},
		), "auto", nil
	default:
		return nil, "", fmt.Errorf("unknown --classifier mode %q (expected auto|rule|mcp)", mode)
	}
}

// callIfNotNil invokes fn when non-nil. Keeps the lazy-resolver indirection
// out of every call site.
func callIfNotNil(fn func() ClassifyMCPClient) ClassifyMCPClient {
	if fn == nil {
		return nil
	}
	return fn()
}
