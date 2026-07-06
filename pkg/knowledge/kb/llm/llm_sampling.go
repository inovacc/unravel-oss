/*
Copyright (c) 2026 Security Research

SamplingClient is the seam between kbllm.Call and internal/mcp.
Defined here (pkg side) so internal/mcp can import this package's interface
without creating an import cycle (pkg may not import internal/mcp).

D-09 invariant preserved: no anthropic SDK imports here.
*/
package llm

import (
	"context"
	"errors"
)

// SamplingClient abstracts the MCP sampling reverse-RPC so that kbllm.Call
// can route through Claude Code's warm session instead of spawning a fresh
// subprocess per call.
type SamplingClient interface {
	Summarize(ctx context.Context, prompt string) ([]byte, error)
}

// NilSamplingClient returns a SamplingClient that always errors, signalling
// that no MCP session is wired and kbllm.Call should fall back to the
// subprocess path.
func NilSamplingClient() SamplingClient { return nilSamplingClient{} }

type nilSamplingClient struct{}

func (nilSamplingClient) Summarize(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("llm: no MCP sampling client wired")
}

// SetSamplingResolver installs the lazy resolver used by Call to obtain a
// SamplingClient. Pass nil to disable the sampling path (subprocess fallback
// only). Called from cmd/ during MCP server startup after SetSession; the llm
// package itself does not import internal/mcp to avoid an import cycle.
func SetSamplingResolver(fn func() SamplingClient) {
	samplingResolver = fn
}
