/*
Copyright (c) 2026 Security Research

Phase 12: pkg/ai is now a thin MCP-delegation shim. The direct Anthropic
HTTP path (X-Api-Key / Bearer token, /v1/messages, SSE streaming) was
removed. All AI calls route through the internal/mcp sampling seam wired
in Phase 11. In standalone CLI mode (no MCP host), calls return a
"no MCP client wired" error so callers WARN-degrade gracefully.

Deprecated: prefer internal/mcp.ForensicClient() for new code. The
exported surface here is preserved for the existing 10 consumer files
(see 12-API-CONTRACT.md) plus 4 transitive importers.
*/
package ai

import (
	"context"
	"errors"
	"fmt"
)

// MCPClient is the structural interface this shim delegates to. It mirrors
// pkg/MCPClient byte-for-byte; defining it locally avoids an import
// cycle (pkg/forensic transitively imports pkg/dissect which imports pkg/ai).
// Any MCPClient value satisfies this interface implicitly because
// Go interfaces are structural.
type MCPClient interface {
	Summarize(ctx context.Context, prompt string) ([]byte, error)
}

// Client is a thin shim over the internal/mcp sampling seam.
type Client struct {
	model string
}

// Option configures the shim Client.
type Option func(*Client)

// WithModel records the requested model. The MCP host ultimately
// chooses the model; this value is informational only.
func WithModel(model string) Option {
	return func(c *Client) { c.model = model }
}

// WithBaseURL is a no-op shim retained for source compatibility.
// Phase 12 removed the direct HTTP path.
func WithBaseURL(string) Option {
	return func(*Client) {}
}

// WithSessionKey is a no-op shim retained for source compatibility.
// Phase 12 removed direct authentication; the MCP host handles it.
func WithSessionKey(string) Option {
	return func(*Client) {}
}

// NewClient creates a shim Client. Never returns an error — auth and
// transport are owned by the MCP host now (or, in standalone mode, the
// resolver returns a nil client that errors gracefully on call).
func NewClient(opts ...Option) (*Client, error) {
	c := &Client{model: "claude-sonnet-4-5-20250929"}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Response holds the parsed AI response. Field shape preserved from the
// pre-Phase-12 HTTP client.
type Response struct {
	Content    string `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      Usage  `json:"usage"`
}

// Usage contains token counts. Always zero in shim mode (the MCP host
// reports its own usage; we don't surface it through this seam yet).
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// AnalysisResponse is the streaming-equivalent response. Phase 12 has no
// streaming MCP equivalent, so this is filled once with the full content.
type AnalysisResponse struct {
	Content    string `json:"content"`
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Usage      Usage  `json:"usage"`
}

// StreamCallback is called with each text chunk. In shim mode, called
// exactly once with the full content (graceful non-streaming fallback).
type StreamCallback func(chunk string)

// mcpResolver is the package-level resolver for the live MCP client.
// Defaults to a nil resolver returning the standardized error message
// for graceful WARN-degrade in standalone CLI mode.
var mcpResolver = func() MCPClient { return nilMCPClient{} }

// SetMCPClient injects the live MCP client. Called once from the MCP
// server bootstrap path (cmd/mcp.go AfterConnect, next to SetSession).
// Passing nil resets to the default graceful-degrade resolver.
func SetMCPClient(c MCPClient) {
	if c == nil {
		mcpResolver = func() MCPClient { return nilMCPClient{} }
		return
	}
	mcpResolver = func() MCPClient { return c }
}

// nilMCPClient is the default resolver when no MCP host is wired.
type nilMCPClient struct{}

// Summarize implements MCPClient with the standardized error.
func (nilMCPClient) Summarize(context.Context, string) ([]byte, error) {
	return nil, errors.New("no MCP client wired (run inside `unravel mcp serve`)")
}

// Analyze sends a system prompt + user content via the MCP sampling seam.
func (c *Client) Analyze(ctx context.Context, systemPrompt, userContent string) (*Response, error) {
	prompt := fmt.Sprintf("%s\n\n%s", systemPrompt, userContent)
	body, err := mcpResolver().Summarize(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("ai: %w", err)
	}
	return &Response{Content: string(body), StopReason: "end_turn"}, nil
}

// AnalyzeStream calls Analyze and emits the full content in one callback
// invocation. Phase 12 has no streaming MCP equivalent.
func (c *Client) AnalyzeStream(ctx context.Context, systemPrompt, userPrompt string, cb StreamCallback) (*AnalysisResponse, error) {
	resp, err := c.Analyze(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}
	if cb != nil {
		cb(resp.Content)
	}
	return &AnalysisResponse{
		Content:    resp.Content,
		Model:      c.model,
		StopReason: resp.StopReason,
		Usage:      resp.Usage,
	}, nil
}
