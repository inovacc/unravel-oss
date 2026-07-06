/*
Copyright (c) 2026 Security Research
*/
package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	pkgmcp "github.com/inovacc/unravel-oss/pkg/mcp"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestForensicClient_NoSession(t *testing.T) {
	SetSession(nil, quietLogger())
	c := ForensicClient()
	_, err := c.Summarize(context.Background(), "x")
	if err == nil {
		t.Fatal("expected nil-client err")
	}
	if !strings.Contains(err.Error(), "forensic: no MCP client wired") {
		t.Fatalf("want forensic nil-client message, got %v", err)
	}
}

func TestForensicClient_WithSession(t *testing.T) {
	resetSession(t)
	ss := newStubHost(t, func(_ context.Context, _ *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error) {
		return &gomcp.CreateMessageResult{
			Content: &gomcp.TextContent{Text: "summary-bytes"},
			Model:   "test-model",
			Role:    "assistant",
		}, nil
	})
	SetSession(ss, quietLogger())

	c := ForensicClient()
	body, err := c.Summarize(context.Background(), "p")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(body) != "summary-bytes" {
		t.Fatalf("body=%q want summary-bytes", body)
	}
}

func TestFridaClient_NoSession(t *testing.T) {
	SetSession(nil, quietLogger())
	c := FridaClient()
	_, err := c.EnrichScript(context.Background(), "x")
	if err == nil {
		t.Fatal("expected nil-client err")
	}
	if !strings.Contains(err.Error(), "enrich: no MCP client wired") {
		t.Fatalf("want enrich nil-client message, got %v", err)
	}
}

func TestFridaClient_WithSession(t *testing.T) {
	resetSession(t)
	canned := `{"header_summary":"ok","hooks":[{"id":"h1","summary":"s","why_it_matters":"w","watch_for":"f","expected":{}}]}`
	ss := newStubHost(t, func(_ context.Context, _ *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error) {
		return &gomcp.CreateMessageResult{
			Content: &gomcp.TextContent{Text: canned},
			Model:   "test-model",
			Role:    "assistant",
		}, nil
	})
	SetSession(ss, quietLogger())

	c := FridaClient()
	out, err := c.EnrichScript(context.Background(), "p")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out.HeaderSummary != "ok" {
		t.Fatalf("HeaderSummary=%q want ok", out.HeaderSummary)
	}
	if len(out.Hooks) != 1 || out.Hooks[0].ID != "h1" {
		t.Fatalf("Hooks unexpected: %+v", out.Hooks)
	}
}

func TestFridaClient_MalformedJSON(t *testing.T) {
	resetSession(t)
	ss := newStubHost(t, func(_ context.Context, _ *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error) {
		return &gomcp.CreateMessageResult{
			Content: &gomcp.TextContent{Text: "not json"},
			Model:   "test-model",
			Role:    "assistant",
		}, nil
	})
	SetSession(ss, quietLogger())

	c := FridaClient()
	out, err := c.EnrichScript(context.Background(), "p")
	if err == nil {
		t.Fatal("expected json parse err")
	}
	if out.HeaderSummary != "" || len(out.Hooks) != 0 {
		t.Fatalf("expected zero EnrichResponse, got %+v", out)
	}
	// Light sanity check: the error chain should NOT be the no-session sentinel.
	if errors.Is(err, pkgmcp.ErrNoSession) {
		t.Fatalf("unexpected errNoSession on parse failure: %v", err)
	}
}

func TestEnrichClient_NoSession(t *testing.T) {
	SetSession(nil, quietLogger())
	c := EnrichClient()
	_, err := c.Summarize(context.Background(), "x")
	if err == nil {
		t.Fatal("expected nil-client err")
	}
	if !strings.Contains(err.Error(), "no MCP sampling client wired") {
		t.Fatalf("want llm nil-client message, got %v", err)
	}
}

func TestEnrichClient_WithSession(t *testing.T) {
	resetSession(t)
	ss := newStubHost(t, func(_ context.Context, _ *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error) {
		return &gomcp.CreateMessageResult{
			Content: &gomcp.TextContent{Text: "module-summary-text"},
			Model:   "test-model",
			Role:    "assistant",
		}, nil
	})
	SetSession(ss, quietLogger())

	c := EnrichClient()
	body, err := c.Summarize(context.Background(), "summarise this module")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(body) != "module-summary-text" {
		t.Fatalf("body=%q want module-summary-text", body)
	}
}

func TestEnrichClient_TransportError(t *testing.T) {
	resetSession(t)
	ss := newStubHost(t, func(_ context.Context, _ *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error) {
		return nil, errors.New("transport denied")
	})
	SetSession(ss, quietLogger())

	c := EnrichClient()
	_, err := c.Summarize(context.Background(), "p")
	if err == nil {
		t.Fatal("expected transport error")
	}
	if errors.Is(err, pkgmcp.ErrNoSession) {
		t.Fatalf("unexpected errNoSession on transport failure: %v", err)
	}
}
