/*
Copyright (c) 2026 Security Research

MCPClassifier — the LLM-backed Classifier implementation that delegates to
an MCP sampling/createMessage adapter (internal/mcp.ClassifyClient) for
per-module verdicts. Phase 45 / LLMC-02.

D-45-MCP-CLASSIFIER-PER-MODULE-ISOLATION: errors from ClassifyModule are
returned to the caller; the composite wrapper converts them into a WARN
log + RuleClassifier fallback for that single module. No batching, no
internal retry: ctx cancellation is authoritative.

D-45-PROMPT-VERSIONING: the prompt template is embedded via embed.FS at
prompts/v1.tmpl; PromptVersion() returns "v1". The version is persisted
into module_components.prompt_version on classifier='llm' rows so future
gate analyses can scope precision metrics by prompt revision.
*/
package classify

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"text/template"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

//go:embed prompts/v1.tmpl
var promptV1Template string

// promptV1 is parsed once at init time. Nil-safe: parse failure panics at
// package init (build-time guarantee that the template is well-formed).
var promptV1 = template.Must(template.New("classify_v1").Parse(promptV1Template))

// MCPClassifier delegates per-module classification to an MCP host via
// ClassifyMCPClient. Constructor pattern keeps Client injectable for tests
// (see mcp_classifier_test.go).
type MCPClassifier struct {
	// Client is the MCP sampling adapter. nil is treated as a fatal
	// configuration error in Classify (returns ErrNoClient); use
	// internal/mcp.ClassifyClient() for production wiring.
	Client ClassifyMCPClient
}

// ErrNoClient is returned by Classify when MCPClassifier.Client is nil.
// Callers (composite wrapper) treat this as any other primary error and
// fall back. Explicit-mode callers (--classifier=mcp) surface it.
var ErrNoClient = errors.New("classify mcp: no ClassifyMCPClient wired")

// Name implements Classifier.
func (MCPClassifier) Name() string { return "mcp" }

// PromptVersion implements Classifier.
func (MCPClassifier) PromptVersion() string { return "v1" }

// Classify implements Classifier by:
//  1. Rendering the v1 prompt template against mod.
//  2. Calling Client.ClassifyModule with the rendered prompt.
//  3. Parsing the JSON response into component.Result.
//
// On ANY error (missing client, render fail, transport fail, empty body,
// malformed JSON, missing required fields) returns (zero, err). The
// composite wrapper converts that into a fallback to RuleClassifier per
// D-45-MCP-CLASSIFIER-PER-MODULE-ISOLATION.
func (m MCPClassifier) Classify(ctx context.Context, mod ModuleRow) (component.Result, error) {
	if m.Client == nil {
		return component.Result{}, ErrNoClient
	}

	var buf bytes.Buffer
	if err := promptV1.Execute(&buf, mod); err != nil {
		return component.Result{}, fmt.Errorf("render prompt: %w", err)
	}

	body, err := m.Client.ClassifyModule(ctx, buf.String())
	if err != nil {
		return component.Result{}, fmt.Errorf("classify module: %w", err)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return component.Result{}, fmt.Errorf("%w: empty response body (host may not have wired sampling)", ErrNoClient)
	}

	// Parse only the fields we trust the model to populate. Confidence
	// and evidence may be omitted; the verdict requires at minimum a
	// non-empty component string from the locked taxonomy.
	var raw struct {
		Component  string  `json:"component"`
		Confidence float32 `json:"confidence"`
		Evidence   string  `json:"evidence"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return component.Result{}, fmt.Errorf("parse response: %w", err)
	}

	bucket := strings.ToLower(strings.TrimSpace(raw.Component))
	if !isValidBucket(bucket) {
		return component.Result{}, fmt.Errorf("response bucket %q not in taxonomy", raw.Component)
	}

	return component.Result{
		Component:  bucket,
		Confidence: raw.Confidence,
		Classifier: "llm",
		Evidence:   raw.Evidence,
	}, nil
}

// isValidBucket reports whether bucket is one of component.Buckets. Defensive
// check against the model hallucinating a new taxonomy entry.
func isValidBucket(bucket string) bool {
	return slices.Contains(component.Buckets, bucket)
}
