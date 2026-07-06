/*
Copyright (c) 2026 Security Research

Classifier strategy interface for Phase 45 / LLMC-02.

Defines the narrow seam that classify.Run consumes: a per-module verdict
producer with a stable name + optional prompt-version metadata. Concrete
implementations live in classify_rule.go (rule registry), classify_mcp_classifier.go
(MCP sampling/createMessage), and classify_composite.go (primary→fallback).

D-45-CLASSIFY-V2-INTERFACE: this interface is the only contract; classify.Run
must not branch on concrete classifier types.
*/
package classify

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

// Classifier is the per-module verdict producer consumed by classify.Run.
//
// Implementations MUST:
//   - Treat ctx cancellation as authoritative.
//   - Return (component.Result, nil) on success.
//   - Return (zero, err) on any failure; the composite wrapper handles
//     fallback per D-45-MCP-CLASSIFIER-PER-MODULE-ISOLATION.
type Classifier interface {
	// Name is a stable identifier ("rule" | "mcp"). Persisted into
	// module_components.classifier; see D-31-NO-COMPONENT-DELETES-ON-RECLASSIFY.
	Name() string

	// Classify returns the verdict for a single module.
	Classify(ctx context.Context, mod ModuleRow) (component.Result, error)

	// PromptVersion returns the embedded prompt revision when applicable
	// ("v1" for MCP). Returns "" for rule/heuristic classifiers; the
	// caller writes NULL to module_components.prompt_version in that case.
	PromptVersion() string
}
