/*
Copyright (c) 2026 Security Research

Composite Classifier — wraps a primary + fallback so per-module failures
in the primary path degrade silently to the fallback. Phase 45 / LLMC-02.

D-45-CLASSIFY-FALLBACK-ORDER: --classifier=auto resolves to
composite{primary: MCPClassifier, fallback: RuleClassifier} when the host
advertises sampling capability. --classifier=mcp returns a bare
MCPClassifier (no fallback) so the user sees the underlying error.

D-45-MCP-CLASSIFIER-PER-MODULE-ISOLATION: the composite isolates failure
at the MODULE level — one bad MCP call cannot poison subsequent modules,
and one bad module never fails the whole Run.
*/
package classify

import (
	"context"
	"log/slog"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

// composite chains primary → fallback. Name() returns the primary's name
// so module_components rows still reflect the chosen path; rows that
// actually fell back are tagged via the embedded fallback's classifier
// string (component.Result.Classifier) returned from its Classify call.
type composite struct {
	primary  Classifier
	fallback Classifier
}

// NewComposite builds a composite Classifier. Either side may be nil-safe
// at construction; nil values are caught at Classify time. Provided as a
// constructor (vs. a struct literal) so future fields stay encapsulated.
func NewComposite(primary, fallback Classifier) Classifier {
	return composite{primary: primary, fallback: fallback}
}

// Name returns the primary's name; the composite is transparent for
// reporting purposes. Per-module fallback events are surfaced via
// slog.Warn inside Classify.
func (c composite) Name() string {
	if c.primary == nil {
		return "composite"
	}
	return c.primary.Name()
}

// PromptVersion returns the primary's prompt version. When the per-module
// path falls back to the secondary classifier, the row written to
// module_components is whatever the fallback returns — the caller in
// classify.Run reads PromptVersion off the *result* (Classifier field),
// not off the strategy here.
func (c composite) PromptVersion() string {
	if c.primary == nil {
		return ""
	}
	return c.primary.PromptVersion()
}

// Classify tries primary first; on any error logs WARN and delegates to
// fallback. The fallback's error (if any) is returned to the caller —
// classify.Run treats double-failure as Skipped++.
func (c composite) Classify(ctx context.Context, mod ModuleRow) (component.Result, error) {
	if c.primary != nil {
		v, err := c.primary.Classify(ctx, mod)
		if err == nil {
			return v, nil
		}
		slog.Warn("classify: primary failed, falling back",
			"primary", c.primary.Name(),
			"fallback", classifierName(c.fallback),
			"module_id", mod.ID,
			"error", err,
		)
	}
	if c.fallback == nil {
		return component.Result{}, ErrNoClient
	}
	return c.fallback.Classify(ctx, mod)
}

// classifierName is a nil-safe Name() accessor for log fields.
func classifierName(c Classifier) string {
	if c == nil {
		return "<nil>"
	}
	return c.Name()
}
