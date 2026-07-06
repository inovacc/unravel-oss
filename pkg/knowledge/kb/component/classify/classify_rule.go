/*
Copyright (c) 2026 Security Research

RuleClassifier — the rule-registry classifier lifted intact from Phase 31's
inline component.Apply call. Phase 45 / LLMC-02 wraps it behind the
Classifier strategy interface so the MCP path can compose with it via
the composite{primary,fallback} wrapper.

This is a behavior-preserving lift: every prior classify.Run caller still
sees identical bucket counts, confidences, evidence strings, and
classifier='rule' rows — just routed through clf.Classify instead of a
direct component.Apply invocation.
*/
package classify

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

// RuleClassifier wraps the pure-Go rule registry (component.Apply) behind
// the Classifier interface. Zero-value usable; no fields, no constructor.
type RuleClassifier struct{}

// Name implements Classifier.
func (RuleClassifier) Name() string { return "rule" }

// PromptVersion implements Classifier. Rule path has no prompt; returns "".
func (RuleClassifier) PromptVersion() string { return "" }

// Classify implements Classifier by delegating to component.Apply. The
// returned Result.Classifier is whatever component.Apply chose ("rule" or
// "heuristic"), preserving the v1 distinction so downstream UPSERT
// preservation rules (D-31-NO-COMPONENT-DELETES-ON-RECLASSIFY) keep
// working unchanged.
func (RuleClassifier) Classify(_ context.Context, mod ModuleRow) (component.Result, error) {
	return component.Apply(component.Module{
		ID:          mod.ID,
		Name:        mod.Name,
		Path:        mod.Path,
		SymbolsJSON: mod.SymbolsJSON,
	}), nil
}
