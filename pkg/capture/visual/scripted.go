/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// ScriptedStep is one entry in the scenario JSON file. The action verb set is
// closed: {click, type, wait, capture} (T-08-03). Unknown verbs are rejected
// at load time.
type ScriptedStep struct {
	Action   string `json:"action"`
	Selector string `json:"selector,omitempty"`
	Value    string `json:"value,omitempty"`
	MS       int    `json:"ms,omitempty"`
	Slug     string `json:"slug,omitempty"`
}

// allowedActions is the closed set per T-08-03. Any verb outside this set
// MUST be rejected during scenario parsing.
var allowedActions = map[string]bool{
	"click":   true,
	"type":    true,
	"wait":    true,
	"capture": true,
}

// loadScenario reads scenario JSON from path, parses, and validates every
// step's action against the closed set (T-08-03).
func loadScenario(path string) ([]ScriptedStep, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scenario: %w", err)
	}
	return parseScenario(b)
}

func parseScenario(b []byte) ([]ScriptedStep, error) {
	// Accept either {"steps":[...]} or a bare [...] array.
	trimmed := strings.TrimSpace(string(b))
	var steps []ScriptedStep
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(b, &steps); err != nil {
			return nil, fmt.Errorf("parse scenario array: %w", err)
		}
	} else {
		var wrap struct {
			Steps []ScriptedStep `json:"steps"`
		}
		if err := json.Unmarshal(b, &wrap); err != nil {
			return nil, fmt.Errorf("parse scenario object: %w", err)
		}
		steps = wrap.Steps
	}
	for i, s := range steps {
		if !allowedActions[s.Action] {
			return nil, fmt.Errorf("scenario step %d: action %q not allowed (allowed: click|type|wait|capture)", i, s.Action)
		}
	}
	return steps, nil
}

// runScriptedStep executes one validated step. Per T-08-03 unknown actions
// cannot reach this function (loadScenario rejects them); a defensive guard
// remains for safety.
func (o *Orchestrator) runScriptedStep(ctx context.Context, step ScriptedStep) error {
	switch step.Action {
	case "click":
		expr := fmt.Sprintf(`(function(){var el=document.querySelector(%q); if(el) el.click(); return !!el;})()`, step.Selector)
		_, err := o.cli.Eval(ctx, expr, cdp.EvalOpts{UserGesture: true})
		return err
	case "type":
		expr := fmt.Sprintf(`(function(){var el=document.querySelector(%q); if(!el) return false; el.focus(); el.value=%q; el.dispatchEvent(new Event('input',{bubbles:true})); return true;})()`, step.Selector, step.Value)
		_, err := o.cli.Eval(ctx, expr, cdp.EvalOpts{UserGesture: true})
		return err
	case "wait":
		d := time.Duration(step.MS) * time.Millisecond
		if d <= 0 {
			d = 100 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
			return nil
		}
	case "capture":
		slug := step.Slug
		if slug == "" {
			slug = "scripted"
		}
		return o.captureState(ctx, StateEvent{Type: "route", Slug: slug})
	default:
		return fmt.Errorf("action %q not allowed", step.Action)
	}
}
