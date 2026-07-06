/*
Copyright (c) 2026 Security Research
*/
package cdp

import (
	"context"
	"encoding/json"
	"fmt"
)

// EvalOpts configures Runtime.evaluate.
type EvalOpts struct {
	AwaitPromise  bool
	UserGesture   bool
	ReturnByValue bool // default true
}

// Eval invokes Runtime.evaluate and returns the JSON-serialized value, or an
// error if the script threw an exception.
func (c *Client) Eval(ctx context.Context, expr string, opts EvalOpts) (json.RawMessage, error) {
	rbv := opts.ReturnByValue
	if !rbv {
		rbv = true // default true; we always want JSON-serializable results
	}
	raw, err := c.SendAndWait(ctx, "Runtime.evaluate", map[string]any{
		"expression":    expr,
		"returnByValue": rbv,
		"awaitPromise":  opts.AwaitPromise,
		"userGesture":   opts.UserGesture,
	})
	if err != nil {
		return nil, err
	}
	var r struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *json.RawMessage `json:"exceptionDetails,omitempty"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decode Runtime.evaluate: %w", err)
	}
	if r.ExceptionDetails != nil {
		return nil, fmt.Errorf("Runtime.evaluate threw: %s", string(*r.ExceptionDetails))
	}
	return r.Result.Value, nil
}
