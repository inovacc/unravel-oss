/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"context"
	"fmt"
)

// Options configures Reconstruct.
type Options struct {
	// UseMCP enables Pass 2 (MCP fallback) when Pass 1 yields zero
	// modules. Default false; explicit-only opt-in per D-18.
	UseMCP bool
	// AIClient is the Beautifier used for Pass 2. Required when
	// UseMCP is true; ignored otherwise.
	AIClient Beautifier
}

// Result is the top-level Reconstruct return value.
type Result struct {
	Kind    Kind             `json:"kind"`
	Modules []ModuleProposal `json:"modules"`
	Errors  []string         `json:"errors,omitempty"`
	UsedMCP bool             `json:"used_mcp"`
	// RunnerUp records the second-best matching recogniser when more
	// than one recogniser fingerprinted the bundle.
	RunnerUp Kind     `json:"runner_up,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// Specificity rank: webpack > esbuild > vite > rollup. The dispatcher
// honours this order; the first recogniser to return matched=true with
// at least one module wins.
var registeredRecognisers = []Recogniser{
	WebpackRecogniser{},
	EsbuildRecogniser{},
	ViteRecogniser{},
	RollupRecogniser{},
}

// Reconstruct runs the D-11 hybrid strategy:
//   - Pass 1: per-bundler pattern recognisers (specificity-ranked).
//   - Pass 2: MCP fallback when Pass 1 returned 0 modules and
//     opts.UseMCP is set.
//   - Pass 3: brace-balance validation rejects pathological proposals.
func Reconstruct(ctx context.Context, src []byte, opts Options) (out *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = &Result{Kind: KindUnknown, Errors: []string{fmt.Sprintf("reconstruct_panic: %v", r)}}
			err = nil
		}
	}()

	res := &Result{Kind: KindUnknown}

	// Pass 1: pattern recognisers. First match by specificity wins.
	var primary ModuleSet
	primaryFound := false
	for _, r := range registeredRecognisers {
		set, ok := r.Match(src)
		if !ok {
			continue
		}
		if !primaryFound {
			primary = set
			primaryFound = true
			continue
		}
		// Already found a primary — record runner-up.
		if res.RunnerUp == "" {
			res.RunnerUp = set.Kind
		}
	}

	if primaryFound {
		res.Kind = primary.Kind
		res.Evidence = primary.Evidence
	}

	proposals := []ModuleProposal{}
	if primaryFound {
		proposals = append(proposals, primary.Modules...)
	}

	// Pass 2: MCP fallback when pattern recognisers carved zero modules.
	if len(proposals) == 0 && opts.UseMCP && opts.AIClient != nil {
		mcpProps, mcpErr := MCPProposeBoundaries(ctx, opts.AIClient, src)
		if mcpErr != nil {
			res.Errors = append(res.Errors, mcpErr.Error())
		} else {
			proposals = append(proposals, mcpProps...)
			res.UsedMCP = true
		}
	}

	// Pass 3: brace-balance validation.
	survivors, dropped := ValidateProposals(src, proposals)
	res.Modules = survivors
	for _, d := range dropped {
		res.Errors = append(res.Errors, d)
	}

	return res, nil
}
