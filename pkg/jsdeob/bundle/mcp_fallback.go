/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/internal/ai/prompts"
)

// Beautifier is the AI-delegation surface (Pass 2). Mirrors the same
// shape used by 06-02's pkg/jsdeob.Beautifier so a single
// implementation can serve both.
type Beautifier interface {
	Beautify(ctx context.Context, prompt, input string) (string, error)
}

// Sentinels wrapping the untrusted bundle source in the Pass 2 prompt
// (T-06-04).
const (
	BundleSentinelBegin = "<BEGIN_BUNDLE>"
	BundleSentinelEnd   = "<END_BUNDLE>"
)

// mcpResponse is the strict JSON shape bundle.md instructs the model to
// return.
type mcpResponse struct {
	Modules []struct {
		Start         int     `json:"start"`
		End           int     `json:"end"`
		CandidateName *string `json:"candidate_name"`
	} `json:"modules"`
}

// MCPProposeBoundaries asks the AI for module boundaries on a bundle
// that pattern recognisers failed on. Returns proposals tagged
// Source="mcp". Errors wrap "mcp_parse_error" when the model output is
// not valid JSON matching the schema.
func MCPProposeBoundaries(ctx context.Context, b Beautifier, src []byte) (out []ModuleProposal, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			err = fmt.Errorf("mcp_propose_panic: %v", r)
		}
	}()

	if b == nil {
		return nil, fmt.Errorf("mcp_propose: nil beautifier")
	}

	// Wrap input between sentinels (T-06-04). The prompt body itself
	// already contains the sentinels; we pass the bundle body as input
	// so the production Beautifier implementation can substitute it
	// where the prompt expects it. Keep wrapping here as defence in
	// depth in case the implementation concatenates raw.
	wrapped := BundleSentinelBegin + "\n" + string(src) + "\n" + BundleSentinelEnd

	resp, err := b.Beautify(ctx, prompts.BundlePrompt(), wrapped)
	if err != nil {
		return nil, fmt.Errorf("mcp_propose: %w", err)
	}

	resp = strings.TrimSpace(resp)
	// Strip any markdown code fences if the model leaked them.
	resp = strings.TrimPrefix(resp, "```json")
	resp = strings.TrimPrefix(resp, "```")
	resp = strings.TrimSuffix(resp, "```")
	resp = strings.TrimSpace(resp)

	var parsed mcpResponse
	if uerr := json.Unmarshal([]byte(resp), &parsed); uerr != nil {
		return nil, fmt.Errorf("mcp_parse_error: %w", uerr)
	}

	out = make([]ModuleProposal, 0, len(parsed.Modules))
	for _, m := range parsed.Modules {
		var name string
		if m.CandidateName != nil {
			name = *m.CandidateName
		}
		out = append(out, ModuleProposal{
			Start:         m.Start,
			End:           m.End,
			CandidateName: name,
			Source:        "mcp",
		})
	}
	return out, nil
}
