/*
Copyright (c) 2026 Security Research

Phase 84 Task 6: reverse-registration of the rearm orchestrator into
pkg/dissect. rearm imports dissect (for DissectResult), so dissect cannot
import rearm. This init() installs Run behind dissect.ObfuscationRearmHook;
the dissect supplemental analyzer builds the AI beautifier closure and
invokes the hook. The MCP-only ai.NewClient construction stays in
pkg/dissect — this package never imports internal/ai or anthropic.
*/
package rearm

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func init() {
	dissect.ObfuscationRearmHook = func(ctx context.Context, r *dissect.DissectResult, beautify func(ctx context.Context, prompt, input string) (string, error)) {
		Run(ctx, r, beautifyFunc(beautify), DefaultOptions())
	}
}

// beautifyFunc adapts a plain closure to the Beautifier interface.
type beautifyFunc func(ctx context.Context, prompt, input string) (string, error)

func (f beautifyFunc) Beautify(ctx context.Context, prompt, input string) (string, error) {
	return f(ctx, prompt, input)
}
