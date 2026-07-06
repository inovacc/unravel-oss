/*
Copyright (c) 2026 Security Research

Phase 84 Task 6 supplemental analyzer that auto-triggers AI-assisted
deobfuscation "rearm" on Electron / Tauri / ASAR dissect runs. Mirrors
the analyze_dotnet_decompile.go / analyze_java_beautify.go
try-and-downgrade AI client construction.

MCP-only invariant: pkg/obfuscation/rearm never imports internal/ai or
the anthropic SDK. Only this dissect analyzer constructs ai.NewClient(),
which is the already-allowed pattern (same as analyze_dotnet_decompile.go).

Import-cycle note: pkg/obfuscation/rearm imports pkg/dissect (for
DissectResult), so dissect cannot import rearm. The orchestrator is
invoked via dissect.ObfuscationRearmHook, which rearm.init() installs.

Decision A: when the AI client is unavailable, candidates are still
recorded (rearm.Run downgrades each module to a not-rearmed status via
the unavailableBeautifier closure) rather than skipping the report.
*/
package dissect

import (
	"context"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/detect"
)

func init() {
	RegisterSupplementalAnalyzer(analyzeObfuscationRearm,
		detect.TypeElectronApp, detect.TypeTauriApp, detect.TypeASAR,
		detect.TypeUWPApp, detect.TypeMSIX)
}

// analyzeObfuscationRearm builds the production AI beautifier (the exact
// dissectAIBeautifier construction reused from analyze_dotnet_decompile.go)
// and invokes the rearm orchestrator via the reverse-registration hook.
// Failures are non-fatal (rearm appends to r.Errors). The defer/recover
// guards the AI boundary so a panic never aborts the dissect run.
func analyzeObfuscationRearm(r *DissectResult, _ string, _ Options) {
	defer func() {
		if rec := recover(); rec != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("obfuscation rearm panic: %v", rec))
		}
	}()

	if ObfuscationRearmHook == nil {
		return
	}

	ctx := context.Background()

	// AI client: try-and-downgrade pattern (mirrors dotnet/java
	// supplementals). dissectAIBeautifier already satisfies the
	// rearm.Beautifier shape (identical Beautify signature).
	var beautify func(ctx context.Context, prompt, input string) (string, error)
	if client, cerr := ai.NewClient(); cerr == nil {
		b := &dissectAIBeautifier{c: client}
		beautify = b.Beautify
	} else {
		beautify = unavailableBeautify
	}

	ObfuscationRearmHook(ctx, r, beautify)
}

// unavailableBeautify is the no-AI fallback. rearm.Run records each
// candidate with a not-rearmed status when Beautify errors (decision A).
func unavailableBeautify(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("ai client unavailable")
}
