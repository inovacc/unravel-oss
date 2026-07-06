/*
Copyright (c) 2026 Security Research
*/
package rearm

import "context"

// Beautifier is the MCP-sampling seam (same signature as the existing
// dissectAIBeautifier). rearm never imports internal/ai or the anthropic SDK.
type Beautifier interface {
	Beautify(ctx context.Context, prompt, input string) (string, error)
}

type Candidate struct {
	Lang          string // "js" | "dotnet" | "java" | "go"
	ModuleRef     string
	Source        string
	Size          int
	HeuristicHint string
	Signal        int
}

type Bounds struct {
	MaxModules     int
	MaxModuleBytes int
	MaxTotalTokens int
}

func DefaultBounds() Bounds {
	return Bounds{MaxModules: 8, MaxModuleBytes: 256 * 1024, MaxTotalTokens: 200_000}
}

type Options struct {
	Bounds   Bounds
	JSObfMin int
}

func DefaultOptions() Options { return Options{Bounds: DefaultBounds(), JSObfMin: 60} }
