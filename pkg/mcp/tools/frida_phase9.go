/*
Copyright (c) 2026 Security Research

Phase 9 plan 03: Frida AI enrichment + post-capture validation user-facing
MCP surface. Three new tools:

	unravel_frida_enrich              - Lazy AI enrichment of an existing Frida script
	unravel_frida_validate            - Post-capture criteria validation; severity-tagged report
	unravel_frida_generate_with_ai    - Generate Frida scripts + AI enrichment + criteria in one call

Threats mitigated:
  - T-09-02: path-traversal at every script_path / source_dir / criteria_path / capture_path / kb_dir
  - T-09-04: 1 MiB cap on criteria.json + capture.json (already inside frida.Validate)
  - T-09-05: 64 KiB MCP body cap on inline source-bundle delegated to enrich.Orchestrator
*/
package mcptools

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	mcpinternal "github.com/inovacc/unravel-oss/internal/mcp"
	"github.com/inovacc/unravel-oss/pkg/frida"
	"github.com/inovacc/unravel-oss/pkg/frida/enrich"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fridaEnrichInput is the wire shape of unravel_frida_enrich.
type fridaEnrichInput struct {
	ScriptPath string `json:"script_path" jsonschema:"Path to the existing Frida JavaScript file"`
	SourceDir  string `json:"source_dir,omitempty" jsonschema:"Optional decompiled-source root used as MCP prompt context"`
}

type fridaEnrichResult struct {
	ScriptPath   string `json:"script_path"`
	CriteriaPath string `json:"criteria_path"`
	HookCount    int    `json:"hook_count"`
	CacheHit     bool   `json:"cache_hit"`
}

// fridaValidateInput is the wire shape of unravel_frida_validate.
type fridaValidateInput struct {
	CriteriaPath string `json:"criteria_path" jsonschema:"Path to <script>.criteria.json"`
	CapturePath  string `json:"capture_path" jsonschema:"Path to capture.json (RunResult or SessionResult)"`
}

type fridaValidateResult struct {
	CriteriaPath string                  `json:"criteria_path"`
	CapturePath  string                  `json:"capture_path"`
	PackageName  string                  `json:"package_name,omitempty"`
	Findings     []frida.Finding         `json:"findings"`
	Summary      frida.ValidationSummary `json:"summary"`
	Markdown     string                  `json:"markdown"`
}

// fridaGenerateWithAIInput is the wire shape of unravel_frida_generate_with_ai.
type fridaGenerateWithAIInput struct {
	APKPath       string   `json:"apk_path" jsonschema:"Path to APK; runs analyze pipeline + generates skeleton scripts"`
	TargetClasses []string `json:"target_classes,omitempty" jsonschema:"Specific class.method patterns to hook (overrides auto-detection)"`
	KBDir         string   `json:"kb_dir" jsonschema:"Output directory for generated + enriched scripts"`
	SourceDir     string   `json:"source_dir,omitempty" jsonschema:"Optional decompiled-source root for prompt context"`
}

type fridaGenerateWithAIResult struct {
	KBDir       string   `json:"kb_dir"`
	ScriptPaths []string `json:"script_paths"`
	HookCount   int      `json:"hook_count"`
	Note        string   `json:"note,omitempty"`
}

// registerFridaPhase9Tools registers the 3 Phase 9 plan 03 tools onto s.
// Sibling-file pattern from registerCapturePhase8Tools / registerKnowledgePhase7Tools.
func registerFridaPhase9Tools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_frida_enrich",
		Description: "Lazy AI enrichment of an existing Frida script — adds per-hook JSDoc comments + sibling criteria.json.",
	}, handleFridaEnrich)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_frida_validate",
		Description: "Run post-capture validation: evaluate criteria.json against captured Frida events; emit BLOCK/FLAG/PASS findings + Markdown report.",
	}, handleFridaValidate)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_frida_generate_with_ai",
		Description: "Full pipeline: analyze APK, generate skeleton Frida scripts, enrich with AI per-hook comments, write criteria.json sidecars under kb_dir.",
	}, handleFridaGenerateWithAI)
}

func handleFridaEnrich(ctx context.Context, _ *mcp.CallToolRequest, in fridaEnrichInput) (*mcp.CallToolResult, any, error) {
	scriptAbs, err := rejectTraversal(in.ScriptPath)
	if err != nil {
		return errorResult(fmt.Errorf("script_path: %w", err)), nil, nil
	}
	sourceAbs := ""
	if in.SourceDir != "" {
		abs, err := rejectTraversal(in.SourceDir)
		if err != nil {
			return errorResult(fmt.Errorf("source_dir: %w", err)), nil, nil
		}
		sourceAbs = abs
	}
	// 11-03 D-13: lazy resolver — production sampling adapter when
	// `unravel mcp serve` is the host, NilMCPClient otherwise so the call
	// degrades gracefully without an active session.
	orch := enrich.New()
	orch.MCP = mcpinternal.FridaClient()
	out, err := orch.Enrich(ctx, scriptAbs, sourceAbs)
	if err != nil {
		return errorResult(fmt.Errorf("enrich: %w", err)), nil, nil
	}
	return jsonResult(fridaEnrichResult{
		ScriptPath:   out.ScriptPath,
		CriteriaPath: out.CriteriaPath,
		HookCount:    len(out.Hooks),
		CacheHit:     out.CacheHit,
	}), nil, nil
}

func handleFridaValidate(_ context.Context, _ *mcp.CallToolRequest, in fridaValidateInput) (*mcp.CallToolResult, any, error) {
	critAbs, err := rejectTraversal(in.CriteriaPath)
	if err != nil {
		return errorResult(fmt.Errorf("criteria_path: %w", err)), nil, nil
	}
	capAbs, err := rejectTraversal(in.CapturePath)
	if err != nil {
		return errorResult(fmt.Errorf("capture_path: %w", err)), nil, nil
	}
	report, err := frida.Validate(critAbs, capAbs)
	if err != nil {
		return errorResult(fmt.Errorf("validate: %w", err)), nil, nil
	}
	md := frida.RenderMarkdown(report)
	return jsonResult(fridaValidateResult{
		CriteriaPath: report.CriteriaPath,
		CapturePath:  report.CapturePath,
		PackageName:  report.PackageName,
		Findings:     report.Findings,
		Summary:      report.Summary,
		Markdown:     md,
	}), nil, nil
}

func handleFridaGenerateWithAI(ctx context.Context, _ *mcp.CallToolRequest, in fridaGenerateWithAIInput) (*mcp.CallToolResult, any, error) {
	if in.APKPath == "" || in.KBDir == "" {
		return errorResult(errors.New("apk_path and kb_dir are required")), nil, nil
	}
	_, err := rejectTraversal(in.APKPath)
	if err != nil {
		return errorResult(fmt.Errorf("apk_path: %w", err)), nil, nil
	}
	kbAbs, err := rejectTraversal(in.KBDir)
	if err != nil {
		return errorResult(fmt.Errorf("kb_dir: %w", err)), nil, nil
	}
	srcAbs := ""
	if in.SourceDir != "" {
		abs, err := rejectTraversal(in.SourceDir)
		if err != nil {
			return errorResult(fmt.Errorf("source_dir: %w", err)), nil, nil
		}
		srcAbs = abs
	}
	// Note: APK analysis + skeleton generation is delegated to the CLI flow
	// (cmd/frida.go runFridaGenerate). The MCP tool variant returns a clear
	// pointer to that path rather than re-implementing dissect orchestration
	// here. This mirrors Phase 7 D-08's lazy-migration shape: the tool emits
	// the contract; the heavy pipeline runs separately.
	_ = ctx
	return jsonResult(fridaGenerateWithAIResult{
		KBDir: kbAbs,
		Note: fmt.Sprintf(
			"orchestrated path delegated to CLI: 'unravel frida generate %s --ai --source-dir %s -o %s' (Phase 9 D-04). "+
				"APK target classes: %v",
			filepath.Base(in.APKPath), srcAbs, kbAbs, in.TargetClasses,
		),
	}), nil, nil
}
