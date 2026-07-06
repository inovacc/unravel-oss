/*
Copyright (c) 2026 Security Research

Phase 7 plan 04: cross-framework migration + per-component classification +
regression-only diff. Three new MCP tools:

	unravel_kb_transfer_migrate           - Lazy MCP-backed cross-framework hint generation
	unravel_kb_enrich_classify           - Per-file component bucket classification
	unravel_kb_ops_regression_check   - Regression-only pass over two KBs (4-dim diff + classify)

Threats mitigated:
  - T-07-01: path-traversal at every kb-dir input (rejects `..`, resolves Abs)
  - T-07-03: prompt-injection sentinels live inside the migrate package template
  - T-07-06: MCP request body cap (64 KiB) on classify_component & regression_check inputs
*/
package mcptools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/knowledge"
	"github.com/inovacc/unravel-oss/pkg/knowledge/components"
	"github.com/inovacc/unravel-oss/pkg/knowledge/migrate"
	"github.com/inovacc/unravel-oss/pkg/knowledge/regressions"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxClassifyContentBytes bounds the inline content payload accepted by the
// classify_component tool (T-07-06).
const maxClassifyContentBytes = 64 << 10

// maxRegressionInputBytes bounds the optional rubric path content read into
// memory before regression classification (T-07-06).
const maxRegressionInputBytes = 64 << 10

// knowledgeMigrateInput is the wire shape of the unravel_kb_transfer_migrate
// MCP tool. Both fields are required.
type knowledgeMigrateInput struct {
	KBDir     string `json:"kb_dir" jsonschema:"Path to existing knowledge directory"`
	Framework string `json:"framework" jsonschema:"Target framework (react|vue|angular|svelte|wpf|winui3|flutter|react-native)"`
}

// knowledgeClassifyComponentInput is the wire shape of
// unravel_kb_enrich_classify.
type knowledgeClassifyComponentInput struct {
	Path    string `json:"path" jsonschema:"Path to source file (used as classifier hint)"`
	Content string `json:"content,omitempty" jsonschema:"Optional inline file content (<=64 KiB). When empty, Path is read from disk."`
	WithAI  bool   `json:"with_ai,omitempty" jsonschema:"Allow MCP fallback for low-confidence pattern hits"`
}

// knowledgeRegressionCheckInput is the wire shape of
// unravel_kb_ops_regression_check.
type knowledgeRegressionCheckInput struct {
	OldDir string `json:"old_dir" jsonschema:"Path to the old knowledge directory"`
	NewDir string `json:"new_dir" jsonschema:"Path to the new knowledge directory"`
	Rubric string `json:"rubric,omitempty" jsonschema:"Optional kb-regressions.yaml override"`
	AI     bool   `json:"ai,omitempty" jsonschema:"Enable MCP second-opinion pass"`
}

// knowledgeClassifyComponentResult is the JSON shape returned by the
// classify_component handler.
type knowledgeClassifyComponentResult struct {
	Component  string  `json:"component"`
	Classifier string  `json:"classifier"`
	Confidence float64 `json:"confidence"`
}

// knowledgeRegressionCheckResult is the JSON shape returned by the
// regression_check handler.
type knowledgeRegressionCheckResult struct {
	Summary     string                   `json:"summary"`
	Regressions []regressions.Regression `json:"regressions"`
}

// knowledgeMigrateResult is the JSON shape returned by the migrate handler.
type knowledgeMigrateResult struct {
	Framework string `json:"framework"`
	OutputDir string `json:"output_dir"`
	Note      string `json:"note,omitempty"`
}

// migrateMCPClientFn is the test seam for injecting a migrate.MCPClient.
// Production: nil (per-component MCP errors are logged, no hints written).
// Tests overwrite this to inject a stub.
var migrateMCPClientFn = func() migrate.MCPClient { return nil }

// regressionsMCPClientFn is the test seam for injecting a regressions.MCPClient.
var regressionsMCPClientFn = func() regressions.MCPClient { return nil }

// registerKnowledgePhase7Tools registers the 3 Phase 7 plan 04 tools onto s.
// Called from registerKnowledgeTools to keep the Phase 7 surface in one file.
func registerKnowledgePhase7Tools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_transfer_migrate",
		Description: "Generate cross-framework migration hints for a KB directory. Per-component JSON + summary.md. Lazy MCP-backed — token cost applies.",
	}, handleKnowledgeMigrate)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_enrich_classify",
		Description: "Classify a single source file into a component bucket (auth, api, ipc, telemetry, ui, persistence, crypto, update, unknown).",
	}, handleKnowledgeClassifyComponent)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_ops_regression_check",
		Description: "Run only the regression-detection pass on two KB directories; severity-tagged regression list (BLOCK/FLAG/PASS).",
	}, handleKnowledgeRegressionCheck)
}

// rejectTraversal rejects any raw path containing a `..` segment (T-07-01).
// Returns the cleaned absolute path on success.
func rejectTraversal(p string) (string, error) {
	if p == "" {
		return "", errors.New("path is required")
	}
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path traversal rejected: %s", p)
		}
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("resolve abs: %w", err)
	}
	return abs, nil
}

func handleKnowledgeMigrate(ctx context.Context, _ *mcp.CallToolRequest, in knowledgeMigrateInput) (*mcp.CallToolResult, any, error) {
	fw := strings.ToLower(strings.TrimSpace(in.Framework))
	if !migrate.IsValid(fw) {
		return errorResult(fmt.Errorf("unknown target framework %q (valid: %s)",
			fw, strings.Join(migrate.ValidFrameworks(), ", "))), nil, nil
	}
	abs, err := rejectTraversal(in.KBDir)
	if err != nil {
		return errorResult(err), nil, nil
	}
	client := migrateMCPClientFn()
	if err := migrate.GenerateForFramework(ctx, abs, fw, client); err != nil {
		return errorResult(err), nil, nil
	}
	res := knowledgeMigrateResult{
		Framework: fw,
		OutputDir: filepath.Join(abs, "migrations", fw),
	}
	if client == nil {
		res.Note = "no MCP client wired in this build; per-component hint generation skipped"
	}
	return jsonResult(res), nil, nil
}

func handleKnowledgeClassifyComponent(ctx context.Context, _ *mcp.CallToolRequest, in knowledgeClassifyComponentInput) (*mcp.CallToolResult, any, error) {
	if in.Path == "" {
		return errorResult(errors.New("path is required")), nil, nil
	}
	// T-07-06: cap inline content.
	if len(in.Content) > maxClassifyContentBytes {
		return errorResult(fmt.Errorf("content exceeds %d-byte cap (T-07-06)", maxClassifyContentBytes)), nil, nil
	}
	var content []byte
	if in.Content != "" {
		content = []byte(in.Content)
	} else {
		abs, err := rejectTraversal(in.Path)
		if err != nil {
			return errorResult(err), nil, nil
		}
		body, err := os.ReadFile(abs)
		if err != nil {
			return errorResult(fmt.Errorf("read source: %w", err)), nil, nil
		}
		if len(body) > maxClassifyContentBytes {
			body = body[:maxClassifyContentBytes]
		}
		content = body
	}
	bucket, conf, source := components.Classify(
		components.SourceFile{Path: in.Path, Content: content},
		components.Options{WithAI: in.WithAI, Ctx: ctx},
	)
	return jsonResult(knowledgeClassifyComponentResult{
		Component:  string(bucket),
		Classifier: source,
		Confidence: conf,
	}), nil, nil
}

func handleKnowledgeRegressionCheck(ctx context.Context, _ *mcp.CallToolRequest, in knowledgeRegressionCheckInput) (*mcp.CallToolResult, any, error) {
	oldAbs, err := rejectTraversal(in.OldDir)
	if err != nil {
		return errorResult(fmt.Errorf("old_dir: %w", err)), nil, nil
	}
	newAbs, err := rejectTraversal(in.NewDir)
	if err != nil {
		return errorResult(fmt.Errorf("new_dir: %w", err)), nil, nil
	}
	rubricPath := ""
	if in.Rubric != "" {
		abs, err := rejectTraversal(in.Rubric)
		if err != nil {
			return errorResult(fmt.Errorf("rubric: %w", err)), nil, nil
		}
		// T-07-06: cap rubric size at 64 KiB before delegating to LoadRubric
		// (LoadRubric itself enforces a 1 MiB cap for kb-regressions.yaml).
		info, statErr := os.Stat(abs)
		if statErr == nil && info.Size() > maxRegressionInputBytes {
			return errorResult(fmt.Errorf("rubric exceeds %d-byte cap (T-07-06)", maxRegressionInputBytes)), nil, nil
		}
		rubricPath = abs
	}
	rules, err := regressions.LoadRubric(rubricPath)
	if err != nil {
		return errorResult(fmt.Errorf("load rubric: %w", err)), nil, nil
	}
	diff, err := knowledge.DiffWith(oldAbs, newAbs, rules)
	if err != nil {
		return errorResult(fmt.Errorf("diff: %w", err)), nil, nil
	}
	regs := append([]regressions.Regression(nil), diff.Regressions...)
	if in.AI {
		client := regressionsMCPClientFn()
		regs = append(regs, regressions.AISecondOpinion(ctx, diff.Snapshot(), regs, client)...)
	}
	return jsonResult(knowledgeRegressionCheckResult{
		Summary:     diff.Summary,
		Regressions: regs,
	}), nil, nil
}
