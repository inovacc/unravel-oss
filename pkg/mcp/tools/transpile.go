/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	pkgmcp "github.com/inovacc/unravel-oss/internal/mcp"
	"github.com/inovacc/unravel-oss/pkg/transpile/analysis"
	"github.com/inovacc/unravel-oss/pkg/transpile/core/converter"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages"
	"github.com/inovacc/unravel-oss/pkg/transpile/rules"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TranspileDetectInput defines the input for unravel_transpile_detect.
type TranspileDetectInput struct {
	Path string `json:"path" jsonschema:"path to file or directory to scan for transpilable source files"`
}

// TranspileRunInput defines the input for unravel_transpile_run.
type TranspileRunInput struct {
	Path     string `json:"path" jsonschema:"path to the source file to transpile"`
	Language string `json:"language,omitempty" jsonschema:"override language detection (e.g., C++, Java, Python, TypeScript)"`
}

// TranspileCoverageInput defines the input for unravel_transpile_coverage.
type TranspileCoverageInput struct {
	Path string `json:"path" jsonschema:"path to the source file to check coverage for"`
}

// TranspileAnalyzeInput defines the input for unravel_transpile_analyze.
type TranspileAnalyzeInput struct {
	Path string `json:"path" jsonschema:"path to the source codebase root to analyze"`
}

// TranspileResourceListInput defines the input for unravel_transpile_resource_list.
type TranspileResourceListInput struct {
	Kind string `json:"kind" jsonschema:"resource kind to list: 'rules' or 'strategies'"`
	Lang string `json:"language,omitempty" jsonschema:"for kind='rules', the language to list (cpp, java, python, typescript)"`
}

// TranspileResourceGetInput defines the input for unravel_transpile_resource_get.
type TranspileResourceGetInput struct {
	Kind string `json:"kind" jsonschema:"resource kind: 'rules' or 'strategies'"`
	Path string `json:"path" jsonschema:"relative path to the resource (e.g., 'cpp/stl' for rules, or 'concurrency/channels.md' for strategies)"`
}

func registerTranspileTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_transpile_detect",
		Description: "Detect source files supported by the unravel transpiler (C++, Java, Python, TypeScript)",
	}, handleTranspileDetect)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_transpile_run",
		Description: "Transpile a source file to Go using a hybrid deterministic+LLM pipeline",
	}, handleTranspileRun)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_transpile_coverage",
		Description: "Report honest deterministic coverage metric for a source file",
	}, handleTranspileCoverage)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_transpile_analyze",
		Description: "Perform deep static analysis of a codebase: LOC, subsystems, dependencies, and triage plan",
	}, handleTranspileAnalyze)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_transpile_resource_list",
		Description: "List embedded conversion resources (rules per language, or architectural strategies)",
	}, handleTranspileResourceList)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_transpile_resource_get",
		Description: "Retrieve an embedded conversion resource (markdown content) to use as idiom context in prompts",
	}, handleTranspileResourceGet)
}

func handleTranspileDetect(_ context.Context, _ *mcp.CallToolRequest, input TranspileDetectInput) (*mcp.CallToolResult, any, error) {
	if input.Path == "" {
		return errorResult(fmt.Errorf("path is required")), nil, nil
	}

	info, err := os.Stat(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	supported := languages.SupportedExtensions()

	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(input.Path))
		if _, ok := supported[ext]; ok {
			lang, _ := languages.ForFile(input.Path)
			return jsonResult(map[string]any{
				"path":      input.Path,
				"supported": true,
				"language":  lang.Name(),
			}), nil, nil
		}
		return jsonResult(map[string]any{
			"path":      input.Path,
			"supported": false,
		}), nil, nil
	}

	var found []map[string]any
	err = filepath.Walk(input.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if _, ok := supported[ext]; ok {
			lang, _ := languages.ForFile(path)
			found = append(found, map[string]any{
				"path":     path,
				"language": lang.Name(),
			})
		}
		return nil
	})

	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(found), nil, nil
}

func handleTranspileRun(ctx context.Context, _ *mcp.CallToolRequest, input TranspileRunInput) (*mcp.CallToolResult, any, error) {
	if input.Path == "" {
		return errorResult(fmt.Errorf("path is required")), nil, nil
	}

	source, err := os.ReadFile(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	var lang languages.Language
	if input.Language != "" {
		for _, l := range languages.All() {
			if strings.EqualFold(l.Name(), input.Language) {
				lang = l
				break
			}
		}
		if lang == nil {
			return errorResult(fmt.Errorf("unsupported language override: %s", input.Language)), nil, nil
		}
	} else {
		lang, err = languages.ForFile(input.Path)
		if err != nil {
			return errorResult(err), nil, nil
		}
	}

	llmClient := pkgmcp.TranspileClient()
	conv := converter.New(slog.Default(), converter.WithLLM(llmClient))

	var result *converter.PromptResult
	if dl, ok := lang.(languages.DeterministicLanguage); ok {
		result, err = conv.ConvertWithDeterministic(ctx, dl, input.Path, source)
	} else if al, ok := lang.(languages.ASTLanguage); ok {
		result, err = conv.ConvertWithLanguageAST(ctx, al, input.Path, source)
	} else {
		result, err = conv.ConvertWithLanguage(ctx, lang, input.Path, source)
	}

	if err != nil {
		return errorResult(err), nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: result.Format()},
		},
	}, nil, nil
}

func handleTranspileCoverage(ctx context.Context, _ *mcp.CallToolRequest, input TranspileCoverageInput) (*mcp.CallToolResult, any, error) {
	if input.Path == "" {
		return errorResult(fmt.Errorf("path is required")), nil, nil
	}

	source, err := os.ReadFile(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	lang, err := languages.ForFile(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	dl, ok := lang.(languages.DeterministicLanguage)
	if !ok {
		return jsonResult(map[string]any{
			"path":     input.Path,
			"language": lang.Name(),
			"note":     "language does not support deterministic coverage metrics",
		}), nil, nil
	}

	conv := converter.New(slog.Default()) // no LLM needed for coverage check
	result, err := conv.ConvertWithDeterministic(ctx, dl, input.Path, source)
	if err != nil {
		return errorResult(err), nil, nil
	}

	if result.Confidence == nil {
		return jsonResult(map[string]any{
			"path":     input.Path,
			"language": lang.Name(),
			"note":     "coverage metrics unavailable for this file",
		}), nil, nil
	}

	return jsonResult(result.Confidence), nil, nil
}

func handleTranspileAnalyze(ctx context.Context, _ *mcp.CallToolRequest, input TranspileAnalyzeInput) (*mcp.CallToolResult, any, error) {
	if input.Path == "" {
		return errorResult(fmt.Errorf("path is required")), nil, nil
	}

	opts := analysis.Options{
		IncludeGraph: true,
		Symbols:      true,
	}

	analyzer := analysis.NewAnalyzer(input.Path, slog.Default(), opts)
	report, err := analyzer.Analyze(ctx)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(report), nil, nil
}

func handleTranspileResourceList(_ context.Context, _ *mcp.CallToolRequest, input TranspileResourceListInput) (*mcp.CallToolResult, any, error) {
	switch input.Kind {
	case "rules":
		if input.Lang == "" {
			return errorResult(fmt.Errorf("language is required for kind='rules'")), nil, nil
		}
		list, err := rules.List(input.Lang)
		if err != nil {
			return errorResult(err), nil, nil
		}
		return jsonResult(list), nil, nil

	case "strategies":
		list, err := rules.ListStrategies()
		if err != nil {
			return errorResult(err), nil, nil
		}
		return jsonResult(list), nil, nil

	default:
		return errorResult(fmt.Errorf("invalid kind: %s (must be 'rules' or 'strategies')", input.Kind)), nil, nil
	}
}

func handleTranspileResourceGet(_ context.Context, _ *mcp.CallToolRequest, input TranspileResourceGetInput) (*mcp.CallToolResult, any, error) {
	if input.Path == "" {
		return errorResult(fmt.Errorf("path is required")), nil, nil
	}

	var content string
	var err error

	switch input.Kind {
	case "rules":
		parts := strings.Split(input.Path, "/")
		if len(parts) != 2 {
			return errorResult(fmt.Errorf("invalid rules path format (expected 'lang/name')")), nil, nil
		}
		content, err = rules.Get(parts[0], parts[1])

	case "strategies":
		content, err = rules.GetStrategy(input.Path)

	default:
		return errorResult(fmt.Errorf("invalid kind: %s", input.Kind)), nil, nil
	}

	if err != nil {
		return errorResult(err), nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: content},
		},
	}, nil, nil
}
