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

	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/java/archive"
	javabeautify "github.com/inovacc/unravel-oss/pkg/java/beautify"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type javaInfoInput struct {
	Path string `json:"path" jsonschema:"Path to .class, .jar, .war, or .ear file"`
}

type javaDecompileInput struct {
	Path      string `json:"path" jsonschema:"Path to .class, .jar, .war, or .ear file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory for decompiled sources"`
}

type javaExtractInput struct {
	Path      string `json:"path" jsonschema:"Path to .jar, .war, or .ear file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory (default: <name>_extracted)"`
}

type javaManifestInput struct {
	Path string `json:"path" jsonschema:"Path to .jar, .war, or .ear file"`
}

// JavaBeautifyInput is the typed input for unravel_java_beautify
// (06-04 Task 2). Path-traversal sanitisation (T-06-01) and symlink
// rejection (T-06-06) are enforced in the handler.
type JavaBeautifyInput struct {
	Path       string `json:"path" jsonschema:"absolute path to a pre-decompiled Java tree (raw/ from a prior 'unravel java decompile' run)"`
	OutputDir  string `json:"output_dir" jsonschema:"output directory for beautified tree + manifest.json"`
	AIDisabled bool   `json:"ai_disabled,omitempty" jsonschema:"skip AI beautification (raw-only manifest)"`
}

func registerJavaTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_java_info",
		Description: "Display Java class or archive metadata: class name, version, fields, methods, manifest, dependencies",
	}, handleJavaInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_java_decompile",
		Description: "Decompile Java class files to source using built-in Go decompiler (no Java required)",
	}, handleJavaDecompile)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_java_extract",
		Description: "Extract Java archive (JAR/WAR/EAR) contents to a directory",
	}, handleJavaExtract)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_java_manifest",
		Description: "Show MANIFEST.MF, web.xml, application.xml, and pom.xml from a Java archive",
	}, handleJavaManifest)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_java_beautify",
		Description: "Run AI beautification on a pre-decompiled Java tree (D-15). Walks raw/ subtree, beautifies each .java with structural-preservation guard, writes parallel beautified/ tree + manifest.json.",
	}, handleJavaBeautify)
}

// sanitizeJavaMCPPath cleans + rejects path-traversal segments at the
// MCP boundary (T-06-01). mustExist=true requires stat-resolve.
func sanitizeJavaMCPPath(p string, mustExist bool) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("path contains '..' segment")
	}
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path contains '..' segment after clean")
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	if mustExist {
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("stat path: %w", err)
		}
	}
	return abs, nil
}

// javaMCPAIBeautifier adapts an *ai.Client to javabeautify.Beautifier.
type javaMCPAIBeautifier struct {
	c *ai.Client
}

func (a *javaMCPAIBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

func handleJavaBeautify(ctx context.Context, _ *mcp.CallToolRequest, input JavaBeautifyInput) (*mcp.CallToolResult, any, error) {
	inAbs, err := sanitizeJavaMCPPath(input.Path, true)
	if err != nil {
		return errorResult(fmt.Errorf("input path: %w", err)), nil, nil
	}
	outAbs, err := sanitizeJavaMCPPath(input.OutputDir, false)
	if err != nil {
		return errorResult(fmt.Errorf("output path: %w", err)), nil, nil
	}

	// Reject symlink input (T-06-06).
	if info, lerr := os.Lstat(inAbs); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errorResult(fmt.Errorf("input is symlink, refusing")), nil, nil
		}
	}

	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return errorResult(fmt.Errorf("mkdir output: %w", err)), nil, nil
	}

	// Build a synthetic DecompileResult: each direct child of inAbs is
	// treated as one JarOutput.
	dr := &javabeautify.DecompileResult{DecompilerVersion: "unravel-java-decompiler"}
	if entries, rerr := os.ReadDir(inAbs); rerr == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			jarDir := filepath.Join(inAbs, e.Name())
			fileCount := 0
			_ = filepath.WalkDir(jarDir, func(p string, d os.DirEntry, werr error) error {
				if werr != nil || d.IsDir() {
					return nil
				}
				if strings.EqualFold(filepath.Ext(p), ".java") {
					fileCount++
				}
				return nil
			})
			dr.Jars = append(dr.Jars, javabeautify.JarOutput{
				Name:              e.Name(),
				Path:              jarDir,
				OutDir:            jarDir,
				FileCount:         fileCount,
				DecompilerVersion: "unravel-java-decompiler",
				Decompiled:        true,
			})
		}
	}

	aiEnabled := !input.AIDisabled
	bopts := javabeautify.BeautifyOptions{AIEnabled: aiEnabled}
	var beautifier javabeautify.Beautifier
	if aiEnabled {
		client, cerr := ai.NewClient()
		if cerr != nil {
			bopts.AIEnabled = false
		} else {
			beautifier = &javaMCPAIBeautifier{c: client}
		}
	}

	orch := javabeautify.NewOrchestrator(beautifier, bopts)
	report, err := orch.Run(ctx, dr, javabeautify.RunOptions{
		Output: outAbs,
		Input:  inAbs,
		Mode:   "beautify",
	})
	if err != nil {
		return errorResult(fmt.Errorf("orchestrator: %w", err)), nil, nil
	}
	return jsonResult(report), nil, nil
}

func handleJavaInfo(ctx context.Context, _ *mcp.CallToolRequest, input javaInfoInput) (*mcp.CallToolResult, any, error) {
	if isClassExt(input.Path) {
		data, err := os.ReadFile(input.Path)
		if err != nil {
			return errorResult(fmt.Errorf("read file: %w", err)), nil, nil
		}

		cf, err := classfile.Parse(data)
		if err != nil {
			return errorResult(fmt.Errorf("parse class: %w", err)), nil, nil
		}

		result := map[string]any{
			"class_name":    cf.ClassNameDotted(),
			"java_version":  cf.JavaVersion(),
			"access_flags":  cf.AccessFlags.ClassAccessString(),
			"super_class":   strings.ReplaceAll(cf.SuperClassName(), "/", "."),
			"field_count":   len(cf.Fields),
			"method_count":  len(cf.Methods),
			"source_file":   cf.SourceFile(),
			"constant_pool": cf.ConstantPool.Count(),
		}

		return jsonResult(result), nil, nil
	}

	a := archive.New(slog.Default())

	info, err := a.Extract(ctx, input.Path)
	if err != nil {
		return errorResult(fmt.Errorf("analyze archive: %w", err)), nil, nil
	}

	defer func() { _ = info.Cleanup() }()

	return jsonResult(info), nil, nil
}

func handleJavaDecompile(ctx context.Context, _ *mcp.CallToolRequest, input javaDecompileInput) (*mcp.CallToolResult, any, error) {
	dec := &decompiler.NativeDecompiler{}

	if isClassExt(input.Path) {
		data, err := os.ReadFile(input.Path)
		if err != nil {
			return errorResult(fmt.Errorf("read file: %w", err)), nil, nil
		}

		source, err := dec.DecompileBytes(data)
		if err != nil {
			return errorResult(fmt.Errorf("decompile: %w", err)), nil, nil
		}

		if input.OutputDir != "" {
			baseName := strings.TrimSuffix(filepath.Base(input.Path), ".class") + ".java"
			outPath := filepath.Join(input.OutputDir, baseName)
			_ = os.MkdirAll(input.OutputDir, 0o755)

			if err := os.WriteFile(outPath, []byte(source), 0o644); err != nil {
				return errorResult(fmt.Errorf("write: %w", err)), nil, nil
			}

			return jsonResult(map[string]any{
				"output_path": outPath,
				"source":      source,
			}), nil, nil
		}

		return textResult(source), nil, nil
	}

	// Archive decompilation
	a := archive.New(slog.Default())

	info, err := a.Extract(ctx, input.Path)
	if err != nil {
		return errorResult(fmt.Errorf("extract archive: %w", err)), nil, nil
	}

	defer func() { _ = info.Cleanup() }()

	outDir := input.OutputDir
	if outDir == "" {
		baseName := strings.TrimSuffix(filepath.Base(input.Path), filepath.Ext(input.Path))
		outDir = baseName + "-decompiled"
	}

	_ = os.MkdirAll(outDir, 0o755)

	var decompiled, errCount int

	for _, classRel := range info.ClassFiles {
		classPath := filepath.Join(info.ExtractDir, filepath.FromSlash(classRel))

		data, err := os.ReadFile(classPath)
		if err != nil {
			errCount++

			continue
		}

		source, err := dec.DecompileBytes(data)
		if err != nil {
			errCount++

			continue
		}

		javaPath := strings.TrimSuffix(classRel, ".class") + ".java"
		outPath := filepath.Join(outDir, filepath.FromSlash(javaPath))
		_ = os.MkdirAll(filepath.Dir(outPath), 0o755)

		if err := os.WriteFile(outPath, []byte(source), 0o644); err != nil {
			errCount++

			continue
		}

		decompiled++
	}

	return jsonResult(map[string]any{
		"output_dir": outDir,
		"total":      len(info.ClassFiles),
		"decompiled": decompiled,
		"errors":     errCount,
	}), nil, nil
}

func handleJavaExtract(ctx context.Context, _ *mcp.CallToolRequest, input javaExtractInput) (*mcp.CallToolResult, any, error) {
	a := archive.New(slog.Default())

	info, err := a.Extract(ctx, input.Path)
	if err != nil {
		return errorResult(fmt.Errorf("extract: %w", err)), nil, nil
	}

	outDir := input.OutputDir
	if outDir == "" {
		baseName := strings.TrimSuffix(filepath.Base(input.Path), filepath.Ext(input.Path))
		outDir = baseName + "-extracted"
	}

	// Copy from temp to output
	if err := copyTree(info.ExtractDir, outDir); err != nil {
		_ = info.Cleanup()

		return errorResult(fmt.Errorf("copy: %w", err)), nil, nil
	}

	_ = info.Cleanup()

	return jsonResult(map[string]any{
		"output_dir":  outDir,
		"type":        info.Type.String(),
		"class_count": len(info.ClassFiles),
		"java_count":  len(info.JavaFiles),
		"nested_jars": len(info.NestedJARs),
	}), nil, nil
}

func handleJavaManifest(ctx context.Context, _ *mcp.CallToolRequest, input javaManifestInput) (*mcp.CallToolResult, any, error) {
	a := archive.New(slog.Default())

	info, err := a.Extract(ctx, input.Path)
	if err != nil {
		return errorResult(fmt.Errorf("extract: %w", err)), nil, nil
	}

	defer func() { _ = info.Cleanup() }()

	result := map[string]any{
		"manifest":        info.Manifest,
		"web_xml":         info.WebXML,
		"application_xml": info.AppXML,
		"pom":             info.POM,
		"spring_config":   info.SpringConfig,
	}

	return jsonResult(result), nil, nil
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

func isClassExt(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".class")
}

// copyTree copies a directory tree from src to dst.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		target := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(target, data, 0o644)
	})
}
