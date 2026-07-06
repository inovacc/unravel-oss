package audit

import (
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/transpile/archive"
)

// Stage directory names.
const (
	DirInput         = "00_input"
	DirExtraction    = "01_extraction"
	DirMetadata      = "02_metadata"
	DirPatterns      = "03_patterns"
	DirDecompilation = "04_decompilation"
	DirParsing       = "05_parsing"
	DirASTRewrite    = "06_ast_rewrite"
	DirCodegen       = "07_codegen"
)

// RecordInput records Stage 0: archive input info and copies the archive.
func (a *Auditor) RecordInput(archivePath string, archiveType archive.ArchiveType) error {
	info, err := os.Stat(archivePath)
	if err != nil {
		return err
	}

	archiveInfo := map[string]any{
		"path":         archivePath,
		"archive_type": archiveType.String(),
		"size_bytes":   info.Size(),
		"filename":     filepath.Base(archivePath),
	}

	if err := a.WriteJSON(DirInput, "archive_info.json", archiveInfo); err != nil {
		return err
	}

	return a.CopyFile(DirInput, filepath.Base(archivePath), archivePath)
}

// RecordExtraction records Stage 1: file listing from extraction.
func (a *Auditor) RecordExtraction(info *archive.ArchiveInfo) error {
	type fileEntry struct {
		Path string `json:"path"`
		Type string `json:"type"` // "java", "class", "jar", "other"
	}

	var entries []fileEntry

	for _, f := range info.JavaFiles {
		entries = append(entries, fileEntry{Path: f, Type: "java"})
	}

	for _, f := range info.ClassFiles {
		entries = append(entries, fileEntry{Path: f, Type: "class"})
	}

	for _, f := range info.NestedJARs {
		entries = append(entries, fileEntry{Path: f, Type: "jar"})
	}

	listing := map[string]any{
		"total_files": len(entries),
		"java_files":  len(info.JavaFiles),
		"class_files": len(info.ClassFiles),
		"nested_jars": len(info.NestedJARs),
		"extract_dir": info.ExtractDir,
		"files":       entries,
	}

	return a.WriteJSON(DirExtraction, "file_listing.json", listing)
}

// RecordMetadata records Stage 2: parsed metadata files.
func (a *Auditor) RecordMetadata(info *archive.ArchiveInfo) error {
	if info.Manifest != nil {
		if err := a.WriteJSON(DirMetadata, "manifest.json", info.Manifest); err != nil {
			a.logger.Warn("audit: failed to write manifest.json", "error", err)
		}
	}

	if info.WebXML != nil {
		if err := a.WriteJSON(DirMetadata, "web_xml.json", info.WebXML); err != nil {
			a.logger.Warn("audit: failed to write web_xml.json", "error", err)
		}
	}

	if info.AppXML != nil {
		if err := a.WriteJSON(DirMetadata, "app_xml.json", info.AppXML); err != nil {
			a.logger.Warn("audit: failed to write app_xml.json", "error", err)
		}
	}

	if info.POM != nil {
		if err := a.WriteJSON(DirMetadata, "pom.json", info.POM); err != nil {
			a.logger.Warn("audit: failed to write pom.json", "error", err)
		}
	}

	if info.SpringConfig != nil {
		if err := a.WriteJSON(DirMetadata, "spring_config.json", info.SpringConfig); err != nil {
			a.logger.Warn("audit: failed to write spring_config.json", "error", err)
		}
	}

	return nil
}

// RecordPatterns records Stage 3: enterprise pattern detection results.
func (a *Auditor) RecordPatterns(report *archive.PatternReport) error {
	if report == nil {
		return nil
	}

	return a.WriteJSON(DirPatterns, "pattern_report.json", report)
}

// RecordDecompilation records Stage 4: decompilation summary.
func (a *Auditor) RecordDecompilation(classFiles, decompiledFiles, errors []string) error {
	report := map[string]any{
		"total_class_files":    len(classFiles),
		"decompiled_files":     len(decompiledFiles),
		"decompilation_errors": len(errors),
		"class_files":          classFiles,
		"decompiled":           decompiledFiles,
	}

	if len(errors) > 0 {
		report["errors"] = errors
	}

	return a.WriteJSON(DirDecompilation, "decompile_report.json", report)
}

// CopyDecompiledSources copies decompiled .java files into the audit directory.
func (a *Auditor) CopyDecompiledSources(extractDir string, javaFiles []string) error {
	sourcesDir := filepath.Join(a.baseDir, DirDecompilation, "sources")
	if err := os.MkdirAll(sourcesDir, 0o755); err != nil {
		return err
	}

	for _, jf := range javaFiles {
		srcPath := filepath.Join(extractDir, filepath.FromSlash(jf))

		dstPath := filepath.Join(sourcesDir, filepath.FromSlash(jf))
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			a.logger.Warn("audit: failed to create dir for decompiled source", "file", jf, "error", err)
			continue
		}

		data, err := os.ReadFile(srcPath)
		if err != nil {
			a.logger.Warn("audit: failed to read decompiled source", "file", jf, "error", err)
			continue
		}

		if err := os.WriteFile(dstPath, data, 0o644); err != nil {
			a.logger.Warn("audit: failed to write decompiled source", "file", jf, "error", err)
		}
	}

	return nil
}

// RecordParsedAST records Stage 5: ANTLR4 parsed AST for a single file.
func (a *Auditor) RecordParsedAST(filename string, module any) error {
	subdir := filepath.Join(DirParsing, sanitizeFilename(filename))
	return a.WriteJSON(subdir, "ast.json", module)
}

// RecordRewritePrompts records Stage 6: AST rewrite prompts for a single file.
func (a *Auditor) RecordRewritePrompts(filename, systemPrompt, userPrompt string) error {
	subdir := filepath.Join(DirASTRewrite, sanitizeFilename(filename))

	if err := a.WriteText(subdir, "rewrite_system_prompt.txt", systemPrompt); err != nil {
		return err
	}

	return a.WriteText(subdir, "rewrite_user_prompt.txt", userPrompt)
}

// RecordRewriteResponse records Stage 6: AI AST rewrite response for a single file.
func (a *Auditor) RecordRewriteResponse(filename, response string) error {
	subdir := filepath.Join(DirASTRewrite, sanitizeFilename(filename))
	return a.WriteText(subdir, "rewrite_response.json", response)
}

// RecordRewrittenAST records Stage 6: parsed rewritten AST module for a single file.
func (a *Auditor) RecordRewrittenAST(filename string, module any) error {
	subdir := filepath.Join(DirASTRewrite, sanitizeFilename(filename))
	return a.WriteJSON(subdir, "rewritten_ast.json", module)
}

// RecordCodegenPrompts records Stage 7: codegen prompts for a single file.
func (a *Auditor) RecordCodegenPrompts(filename, systemPrompt, userPrompt string) error {
	subdir := filepath.Join(DirCodegen, sanitizeFilename(filename))

	if err := a.WriteText(subdir, "system_prompt.txt", systemPrompt); err != nil {
		return err
	}

	return a.WriteText(subdir, "user_prompt.txt", userPrompt)
}

// RecordCodegenOutput records Stage 7: generated Go code for a single file.
func (a *Auditor) RecordCodegenOutput(filename, rawCode, formattedCode string) error {
	subdir := filepath.Join(DirCodegen, sanitizeFilename(filename))

	if err := a.WriteText(subdir, "output_raw.go", rawCode); err != nil {
		return err
	}

	return a.WriteText(subdir, "output.go", formattedCode)
}
