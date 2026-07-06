// Package languages defines the Language interface and registry for
// multi-language-to-Go conversion. Each source language (C++, Python, etc.)
// implements the Language interface and registers itself with the registry.
package languages

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// Language defines the interface that each source language must implement.
type Language interface {
	// Name returns the display name of the language (e.g., "C++", "Python").
	Name() string

	// Extensions returns the file extensions handled by this language
	// (e.g., []string{".c", ".cpp", ".cc", ".h", ".hpp"}).
	Extensions() []string

	// SystemPrompt returns the base system prompt for this language.
	SystemPrompt() string

	// SystemPromptFor returns the system prompt enriched with context rules
	// for the given source code.
	SystemPromptFor(ctx context.Context, source string) (string, error)

	// ConvertRawPrompt builds the user prompt for raw source conversion.
	ConvertRawPrompt(filename, source string) string

	// DetectImports extracts import/include identifiers from source code.
	DetectImports(source string) []string
}

// ASTLanguage is an optional interface for languages that support AST parsing.
type ASTLanguage interface {
	Language

	// ParseFile parses source into a language-specific AST/IR.
	// Returns the parsed module as any (caller type-asserts).
	ParseFile(filename string, source []byte) (any, error)

	// ConvertModulePrompt builds the user prompt for AST-mode conversion.
	ConvertModulePrompt(module any) (string, error)
}

// ASTRewriteLanguage extends ASTLanguage for languages that support AI-assisted
// AST restructuring before code generation. The pipeline is:
// Source → Parse → AST JSON → AI rewrites AST → Parse rewritten AST → LLM codegen → Go.
type ASTRewriteLanguage interface {
	ASTLanguage

	// RewriteASTPrompt builds prompts for AI to restructure the AST JSON
	// for better Go idiom alignment.
	RewriteASTPrompt(module any) (system string, user string, err error)

	// ParseRewrittenAST deserializes AI-rewritten AST JSON back to module type.
	ParseRewrittenAST(data []byte) (any, error)
}

// DeterministicLanguage extends ASTLanguage for languages that support the
// full deterministic pipeline: parse → lower to IR → adapt → codegen → Go code.
// Languages implementing this interface can convert code without LLM calls
// for straightforward cases, falling back to LLM only for complex sections.
type DeterministicLanguage interface {
	ASTLanguage

	// LowerToIR lowers the parsed AST module to a language-agnostic ir.Module.
	// The module parameter is the result of ParseFile.
	LowerToIR(module any) (any, error)

	// SupportsCodegen reports whether this language supports deterministic
	// code generation from IR (adapt → codegen → Go code).
	SupportsCodegen() bool
}

// registry holds all registered languages.
var (
	registryMu sync.RWMutex
	registry   = make(map[string]Language) // extension → language
	languages  []Language                  // all registered languages (deduped)
)

// Register adds a language to the registry for all its extensions.
func Register(lang Language) {
	registryMu.Lock()
	defer registryMu.Unlock()

	languages = append(languages, lang)

	for _, ext := range lang.Extensions() {
		ext = strings.ToLower(ext)
		registry[ext] = lang
	}
}

// ForExtension returns the language registered for the given file extension.
func ForExtension(ext string) (Language, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	lang, ok := registry[strings.ToLower(ext)]

	return lang, ok
}

// ForFile returns the language registered for the given filename.
func ForFile(filename string) (Language, error) {
	ext := strings.ToLower(filepath.Ext(filename))

	lang, ok := ForExtension(ext)
	if !ok {
		return nil, fmt.Errorf("unsupported file extension %q", ext)
	}

	return lang, nil
}

// All returns all registered languages.
func All() []Language {
	registryMu.RLock()
	defer registryMu.RUnlock()

	out := make([]Language, len(languages))
	copy(out, languages)

	return out
}

// SupportedExtensions returns all supported file extensions.
func SupportedExtensions() map[string]struct{} {
	registryMu.RLock()
	defer registryMu.RUnlock()

	out := make(map[string]struct{}, len(registry))
	for ext := range registry {
		out[ext] = struct{}{}
	}

	return out
}
