// Package cpp registers C/C++ as a source language for conversion.
package cpp

import (
	"context"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/ast"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/lower"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/parser"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/prompt"
)

// Lang implements the DeterministicLanguage interface for C/C++.
type Lang struct {
	builder *prompt.Builder
	parser  *parser.Parser
	lowerer *lower.Lowerer
}

func init() {
	languages.Register(New())
}

// New creates a new C/C++ language with default settings.
func New() *Lang {
	return &Lang{
		builder: prompt.New(),
		parser:  parser.New(),
		lowerer: lower.NewLowerer(),
	}
}

func (l *Lang) Name() string { return "C/C++" }

func (l *Lang) Extensions() []string {
	return []string{".c", ".cpp", ".cc", ".cxx", ".c++", ".h", ".hpp", ".hxx"}
}

func (l *Lang) SystemPrompt() string {
	return l.builder.SystemPrompt()
}

func (l *Lang) SystemPromptFor(ctx context.Context, source string) (string, error) {
	return l.builder.SystemPromptFor(ctx, source)
}

func (l *Lang) ConvertRawPrompt(filename, source string) string {
	return l.builder.ConvertRawPrompt(filename, source)
}

func (l *Lang) DetectImports(source string) []string {
	return prompt.DetectIncludes(source)
}

// ParseFile parses C/C++ source into an AST (TranslationUnit).
func (l *Lang) ParseFile(filename string, source []byte) (any, error) {
	tu, err := l.parser.ParseFile(filename, source)
	if err != nil {
		return nil, fmt.Errorf("parse C++ %s: %w", filename, err)
	}

	return tu, nil
}

// ConvertModulePrompt builds the user prompt from an ir.Module.
func (l *Lang) ConvertModulePrompt(module any) (string, error) {
	mod, ok := module.(*ir.Module)
	if !ok {
		return "", fmt.Errorf("expected *ir.Module, got %T", module)
	}

	return l.builder.ConvertModulePrompt(mod)
}

// LowerToIR lowers the parsed AST (TranslationUnit) to a language-agnostic ir.Module.
func (l *Lang) LowerToIR(module any) (any, error) {
	tu, ok := module.(*ast.TranslationUnit)
	if !ok {
		return nil, fmt.Errorf("expected *ast.TranslationUnit, got %T", module)
	}

	return l.lowerer.Lower(tu), nil
}

// SupportsCodegen reports that C/C++ supports deterministic code generation.
func (l *Lang) SupportsCodegen() bool { return true }
