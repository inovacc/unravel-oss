package parser

import (
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/ast"
)

// Parser wraps the ANTLR4 C++ parser and produces semantic AST nodes.
type Parser struct {
	builder *ast.Builder
}

// New creates a new C++ parser.
func New() *Parser {
	return &Parser{
		builder: ast.NewBuilder(),
	}
}

// ParseFile parses C++ source code and returns a semantic AST.
// This currently uses the regex-based AST builder. When ANTLR4 generated
// code is available, it will use the full parse tree → AST visitor.
func (p *Parser) ParseFile(filename string, source []byte) (*ast.TranslationUnit, error) {
	tu := p.builder.BuildFromSource(filename, string(source))

	return tu, nil
}
