// Package parser wraps the ANTLR4-generated Java lexer and parser.
// It provides a high-level ParseFile function that takes Java source
// and returns a Module IR by walking the parse tree with a custom visitor.
package parser

import (
	"fmt"
	"strings"

	"github.com/antlr4-go/antlr/v4"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages/java/javamodel"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/java/parser/generated"
)

// Parser parses Java source code into an intermediate representation.
type Parser struct{}

// New creates a new Java parser.
func New() *Parser {
	return &Parser{}
}

// ParseFile reads a Java file and returns its IR.
func (p *Parser) ParseFile(filename string, source []byte) (*javamodel.Module, error) {
	input := antlr.NewInputStream(string(source))

	lexer := generated.NewJavaLexer(input)
	lexer.RemoveErrorListeners()

	errListener := &errorListener{}
	lexer.AddErrorListener(errListener)

	stream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)

	pr := generated.NewJavaParser(stream)
	pr.RemoveErrorListeners()
	pr.AddErrorListener(errListener)

	tree := pr.CompilationUnit()

	if errListener.hasErrors() {
		return nil, fmt.Errorf("parse errors: %s", errListener.errors())
	}

	visitor := newVisitor(stream)
	module := visitor.visitModule(tree)
	module.FileName = filename

	return module, nil
}

// errorListener collects parse errors.
type errorListener struct {
	antlr.DefaultErrorListener

	errs []string
}

func (e *errorListener) SyntaxError(
	_ antlr.Recognizer,
	_ any,
	line, column int,
	msg string,
	_ antlr.RecognitionException,
) {
	e.errs = append(e.errs, fmt.Sprintf("line %d:%d %s", line, column, msg))
}

func (e *errorListener) hasErrors() bool {
	return len(e.errs) > 0
}

func (e *errorListener) errors() string {
	var result strings.Builder

	for i, err := range e.errs {
		if i > 0 {
			result.WriteString("; ")
		}

		result.WriteString(err)
	}

	return result.String()
}
