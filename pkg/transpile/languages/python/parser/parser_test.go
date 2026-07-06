package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/antlr4-go/antlr/v4"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages/python/parser/generated"
)

func TestParseCalculator(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "test_scenarios", "python", "01_calculator", "calculator.py"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	p := New()
	mod, err := p.ParseFile("calculator.py", src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if mod == nil {
		t.Fatal("module is nil")
	}

	if mod.FileName != "calculator.py" {
		t.Errorf("filename = %q, want calculator.py", mod.FileName)
	}
}

func TestParseAllScenarios(t *testing.T) {
	scenarioDir := filepath.Join("..", "..", "..", "test_scenarios", "python")
	entries, err := os.ReadDir(scenarioDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}

	// These files use walrus operator (:=) which the Python3 grammar doesn't support
	walrusFiles := map[string]bool{
		"text_adventure.py":     true,
		"sorting_algorithms.py": true,
		"url_shortener.py":      true,
	}

	p := New()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pyFiles, _ := filepath.Glob(filepath.Join(scenarioDir, entry.Name(), "*.py"))
		for _, pyFile := range pyFiles {
			name := filepath.Base(pyFile)
			t.Run(name, func(t *testing.T) {
				if walrusFiles[name] {
					t.Skip("uses walrus operator (:=) unsupported by grammar")
				}
				src, err := os.ReadFile(pyFile)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				mod, err := p.ParseFile(name, src)
				if err != nil {
					t.Errorf("parse error: %v", err)
					return
				}
				if mod == nil {
					t.Error("module is nil")
				}
			})
		}
	}
}

func TestLexerTokenDump(t *testing.T) {
	src := "class Foo:\n    x = 1\n"

	input := antlr.NewInputStream(src)
	lexer := generated.NewPython3Lexer(input)
	stream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	stream.Fill()

	tokens := stream.GetAllTokens()
	for i, tok := range tokens {
		t.Logf("token[%d]: type=%d channel=%d text=%q", i, tok.GetTokenType(), tok.GetChannel(), tok.GetText())
	}

	// Verify INDENT token is present with correct type
	foundIndent := false
	for _, tok := range tokens {
		if tok.GetTokenType() == 1 { // INDENT
			foundIndent = true
			break
		}
	}
	if !foundIndent {
		t.Error("INDENT token (type=1) not found in token stream")
	}
}
