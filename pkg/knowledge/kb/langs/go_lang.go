package langs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
)

// init registers the Go extractor at package load. The walker side just
// calls langs.Lookup(".go") and gets back this function transparently.
func init() {
	Register(".go", "go", extractGo)
}

// extractGo parses a Go source file with go/parser and returns a Module
// whose SymbolsJSON contains the top-level declaration names grouped by
// kind (functions / types / consts / vars), and whose Imports list holds
// the verbatim import paths.
//
// Errors are returned only for hard parse failures — partial files (e.g.
// a build-tagged stub with a syntax error) are still surfaced so the
// walker can decide whether to skip or persist a body-only row.
func extractGo(path string, body []byte) (Module, error) {
	fset := token.NewFileSet()
	// AllErrors so we get a parse failure message; ParseComments is off
	// because we don't index comments specifically — they end up in the
	// 4 KB excerpt anyway via pg_trgm trigram tokens.
	file, err := parser.ParseFile(fset, path, body, parser.AllErrors)
	if err != nil {
		// On parse failure we still hash the body so the walker can
		// store a generic row (lang="go", no symbols). The walker
		// inspects the error and decides whether to log+continue.
		return Module{}, fmt.Errorf("parse %s: %w", path, err)
	}

	var (
		funcs  []string
		types  []string
		consts []string
		vars   []string
	)
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name != nil {
				funcs = append(funcs, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name != nil {
						types = append(types, s.Name.Name)
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n == nil {
							continue
						}
						switch d.Tok {
						case token.CONST:
							consts = append(consts, n.Name)
						case token.VAR:
							vars = append(vars, n.Name)
						}
					}
				}
			}
		}
	}

	imports := make([]string, 0, len(file.Imports))
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		// imp.Path.Value is a quoted Go string literal — strip surrounding
		// quotes without bringing in strconv.
		p := strings.Trim(imp.Path.Value, "\"`")
		if p != "" {
			imports = append(imports, p)
		}
	}

	symbolsObj := map[string][]string{}
	if len(funcs) > 0 {
		symbolsObj["functions"] = funcs
	}
	if len(types) > 0 {
		symbolsObj["types"] = types
	}
	if len(consts) > 0 {
		symbolsObj["consts"] = consts
	}
	if len(vars) > 0 {
		symbolsObj["vars"] = vars
	}
	if len(imports) > 0 {
		symbolsObj["imports"] = imports
	}
	var symbolsJSON string
	if len(symbolsObj) > 0 {
		raw, _ := json.Marshal(symbolsObj)
		symbolsJSON = string(raw)
	}

	const excerptCap = 4096
	excerpt := body
	if len(excerpt) > excerptCap {
		excerpt = excerpt[:excerptCap]
	}
	sum := sha256.Sum256(body)

	pkg := ""
	if file.Name != nil {
		pkg = file.Name.Name
	}
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	name := base
	if pkg != "" {
		name = pkg + "." + base
	}

	return Module{
		Name:        name,
		BodyExcerpt: string(excerpt),
		BodySHA256:  hex.EncodeToString(sum[:]),
		FullBody:    body,
		SymbolsJSON: symbolsJSON,
		Lang:        "go",
		Imports:     imports,
		Size:        len(body),
	}, nil
}
