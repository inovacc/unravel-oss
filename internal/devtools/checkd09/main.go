/*
Copyright (c) 2026 Security Research

checkd09 is the CI guard tool that enforces D-09: only internal/ai and
internal/mcp may import the Anthropic Go SDK directly. Every other
package MUST go through the MCP sampling seam.

Usage:

	go run ./internal/devtools/checkd09 [root]

If `root` is omitted, the current working directory is used.

Exit codes:

	0 — no violations
	1 — at least one forbidden import was found (printed to stderr)
	2 — invocation / I/O failure (printed to stderr)
*/
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// forbiddenPrefixes lists module-path prefixes no caller may import directly.
// Add ONLY after writing an ADR; widening this list is a D-09 regression.
var forbiddenPrefixes = []string{
	"github.com/anthropics/anthropic-sdk-go",
}

// allowedDirs is the (slash-style, repo-relative) directory prefix allowlist
// for forbidden SDK imports.
var allowedDirs = []string{
	"internal/ai/",
	"internal/mcp/",
}

// explicitDenyPrefixes names subtrees that are asserted, by intent, never to
// import the Anthropic SDK. The allow-list above already denies everything
// outside internal/ai|mcp, so these are defense-in-depth + documentation: a
// regression here surfaces a DISTINCT, self-explaining error ("<dir> must not
// import the Anthropic SDK (D-09)") instead of the generic forbidden-import
// line, making the intent obvious in CI and code review.
//
// TRANSPILE-PHASE2-GAPS (P3): pkg/transpile is a named, explicit denied subtree
// so the protection no longer rests on it incidentally having zero SDK imports.
var explicitDenyPrefixes = []string{
	"pkg/transpile/",
}

// subprocessAllowedDirs is the allowlist for the `claude` subprocess scan.
// pkg/knowledge/kb/llm owns the legacy CLI seam pending the MCP sampling
// pivot — it is the ONLY place outside internal/ai|mcp permitted to
// reference the `claude` binary by name.
var subprocessAllowedDirs = []string{
	"internal/ai/",
	"internal/mcp/",
	"pkg/knowledge/kb/llm/",
	"internal/devtools/checkd09/",
	// cmd/plugin_install.go shells out `claude plugin marketplace add` so
	// users get one-shot install without typing the registration command
	// themselves. Required for the embed-and-install UX.
	"cmd/",
	// pkg/aihost/claude/install.go owns the marketplace registration
	// ritual after the cmd/-side refactor moved it out of cmd/.
	"pkg/aihost/claude/",
}

// skipDirs are directory names we do not descend into. `testdata` is
// included because the Go toolchain itself ignores it for compilation,
// so files there are intentionally non-buildable fixtures (including
// our own check_test.go fixtures that import the forbidden SDK on
// purpose to assert the guard fires).
var skipDirs = map[string]struct{}{
	"vendor":       {},
	".git":         {},
	".claude":      {},
	"node_modules": {},
	"_legacy":      {},
	"testdata":     {},
}

type violation struct {
	file string // repo-relative, slash-style
	line int
	imp  string // forbidden import path OR "exec:claude" for subprocess hits
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkd09: resolve root: %v\n", err)
		os.Exit(2)
	}
	violations, err := scan(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkd09: %v\n", err)
		os.Exit(2)
	}
	if len(violations) == 0 {
		return
	}
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "%s:%d: forbidden import %q\n", v.file, v.line, v.imp)
	}
	fmt.Fprintf(os.Stderr, "checkd09: %d violation(s)\n", len(violations))
	os.Exit(1)
}

// scan walks root and returns every D-09 violation it finds. The returned
// file paths are repo-relative with forward slashes, suitable for both
// matching against allowedDirs and for stable, OS-independent reporting.
func scan(root string) ([]violation, error) {
	fset := token.NewFileSet()
	var out []violation

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		relSlash := filepath.ToSlash(rel)
		// testdata is already skipped at the dir level; *_test.go files are
		// scanned (real production code paths sometimes hide behind tests).
		sdkAllowed := isAllowed(relSlash, allowedDirs)
		subAllowed := isAllowed(relSlash, subprocessAllowedDirs)
		if sdkAllowed && subAllowed {
			return nil
		}
		// Full-AST parse needed to inspect call expressions for the
		// subprocess scan. ImportsOnly would skip function bodies.
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "checkd09: parse %s: %v\n", relSlash, parseErr)
			return nil
		}
		if !sdkAllowed {
			denyPrefix, explicitlyDenied := matchExplicitDeny(relSlash)
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if !isForbidden(p) {
					continue
				}
				pos := fset.Position(imp.Pos())
				v := violation{file: relSlash, line: pos.Line, imp: p}
				// Defense-in-depth: files under an explicit-deny subtree get a
				// distinct, self-explaining marker so the regression reads as
				// intentional protection, not a generic allow-list miss.
				if explicitlyDenied {
					v.imp = fmt.Sprintf("%s (%s must not import the Anthropic SDK (D-09))", p, strings.TrimSuffix(denyPrefix, "/"))
				}
				out = append(out, v)
			}
		}
		if !subAllowed {
			ast.Inspect(f, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok || len(ce.Args) == 0 {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "exec" {
					return true
				}
				switch sel.Sel.Name {
				case "Command", "CommandContext", "LookPath":
				default:
					return true
				}
				// First string-literal arg after ctx for CommandContext.
				for _, a := range ce.Args {
					lit, ok := a.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v := strings.Trim(lit.Value, `"`+"`")
					if v == "claude" || strings.HasSuffix(v, "/claude") || strings.HasSuffix(v, `\claude`) || v == "claude.exe" {
						pos := fset.Position(lit.Pos())
						out = append(out, violation{file: relSlash, line: pos.Line, imp: "exec:" + sel.Sel.Name + "(claude)"})
						return false
					}
				}
				return true
			})
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return out, nil
}

func isAllowed(relSlash string, dirs []string) bool {
	for _, p := range dirs {
		if strings.HasPrefix(relSlash, p) {
			return true
		}
	}
	return false
}

// matchExplicitDeny reports whether relSlash falls under one of the named,
// asserted explicitDenyPrefixes and returns the matched prefix. These subtrees
// are already covered by the allow-list semantics; the explicit match exists to
// produce a distinct violation message documenting the intent.
func matchExplicitDeny(relSlash string) (prefix string, denied bool) {
	for _, p := range explicitDenyPrefixes {
		if strings.HasPrefix(relSlash, p) {
			return p, true
		}
	}
	return "", false
}

func isForbidden(imp string) bool {
	for _, p := range forbiddenPrefixes {
		if imp == p || strings.HasPrefix(imp, p+"/") {
			return true
		}
	}
	return false
}
