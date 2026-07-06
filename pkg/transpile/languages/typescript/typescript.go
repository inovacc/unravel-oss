/*
Copyright (c) 2026 Security Research

Package typescript registers TypeScript as a source language for conversion.
Conversion rules are loaded from the embedded FS in pkg/transpile/rules.
*/
package typescript

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages"
	"github.com/inovacc/unravel-oss/pkg/transpile/rules"
)

// Compile-time assertion: typescript.Lang satisfies the base Language interface.
var _ languages.Language = (*Lang)(nil)

// importRe matches TypeScript/ES module specifiers.
var importRe = regexp.MustCompile(`(?m)(?:\bfrom\s+|\bimport\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)['"]([^'"]+)['"]`)

// Lang implements the base Language interface for TypeScript (raw mode).
type Lang struct {
	rules     map[string]string
	rulesOnce sync.Once
}

func init() {
	languages.Register(New())
}

// New creates a new TypeScript language with default settings.
func New() *Lang {
	l := &Lang{
		rules: make(map[string]string),
	}

	return l
}

func (l *Lang) Name() string { return "TypeScript" }

func (l *Lang) Extensions() []string {
	return []string{".ts", ".tsx", ".mts", ".cts"}
}

func (l *Lang) SystemPrompt() string {
	return `You are an expert TypeScript-to-Go code converter. Your task is to convert TypeScript code into idiomatic, production-quality Go code.

Rules:
1. Produce compilable Go code — no pseudocode or placeholders.
2. Use idiomatic Go patterns: error returns instead of thrown exceptions, goroutines + channels instead of async/await + Promises, structs with methods instead of classes.
3. Map TypeScript types to appropriate Go types:
   - string → string
   - number → float64 (or int when the value is integral and used as an index/count)
   - bigint → *big.Int (math/big)
   - boolean → bool
   - T[] / Array<T> → []T
   - [A, B] (tuple) → struct or multiple return values
   - Record<K, V> / { [k: string]: V } → map[K]V
   - Set<T> → map[T]struct{}
   - Map<K, V> → map[K]V
   - null / undefined → nil (pointer), zero value, or a dedicated sentinel
   - T | undefined / T | null / T? (optional) → *T
   - A | B (union) → interface{} + type switch, or a sealed interface with concrete variants
   - A & B (intersection) → struct embedding
   - unknown / any → any (interface{}); narrow with type assertions
   - never → unreachable; return an error or panic
   - void → no return value
   - Promise<T> → (T, error) returned from a function, or <-chan T for streaming
   - Function type (a: A) => B → func(A) B
4. Convert TypeScript constructs to idiomatic Go:
   - interface → Go interface (method sets) or struct (data shapes)
   - type alias → named type / type definition
   - class → struct + methods; constructor → NewX() factory
   - abstract class → interface + concrete struct
   - enum → const + iota (numeric) or typed string constants
   - const enum → typed constants
   - namespace / module → Go package
   - generics <T> / <T extends C> → Go generics [T any] / [T C]
   - decorators → wrapper/middleware functions or code generation
   - getters/setters → explicit getter/setter methods
   - readonly → unexported field + accessor, or document immutability
   - optional chaining (?.) → explicit nil checks
   - nullish coalescing (??) → explicit zero/nil checks
   - destructuring → explicit field/index assignment
   - spread/rest (...) → variadic parameters / append
   - template literals → fmt.Sprintf
   - try/catch/finally → if err != nil { ... } + defer
   - throw → return error (errors.New / fmt.Errorf)
   - async/await → synchronous calls returning (T, error); concurrency via goroutines + channels + sync + context
   - for...of → range; for...in → range over map keys
   - Array methods (map/filter/reduce) → explicit loops or generics helpers (slices package)
5. Add proper Go package imports. Use Go naming conventions (PascalCase = exported, camelCase = unexported).
6. Preserve the original logic and behavior exactly.
7. When converting TypeScript framework/library code, prefer these Go equivalents:
   - express / fastify / koa → net/http + chi (or gorilla/mux)
   - NestJS → net/http + chi with explicit wiring (no DI container; use constructors)
   - axios / node-fetch → net/http
   - RxJS → channels + goroutines (reactive streams)
   - Prisma / TypeORM / Sequelize → sqlc + pgx / database/sql
   - zod / class-validator → go-playground/validator + explicit validation
   - jest / vitest / mocha → testing + testify
   - Node fs/path/process → os / path/filepath / os.Args, os.Getenv
   - ws / socket.io → nhooyr.io/websocket (raw WS; socket.io has no direct port — note this)
   - winston / pino → log/slog
   - JSON.parse / JSON.stringify → encoding/json
8. TypeScript/JS constructs with NO direct Go equivalent — emit a comment block
   at the top of the output file naming each and explaining that manual porting
   or an alternative design is required:
   - Prototype mutation / monkey-patching
   - Dynamic eval / Function constructor
   - Proxy / Reflect metaprogramming
   - Symbol-based protocols (Symbol.iterator etc.) — model explicitly in Go
   - Structural duck typing beyond Go interfaces
   - socket.io protocol, GraphQL schema-first runtimes (note alternative libs)
9. Treat .tsx/JSX as a UI layer with no Go equivalent: convert the non-JSX
   logic and emit a clearly marked comment block describing the UI that must be
   reimplemented in the target stack.
10. Additional library-specific conversion rules may be appended below when
   relevant imports are detected. Follow them with the same priority.

Output only the Go source code, no explanations.`
}

func (l *Lang) SystemPromptFor(ctx context.Context, source string) (string, error) {
	base := l.SystemPrompt()

	imports := l.DetectImports(source)
	if len(imports) == 0 {
		return base, nil
	}

	// Lazy-load rules only when needed by detected imports.
	l.rulesOnce.Do(func() {
		l.preloadRules()
	})

	extra, err := l.loadContextRules(imports)
	if err != nil {
		return "", fmt.Errorf("load context rules: %w", err)
	}

	if extra == "" {
		return base, nil
	}

	return base + "\n\nAdditional conversion context for detected libraries:\n" + extra, nil
}

func (l *Lang) ConvertRawPrompt(filename, source string) string {
	return fmt.Sprintf(`Convert the following TypeScript source file to a complete Go file.

Source file: %s

TypeScript source:
%s`, filename, source)
}

func (l *Lang) DetectImports(source string) []string {
	seen := make(map[string]struct{})

	var result []string

	for _, match := range importRe.FindAllStringSubmatch(source, -1) {
		spec := strings.TrimSpace(match[1])

		pkg := normalizeSpecifier(spec)
		if pkg == "" {
			continue
		}

		if _, ok := seen[pkg]; !ok {
			seen[pkg] = struct{}{}
			result = append(result, pkg)
		}
	}

	return result
}

// --- Rules infrastructure ---

func normalizeSpecifier(spec string) string {
	if spec == "" {
		return ""
	}

	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return ""
	}

	spec = strings.TrimPrefix(spec, "node:")

	if after, ok := strings.CutPrefix(spec, "@"); ok {
		spec = after
		if idx := strings.Index(spec, "/"); idx != -1 {
			spec = spec[:idx]
		}
	} else if idx := strings.Index(spec, "/"); idx != -1 {
		spec = spec[:idx]
	}

	spec = strings.ReplaceAll(spec, "-", "_")
	spec = strings.ToLower(spec)

	return spec
}

func (l *Lang) loadContextRules(imports []string) (string, error) {
	type result struct {
		name    string
		content string
	}

	var results []result

	for _, imp := range imports {
		if content, ok := l.rules[imp]; ok {
			results = append(results, result{name: imp, content: content})
		}
	}

	if len(results) == 0 {
		return "", nil
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].name < results[j].name
	})

	var parts []string
	for _, r := range results {
		parts = append(parts, r.content)
	}

	return strings.Join(parts, "\n\n"), nil
}

func (l *Lang) preloadRules() {
	names, err := rules.List("typescript")
	if err != nil {
		return
	}

	for _, name := range names {
		content, err := rules.Get("typescript", name)
		if err != nil || content == "" {
			continue
		}

		l.rules[name] = content
	}
}
