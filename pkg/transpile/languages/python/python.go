/*
Copyright (c) 2026 Security Research

Package python registers Python as a source language for conversion.
Conversion rules are loaded from the embedded FS in pkg/transpile/rules.
*/
package python

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	coreir "github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/python/lower"
	pyparser "github.com/inovacc/unravel-oss/pkg/transpile/languages/python/parser"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/python/pymodel"
	"github.com/inovacc/unravel-oss/pkg/transpile/rules"
)

// importRe matches Python import statements.
var importRe = regexp.MustCompile(`(?m)^\s*(?:from\s+(\S+)\s+import|import\s+(.+))`)

// Lang implements the Language and ASTLanguage interfaces for Python.
type Lang struct {
	rules     map[string]string
	rulesOnce sync.Once
	parser    *pyparser.Parser
}

func init() {
	languages.Register(New())
}

// New creates a new Python language with default settings.
func New() *Lang {
	l := &Lang{
		rules:  make(map[string]string),
		parser: pyparser.New(),
	}

	return l
}

func (l *Lang) Name() string { return "Python" }

func (l *Lang) Extensions() []string {
	return []string{".py"}
}

func (l *Lang) SystemPrompt() string {
	return `You are an expert Python-to-Go code converter. Your task is to convert Python code into idiomatic, production-quality Go code.

Rules:
1. Produce compilable Go code — no pseudocode or placeholders.
2. Use idiomatic Go patterns: error returns instead of exceptions, goroutines instead of async/await, structs with methods instead of classes.
3. Map Python types to appropriate Go types:
   - list → []T (slice)
   - dict → map[K]V
   - tuple → struct or multiple return values
   - set → map[T]struct{}
   - None → nil (pointer) or zero value
   - str → string
   - int → int (or int64 for large values)
   - float → float64
   - bool → bool
4. Convert Python exceptions to Go error handling (return error).
5. Convert Python decorators to appropriate Go patterns (middleware, wrapper functions).
6. Convert Python context managers (with statements) to defer patterns.
7. Convert list comprehensions to explicit loops or helper functions.
8. Add proper Go package imports.
9. Use Go naming conventions (camelCase for unexported, PascalCase for exported).
10. Preserve the original logic and behavior exactly.
11. When converting Python framework code, use these Go equivalents:
   - Django → net/http + chi (or gorilla/mux) + sqlc/pgx
   - FastAPI → net/http + chi (or fiber/echo)
   - Flask → net/http + chi
   - Celery → goroutines + channels (or asynq/machinery)
   - SQLAlchemy → sqlc + pgx / database/sql
   - Pydantic → struct tags + go-playground/validator
   - asyncio → goroutines + channels + sync + context
   - Jinja2 → text/template / html/template
   - pytest → testing + testify
   - boto3/botocore → aws-sdk-go-v2
12. These Python libraries have direct Go equivalents — convert normally:
   - requests/httpx → net/http
   - json → encoding/json
   - logging → log/slog
   - os/sys/pathlib → os / filepath
   - re → regexp
   - argparse/click → cobra / flag
   - threading → goroutines + sync
   - hashlib → crypto/*
   - uuid → github.com/google/uuid
   - yaml/toml → gopkg.in/yaml.v3 / github.com/BurntSushi/toml
   - docker → github.com/docker/docker/client
   - grpc → google.golang.org/grpc
   - redis → github.com/redis/go-redis
   - websocket → nhooyr.io/websocket
13. WARNING: The following Python libraries have NO direct Go equivalent.
   If the source code imports any of these, emit a comment block at the
   top of the output file listing each detected library and explaining
   that manual porting or an alternative approach is required:
   - ML/AI: tensorflow, keras, torch/pytorch, scikit-learn, xgboost, lightgbm
   - Data Science: numpy, pandas, scipy, matplotlib, seaborn, plotly
   - NLP: nltk, spacy, transformers (huggingface)
   - Computer Vision: cv2 (opencv-python), pillow (advanced image processing)
   - ORM layer: sqlalchemy.orm (the query-builder part of sqlalchemy is convertible)
   - Task queues: celery (the broker-based distributed task system)
   - Web scraping: scrapy
   - Event-driven: twisted
   - Compilation: cython, numba
   - Bridges: jpype, jython
   - Testing mocks: moto (AWS mocking)
   - Notebooks: jupyter, ipython
   - Symbolic math: sympy
   - Parallel data: dask, ray
   - Multiprocessing: multiprocessing (Python-specific shared-memory process model)
14. Convert Python patterns to idiomatic Go patterns:
   - Decorators → middleware functions / higher-order functions
   - Context managers (with) → defer + explicit Close()
   - Type hints → native Go types
   - *args → variadic parameters (...T)
   - **kwargs → option structs or functional options
   - Multiple inheritance → composition + interfaces
   - List comprehensions → for loops or slices package helpers
   - Generators/yield → channels + goroutines
   - Dynamic imports → plugin package or build tags
   - Exception handling (try/except) → error returns + errors.Is/As
   - Dataclasses/attrs → structs
   - Properties (@property) → getter/setter methods
   - Enums → const + iota
   - ABC/abstract classes → interfaces
15. Additional library-specific conversion rules may be appended below
   when relevant imports are detected in the source code. Follow those
   supplementary rules with the same priority as the rules above.

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
	return fmt.Sprintf(`Convert the following Python source file to a complete Go file.

Source file: %s

Python source:
%s`, filename, source)
}

func (l *Lang) DetectImports(source string) []string {
	seen := make(map[string]struct{})

	var result []string

	for _, match := range importRe.FindAllStringSubmatch(source, -1) {
		if match[1] != "" {
			pkg := topLevelPackage(match[1])
			if pkg != "" {
				if _, ok := seen[pkg]; !ok {
					seen[pkg] = struct{}{}
					result = append(result, pkg)
				}
			}
		} else if match[2] != "" {
			for part := range strings.SplitSeq(match[2], ",") {
				name := strings.TrimSpace(part)
				if idx := strings.Index(name, " "); idx != -1 {
					name = name[:idx]
				}

				pkg := topLevelPackage(name)
				if pkg != "" {
					if _, ok := seen[pkg]; !ok {
						seen[pkg] = struct{}{}
						result = append(result, pkg)
					}
				}
			}
		}
	}

	return result
}

// ParseFile implements ASTLanguage.
func (l *Lang) ParseFile(filename string, source []byte) (any, error) {
	return l.parser.ParseFile(filename, source)
}

// ConvertModulePrompt implements ASTLanguage.
// Accepts either *pymodel.Module (AST mode) or *ir.Module (hybrid fallback from deterministic mode).
func (l *Lang) ConvertModulePrompt(module any) (string, error) {
	switch mod := module.(type) {
	case *pymodel.Module:
		data, err := json.MarshalIndent(mod, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal module IR: %w", err)
		}

		return fmt.Sprintf(`Convert the following Python module IR to a complete Go file.

Source file: %s

Module IR (JSON):
%s`, mod.FileName, string(data)), nil

	case *coreir.Module:
		data, err := json.MarshalIndent(mod, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal IR module: %w", err)
		}

		return fmt.Sprintf(`Convert the following language-agnostic IR to a complete Go file.

Source file: %s

IR Module (JSON):
%s`, mod.SourceFile, string(data)), nil

	default:
		return "", fmt.Errorf("expected *pymodel.Module or *ir.Module, got %T", module)
	}
}

// LowerToIR implements DeterministicLanguage.
func (l *Lang) LowerToIR(module any) (any, error) {
	mod, ok := module.(*pymodel.Module)
	if !ok {
		return nil, fmt.Errorf("expected *pymodel.Module, got %T", module)
	}

	return lower.NewLowerer().Lower(mod)
}

// SupportsCodegen implements DeterministicLanguage.
func (l *Lang) SupportsCodegen() bool {
	return true
}

// --- Rules infrastructure ---

func topLevelPackage(pkg string) string {
	if before, _, ok := strings.Cut(pkg, "."); ok {
		return before
	}

	return pkg
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
	names, err := rules.List("python")
	if err != nil {
		return
	}

	for _, name := range names {
		content, err := rules.Get("python", name)
		if err != nil || content == "" {
			continue
		}

		l.rules[name] = content
	}
}
