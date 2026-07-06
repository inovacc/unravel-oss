/*
Copyright (c) 2026 Security Research

Package java registers Java as a source language for conversion.
Conversion rules are loaded from the embedded FS in pkg/transpile/rules.
*/
package java

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
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/java/javamodel"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/java/lower"
	javaparser "github.com/inovacc/unravel-oss/pkg/transpile/languages/java/parser"
	"github.com/inovacc/unravel-oss/pkg/transpile/rules"
)

// Compile-time assertion: java.Lang satisfies DeterministicLanguage (SC1).
var _ languages.DeterministicLanguage = (*Lang)(nil)

// importRe matches Java import statements.
var importRe = regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?([a-zA-Z_][\w.]*(?:\.\*)?)\s*;`)

// importToRule maps Java package prefixes to rule names.
var importToRule = map[string]string{
	"org.springframework":      "spring",
	"springframework":          "spring",
	"org.junit":                "junit",
	"junit":                    "junit",
	"com.fasterxml.jackson":    "jackson",
	"jackson":                  "jackson",
	"lombok":                   "lombok",
	"org.slf4j":                "slf4j",
	"slf4j":                    "slf4j",
	"org.hibernate":            "hibernate",
	"hibernate":                "hibernate",
	"javax.persistence":        "jpa",
	"jakarta.persistence":      "jpa",
	"org.mockito":              "mockito",
	"mockito":                  "mockito",
	"com.google.common":        "guava",
	"com.google.guava":         "guava",
	"org.apache.commons.lang":  "commons_lang",
	"org.apache.commons.lang3": "commons_lang",
	"org.apache.commons.io":    "commons_io",
	"com.google.gson":          "gson",
	"retrofit2":                "retrofit",
	"okhttp3":                  "okhttp",
	"io.reactivex":             "rxjava",
	"io.netty":                 "netty",
	"org.apache.kafka":         "kafka",
	"io.vertx":                 "vertx",
	"org.testng":               "testng",
	"org.apache.logging.log4j": "log4j",
	"javax.servlet":            "servlet",
	"jakarta.servlet":          "servlet",
	"javax.ejb":                "ejb",
	"jakarta.ejb":              "ejb",
	"javax.naming":             "jndi",
	"javax.inject":             "javaee",
	"jakarta.inject":           "javaee",
	"javax.ws.rs":              "javaee",
	"jakarta.ws.rs":            "javaee",
	"javax.transaction":        "javaee",
	"jakarta.transaction":      "javaee",
}

// Lang implements the Language and ASTLanguage interfaces for Java.
type Lang struct {
	rules     map[string]string
	rulesOnce sync.Once
	parser    *javaparser.Parser
}

func init() {
	languages.Register(New())
}

// New creates a new Java language with default settings.
func New() *Lang {
	l := &Lang{
		rules:  make(map[string]string),
		parser: javaparser.New(),
	}

	return l
}

func (l *Lang) Name() string { return "Java" }

func (l *Lang) Extensions() []string {
	return []string{".java"}
}

func (l *Lang) SystemPrompt() string {
	return `You are an expert Java-to-Go code converter. Your task is to convert Java code into idiomatic, production-quality Go code.

Rules:
1. Produce compilable Go code — no pseudocode or placeholders.
2. Use idiomatic Go patterns: error returns instead of exceptions, structs with methods instead of classes.
3. Map Java types to appropriate Go types:
   - ArrayList<T> / List<T> → []T (slice)
   - HashMap<K,V> / Map<K,V> → map[K]V
   - HashSet<T> / Set<T> → map[T]struct{}
   - LinkedList<T> → []T or container/list
   - TreeMap<K,V> → custom sorted map or btree
   - Optional<T> → *T
   - String → string
   - int / Integer → int
   - long / Long → int64
   - float / Float → float32
   - double / Double → float64
   - boolean / Boolean → bool
   - byte / Byte → byte
   - char / Character → rune
   - short / Short → int16
   - void → (no return, or error)
   - Object → any / interface{}
   - byte[] → []byte
   - T[] → []T
4. Convert Java exceptions to Go error handling:
   - try/catch → if err != nil { ... }
   - throws → add error to return values
   - throw new XException → return fmt.Errorf(...) or custom error type
   - try-with-resources → defer + Close()
   - checked exceptions → error returns
   - unchecked exceptions → panic for truly unrecoverable, otherwise error
5. Convert Java classes to Go:
   - class → struct + methods
   - interface → Go interface (method set only)
   - abstract class → interface + partial struct implementation
   - inner class → separate struct in same package
   - static nested class → separate struct
   - anonymous class → closure or interface implementation
   - enum → const + iota or string constants with methods
   - record → struct (Java 16+)
6. Convert Java access modifiers:
   - public → PascalCase (exported)
   - private/protected/package-private → camelCase (unexported)
   - static fields/methods → package-level variables/functions
   - final fields → unexported with getter, or just a field
   - final class → no special treatment (Go has no inheritance)
7. Convert Java constructors to NewX() factory functions.
8. Convert Java inheritance to composition + interfaces:
   - extends → embed the parent struct
   - implements → implement the Go interface
   - super() → call embedded struct methods
   - @Override → just implement the method (implicit in Go)
9. Convert Java generics to Go generics [T any] or [T comparable].
10. Convert Java annotations to appropriate Go patterns:
   - @Override → remove (implicit in Go)
   - @Deprecated → // Deprecated: comment
   - @FunctionalInterface → type MyFunc func(...)
   - @SuppressWarnings → remove
   - DI annotations (@Autowired, @Inject) → constructor parameters
   - JSON annotations (@JsonProperty, @SerializedName) → struct tags (json:"name")
   - Validation annotations → struct tags + validator
   - JPA annotations (@Entity, @Column) → struct tags + sqlc
11. Convert Java concurrency to Go concurrency:
   - Thread → goroutine
   - Runnable/Callable → func()
   - ExecutorService → goroutines + sync.WaitGroup
   - CompletableFuture → goroutine + channel
   - synchronized → sync.Mutex
   - volatile → sync/atomic
   - ReentrantLock → sync.Mutex
   - Semaphore → buffered channel
   - CountDownLatch → sync.WaitGroup
   - ConcurrentHashMap → sync.Map
   - BlockingQueue → buffered channel
   - AtomicInteger/Long → atomic.Int32/Int64
12. Convert Java streams to explicit Go loops:
   - stream().filter() → for loop with if
   - stream().map() → for loop with append
   - stream().collect() → for loop building result
   - stream().reduce() → for loop with accumulator
   - stream().forEach() → for range loop
   - Collectors.toList() → append to slice
   - Collectors.groupingBy() → map building loop
13. Convert Java patterns to idiomatic Go:
   - Iterator → for range
   - Builder pattern → functional options pattern
   - Singleton → package-level var with sync.Once
   - Factory pattern → NewX() functions
   - Observer → channels
   - Strategy → interface + implementations
   - Dependency injection → constructor injection (no framework)
14. Framework equivalents:
   - Spring Boot → net/http + chi router
   - Spring MVC → chi handlers
   - Spring Data JPA → sqlc + pgx
   - Hibernate → database/sql + sqlc
   - JUnit 5 → testing + testify
   - Mockito → interface-based mocks or testify/mock
   - SLF4J/Logback → log/slog
   - Log4j → log/slog
   - Jackson → encoding/json
   - Gson → encoding/json
   - Lombok → explicit Go structs (no code gen needed)
   - Guava → standard library equivalents
   - Apache Commons → standard library equivalents
   - Retrofit/OkHttp → net/http
   - RxJava → goroutines + channels
   - Netty → net package + goroutines
   - Kafka → kafka-go or confluent-kafka-go
   - Vert.x → goroutines + channels + chi
15. WARNING: The following Java libraries have NO direct Go equivalent.
   If the source code imports any of these, emit a comment block at the
   top of the output file listing each detected library and explaining
   that manual porting or an alternative approach is required:
   - JavaFX (desktop UI framework)
   - Swing/AWT (desktop UI)
   - Spring AOP (aspect-oriented programming)
   - Bytecode manipulation (ASM, ByteBuddy, Javassist)
   - JNI/JNA (native interface)
   - Reflection-heavy frameworks (without Go equivalents)
   - Java Agents (instrumentation)
   - OSGi (module system)
   - EJB (Enterprise JavaBeans)
   - Applets
16. Additional library-specific conversion rules may be appended below
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
	return fmt.Sprintf(`Convert the following Java source file to a complete Go file.

Source file: %s

Java source:
%s`, filename, source)
}

func (l *Lang) DetectImports(source string) []string {
	seen := make(map[string]struct{})

	var result []string

	for _, match := range importRe.FindAllStringSubmatch(source, -1) {
		if match[1] == "" {
			continue
		}

		imp := match[1]
		// Try matching against known package prefixes
		for prefix, rule := range importToRule {
			if strings.HasPrefix(imp, prefix) {
				if _, ok := seen[rule]; !ok {
					seen[rule] = struct{}{}
					result = append(result, rule)
				}

				break
			}
		}
	}

	sort.Strings(result)

	return result
}

// ParseFile implements ASTLanguage.
func (l *Lang) ParseFile(filename string, source []byte) (any, error) {
	return l.parser.ParseFile(filename, source)
}

// ConvertModulePrompt implements ASTLanguage.
// Accepts either *javamodel.Module (AST mode) or *coreir.Module (hybrid fallback from deterministic mode).
func (l *Lang) ConvertModulePrompt(module any) (string, error) {
	switch mod := module.(type) {
	case *javamodel.Module:
		data, err := json.MarshalIndent(mod, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal module IR: %w", err)
		}

		return fmt.Sprintf(`Convert the following Java module IR to a complete Go file.

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
		return "", fmt.Errorf("expected *javamodel.Module or *ir.Module, got %T", module)
	}
}

// LowerToIR implements DeterministicLanguage.
func (l *Lang) LowerToIR(module any) (any, error) {
	mod, ok := module.(*javamodel.Module)
	if !ok {
		return nil, fmt.Errorf("expected *javamodel.Module, got %T", module)
	}

	return lower.NewLowerer().Lower(mod)
}

// SupportsCodegen implements DeterministicLanguage.
func (l *Lang) SupportsCodegen() bool {
	return true
}

// RewriteASTPrompt implements ASTRewriteLanguage.
// It builds prompts for AI to restructure the Java AST JSON for better Go idiom alignment.
func (l *Lang) RewriteASTPrompt(module any) (string, string, error) {
	mod, ok := module.(*javamodel.Module)
	if !ok {
		return "", "", fmt.Errorf("expected *javamodel.Module, got %T", module)
	}

	astJSON, err := json.MarshalIndent(mod, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal module AST: %w", err)
	}

	system := `You are an expert Java-to-Go AST restructuring engine.

You receive a Java AST as JSON and must restructure it for Go idiom alignment.

Rules for restructuring:
1. Flatten deep inheritance hierarchies to composition (embed parent struct fields).
2. Convert Builder patterns to functional options (WithX functions).
3. Convert Singleton patterns to package-level var with sync.Once init.
4. Mark interfaces that should be extracted as Go interfaces.
5. Fix any RawStmt/RawExpr nodes by inferring their structured types where possible.
6. Add "go_hints" metadata to nodes to guide code generation:
   - Add go_hints.pattern = "options" for Builder classes
   - Add go_hints.pattern = "singleton" for Singleton classes
   - Add go_hints.pattern = "error_return" for methods with try/catch
   - Add go_hints.pattern = "http_handler" for servlet classes
   - Add go_hints.interface = "true" for abstract classes with only abstract methods
7. Restructure try/catch blocks: annotate caught exceptions as error return types.
8. Convert Java annotation metadata to struct tag hints in go_hints.tags.
9. For servlet/filter classes, add go_hints.pattern = "http_handler" or "middleware".
10. For @Entity classes, add go_hints.pattern = "model" with struct tag hints.

Output ONLY the restructured JSON. Preserve the same schema as the input.
Do not add fields outside the existing schema except in the "metadata" map.`

	user := fmt.Sprintf(`Restructure the following Java AST for Go conversion.

Source file: %s

AST JSON:
%s`, mod.FileName, string(astJSON))

	return system, user, nil
}

// ParseRewrittenAST implements ASTRewriteLanguage.
// It deserializes AI-rewritten AST JSON back to a javamodel.Module.
func (l *Lang) ParseRewrittenAST(data []byte) (any, error) {
	var mod javamodel.Module
	if err := json.Unmarshal(data, &mod); err != nil {
		return nil, fmt.Errorf("unmarshal rewritten AST: %w", err)
	}

	return &mod, nil
}

// --- Rules infrastructure ---

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
	names, err := rules.List("java")
	if err != nil {
		return
	}

	for _, name := range names {
		content, err := rules.Get("java", name)
		if err != nil || content == "" {
			continue
		}

		l.rules[name] = content
	}
}
