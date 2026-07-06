/*
Copyright (c) 2026 Security Research

Prompt package constructs the system and user prompts for Claude API calls.
Conversion rules are loaded from the embedded FS in pkg/transpile/rules.
*/
package prompt

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/rules"
)

// includeToRuleName maps C++ #include paths to rule names.
var includeToRuleName = map[string]string{
	"vector":                       "stl",
	"map":                          "stl",
	"set":                          "stl",
	"string":                       "stl",
	"algorithm":                    "stl",
	"memory":                       "stl",
	"iostream":                     "stl",
	"fstream":                      "stl",
	"sstream":                      "stl",
	"numeric":                      "stl",
	"functional":                   "stl",
	"thread":                       "stl",
	"mutex":                        "stl",
	"atomic":                       "stl",
	"chrono":                       "stl",
	"regex":                        "stl",
	"filesystem":                   "stl",
	"optional":                     "stl",
	"variant":                      "stl",
	"any":                          "stl",
	"array":                        "stl",
	"deque":                        "stl",
	"list":                         "stl",
	"forward_list":                 "stl",
	"unordered_map":                "stl",
	"unordered_set":                "stl",
	"queue":                        "stl",
	"stack":                        "stl",
	"tuple":                        "stl",
	"boost/asio.hpp":               "asio",
	"boost/asio":                   "asio",
	"boost":                        "boost",
	"catch2/catch_test_macros.hpp": "catch2",
	"catch2":                       "catch2",
	"Eigen":                        "eigen",
	"fmt/core.h":                   "fmt",
	"fmt/format.h":                 "fmt",
	"fmt":                          "fmt",
	"gtest/gtest.h":                "googletest",
	"gmock/gmock.h":                "googletest",
	"grpc++/grpc++.h":              "grpc",
	"grpcpp":                       "grpc",
	"nlohmann/json.hpp":            "json",
	"json/json.h":                  "json",
	"rapidjson":                    "json",
	"opencv2":                      "opencv",
	"openssl":                      "openssl",
	"Poco":                         "poco",
	"google/protobuf":              "protobuf",
	"Qt":                           "qt",
	"QtCore":                       "qt",
	"QtGui":                        "qt",
	"QtWidgets":                    "qt",
	"SDL.h":                        "sdl",
	"SDL2/SDL.h":                   "sdl",
	"spdlog/spdlog.h":              "spdlog",
	"spdlog":                       "spdlog",
	"sqlite3.h":                    "sqlite",
	"tbb":                          "tbb",
	"vulkan/vulkan.h":              "vulkan",
	"wx/wx.h":                      "wxwidgets",
	"wx":                           "wxwidgets",
	"zmq.hpp":                      "zmq",
	"zmq.h":                        "zmq",
	"curl/curl.h":                  "curl",
	"GL/gl.h":                      "opengl",
	"GL/glew.h":                    "opengl",
	"glad/glad.h":                  "opengl",
	"GLFW/glfw3.h":                 "opengl",
	"SFML":                         "sfml",
	"imgui.h":                      "imgui",
	"absl":                         "abseil",

	// C standard library headers
	"stdio.h":   "c_stdlib",
	"stdlib.h":  "c_stdlib",
	"string.h":  "c_stdlib",
	"math.h":    "c_stdlib",
	"time.h":    "c_stdlib",
	"stdint.h":  "c_stdlib",
	"stdbool.h": "c_stdlib",
	"stddef.h":  "c_stdlib",
	"ctype.h":   "c_stdlib",
	"errno.h":   "c_stdlib",
	"limits.h":  "c_stdlib",
	"float.h":   "c_stdlib",
	"stdarg.h":  "c_stdlib",
	"signal.h":  "c_stdlib",
	"setjmp.h":  "c_stdlib",
	"assert.h":  "c_stdlib",
	"locale.h":  "c_stdlib",

	// POSIX headers
	"unistd.h":     "posix",
	"fcntl.h":      "posix",
	"sys/types.h":  "posix",
	"sys/stat.h":   "posix",
	"sys/socket.h": "posix",
	"pthread.h":    "posix",
	"dirent.h":     "posix",
	"dlfcn.h":      "posix",
	"sys/mman.h":   "posix",
	"arpa/inet.h":  "posix",
	"netinet/in.h": "posix",

	// Windows headers
	"windows.h":  "win32",
	"winsock2.h": "win32",
	"ws2tcpip.h": "win32",
}

// Builder constructs the system and user prompts for Claude API calls.
type Builder struct {
	rules map[string]string
}

// New creates a new prompt builder.
func New() *Builder {
	b := &Builder{
		rules: make(map[string]string),
	}

	b.preloadRules()

	return b
}

// preloadRules loads all known rule files from the embedded FS.
// Failed or missing rules are silently skipped.
func (b *Builder) preloadRules() {
	names, err := rules.List("cpp")
	if err != nil {
		return
	}

	for _, name := range names {
		content, err := rules.Get("cpp", name)
		if err != nil || content == "" {
			continue
		}

		b.rules[name] = content
	}
}

// SystemPrompt returns the system prompt that instructs Claude on C/C++ to Go conversion.
func (b *Builder) SystemPrompt() string {
	return `You are an expert C/C++-to-Go code converter. Your task is to convert C or C++ code into idiomatic, production-quality Go code.

Rules:
1. Produce compilable Go code — no pseudocode or placeholders.
2. Use idiomatic Go patterns: error returns instead of exceptions, goroutines instead of threads, structs with methods instead of classes.
3. Map C++ types to appropriate Go types:
   - std::vector<T> → []T (slice)
   - std::map<K,V> → map[K]V
   - std::set<T> → map[T]struct{}
   - std::string → string
   - std::pair<A,B> → struct{ First A; Second B } or multiple return values
   - std::tuple → struct or multiple return values
   - std::optional<T> → *T (pointer)
   - std::unique_ptr<T> / std::shared_ptr<T> → *T
   - int → int, long → int64, double → float64, float → float32
   - char → byte, wchar_t → rune
   - bool → bool
   - size_t → uint or int
   - void → (omit return type)
   - nullptr → nil
   - auto → inferred type
4. Convert C++ exceptions to Go error handling (return error).
   - try/catch → if err != nil { return err }
   - throw → return fmt.Errorf(...)
   - Exception types → error values
5. Convert C++ classes to Go structs with methods:
   - Class/struct → Go struct
   - Public methods → exported methods (PascalCase)
   - Private methods → unexported methods (camelCase)
   - Constructors → NewX() factory functions
   - Destructors → Close() method (use with defer)
   - Inheritance → composition (embedded structs) + interfaces
   - Virtual methods / abstract classes → interfaces
   - Operator overloading → named methods (Add, Sub, Equal, Less, String, etc.)
6. Convert C++ memory management to Go patterns:
   - new/delete → pointer creation (GC handles cleanup)
   - RAII → defer + Close()
   - Smart pointers → regular pointers
   - Manual memory management → let GC handle it
7. Convert C++ concurrency to Go patterns:
   - std::thread → goroutines
   - std::mutex → sync.Mutex
   - std::condition_variable → sync.Cond or channels
   - std::atomic → sync/atomic
   - std::async/std::future → goroutines + channels
   - Thread pools → goroutines (lightweight)
8. Convert C++ templates to Go generics or interfaces:
   - Simple templates → Go generics [T any]
   - SFINAE/enable_if → type constraints
   - Template specialization → type switches or separate functions
9. Add proper Go package imports.
10. Use Go naming conventions (camelCase for unexported, PascalCase for exported).
11. Preserve the original logic and behavior exactly.
12. Convert C++ standard library usage:
    - <iostream> std::cout → fmt.Print/fmt.Println
    - <iostream> std::cerr → fmt.Fprint(os.Stderr, ...)
    - <fstream> → os.Open/os.Create + bufio
    - <algorithm> std::sort → sort.Slice or slices.Sort
    - <regex> → regexp
    - <chrono> → time
    - <filesystem> → os + filepath
    - <sstream> → strings.Builder or fmt.Sprintf
    - <cmath> → math
    - <random> → math/rand
    - <numeric> → manual loops or math helpers
13. Convert C++ patterns to idiomatic Go patterns:
    - Range-based for → for range
    - Iterators → slice/map indexing or range
    - Function pointers/std::function → func types / closures
    - Lambdas → anonymous functions / closures
    - Namespaces → packages
    - #define constants → const
    - #define macros → functions
    - Enums → const + iota (or typed constants)
    - enum class → typed constants with custom type
    - Union → interface{} or unsafe (discouraged)
    - Typedef/using → type alias
    - const& parameters → value or pointer parameters
    - Default parameters → functional options or overloaded functions
    - Singleton pattern → package-level var + sync.Once
    - Factory pattern → constructor functions
    - Observer pattern → channels or callback functions
    - Builder pattern → functional options
14. WARNING: The following C++ libraries have NO direct Go equivalent.
    If the source code uses any of these, emit a comment block at the
    top of the output file explaining that manual porting is required:
    - Graphics: OpenGL (partial), DirectX, Vulkan (partial)
    - GUI: Qt, wxWidgets, GTK (partial via gotk3)
    - Game engines: Unreal Engine, SDL (partial)
    - ML/AI: TensorFlow C++, PyTorch C++, ONNX Runtime
    - Math: Eigen (partial), BLAS/LAPACK
    - Media: FFmpeg, OpenCV (partial via gocv)
15. Additional library-specific conversion rules may be appended below
    when relevant includes are detected in the source code. Follow those
    supplementary rules with the same priority as the rules above.
16. Convert C-specific patterns to idiomatic Go:
    - Function pointers → func types
    - typedef struct → named Go struct
    - typedef function pointer → named func type
    - goto/labels → restructure to loops with break/continue where possible, comment otherwise
    - malloc/calloc/realloc + free → Go allocations (make, new, slices)
    - printf/fprintf/sprintf → fmt.Printf/fmt.Fprintf/fmt.Sprintf
    - strlen/strcmp/strcpy/strcat → len(), ==, string concat, strings package
    - FILE* + fopen/fread/fwrite/fclose → os.File + os.Open/Read/Write
    - errno → error returns
    - signal handlers → os/signal.Notify + channels
    - setjmp/longjmp → error returns or panic/recover (with comment)
    - Variadic functions (va_list) → variadic Go functions (...Type)
    - Static local variables → package-level vars or closures
    - extern declarations → package-level var/func
    - Union types → interface{} or struct with accessor methods
    - Bitfields → manual bit manipulation with masks
    - #define function-like macros → Go functions
    - C arrays (fixed size) → Go arrays [N]T or slices
    - VLA (variable-length arrays) → slices
17. C type mappings:
    - int8_t/int16_t/int32_t/int64_t → int8/int16/int32/int64
    - uint8_t/uint16_t/uint32_t/uint64_t → uint8/uint16/uint32/uint64
    - size_t → uint or int
    - ptrdiff_t → int
    - char* (string) → string (or []byte for binary)
    - void* → unsafe.Pointer or interface{}
    - FILE* → *os.File
    - NULL → nil

Output only the Go source code, no explanations.`
}

// SystemPromptFor returns the system prompt enriched with additional context
// rules when the C++ source includes libraries that have matching rule files.
func (b *Builder) SystemPromptFor(_ context.Context, cppSource string) (string, error) {
	base := b.SystemPrompt()

	includes := DetectIncludes(cppSource)
	if len(includes) == 0 {
		return base, nil
	}

	extra, err := b.loadContextRules(includes)
	if err != nil {
		return "", fmt.Errorf("load context rules: %w", err)
	}

	if extra == "" {
		return base, nil
	}

	return base + "\n\nAdditional conversion context for detected libraries:\n" + extra, nil
}

// includeRe matches C++ #include directives.
var includeRe = regexp.MustCompile(`(?m)^\s*#\s*include\s+[<"]([^>"]+)[>"]`)

// DetectIncludes extracts include paths from C++ source code.
func DetectIncludes(source string) []string {
	seen := make(map[string]struct{})

	var result []string

	for _, match := range includeRe.FindAllStringSubmatch(source, -1) {
		path := match[1]
		if _, ok := seen[path]; !ok {
			seen[path] = struct{}{}
			result = append(result, path)
		}
	}

	return result
}

// MapIncludeToRule maps an #include path to a rule name.
func MapIncludeToRule(includePath string) string {
	// Direct match
	if name, ok := includeToRuleName[includePath]; ok {
		return name
	}

	// Try matching the first path component
	if idx := strings.Index(includePath, "/"); idx > 0 {
		prefix := includePath[:idx]
		if name, ok := includeToRuleName[prefix]; ok {
			return name
		}
	}

	return ""
}

// loadContextRules looks up preloaded rules matching the detected includes.
func (b *Builder) loadContextRules(includes []string) (string, error) {
	type result struct {
		name    string
		content string
	}

	seen := make(map[string]struct{})

	var results []result

	for _, inc := range includes {
		ruleName := MapIncludeToRule(inc)
		if ruleName == "" {
			continue
		}

		if _, ok := seen[ruleName]; ok {
			continue
		}

		seen[ruleName] = struct{}{}

		if content, ok := b.rules[ruleName]; ok {
			results = append(results, result{name: ruleName, content: content})
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

// ConvertModulePrompt builds the user prompt for an IR module conversion.
func (b *Builder) ConvertModulePrompt(module *ir.Module) (string, error) {
	data, err := json.MarshalIndent(module, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal module IR: %w", err)
	}

	return fmt.Sprintf(`Convert the following C/C++ module IR to a complete Go file.

Source file: %s

Module IR (JSON):
%s`, module.SourceFile, string(data)), nil
}

// ConvertRawPrompt builds the user prompt for raw C++ source conversion.
func (b *Builder) ConvertRawPrompt(filename string, source string) string {
	return fmt.Sprintf(`Convert the following C/C++ source file to a complete Go file.

Source file: %s

C++ source:
%s`, filename, source)
}
