/*
Copyright (c) 2026 Security Research
*/
package transpile

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/c_memory/function_pointers.md",
			Body: `# Function Pointers to Go func Types

## Pipeline: C → AST → IR → Go

### C Source Pattern

` + "`" + `` + "`" + `` + "`" + `c
#include <stdio.h>

// Function pointer typedef
typedef int (*comparator_t)(const void*, const void*);
typedef void (*callback_t)(int, const char*);

// Function matching the typedef
int compare_ints(const void* a, const void* b) {
    return (*(int*)a - *(int*)b);
}

void log_event(int code, const char* msg) {
    printf("[%d] %s\n", code, msg);
}

// Function accepting a function pointer
void process(int* arr, int count, comparator_t cmp) {
    // use cmp to sort
    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (cmp(&arr[i], &arr[j]) > 0) {
                int tmp = arr[i];
                arr[i] = arr[j];
                arr[j] = tmp;
            }
        }
    }
}

// Struct with function pointer member
typedef struct {
    callback_t on_event;
    void* user_data;
} event_handler_t;

void dispatch(event_handler_t* handler, int code, const char* msg) {
    if (handler->on_event != NULL) {
        handler->on_event(code, msg);
    }
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. ` + "`" + `typedef RetType (*Name)(Params)` + "`" + ` → ` + "`" + `type Name func(Params) RetType` + "`" + `
2. Function pointer parameters → ` + "`" + `func` + "`" + ` type parameters
3. NULL function pointer checks → ` + "`" + `nil` + "`" + ` checks on func values
4. ` + "`" + `void*` + "`" + ` callback data → ` + "`" + `any` + "`" + ` or typed closure captures
5. Struct with function pointer fields → struct with ` + "`" + `func` + "`" + ` fields

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

// ComparatorT is a comparison function type.
type ComparatorT func(a, b int) int

// CallbackT is an event callback function type.
type CallbackT func(code int, msg string)

func CompareInts(a, b int) int {
	return a - b
}

func LogEvent(code int, msg string) {
	fmt.Printf("[%d] %s\n", code, msg)
}

// Process sorts arr using the provided comparator.
func Process(arr []int, cmp ComparatorT) {
	for i := 0; i < len(arr)-1; i++ {
		for j := i + 1; j < len(arr); j++ {
			if cmp(arr[i], arr[j]) > 0 {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}
}

// EventHandler holds a callback for event dispatching.
type EventHandler struct {
	OnEvent  CallbackT
	UserData any
}

func Dispatch(handler *EventHandler, code int, msg string) {
	if handler.OnEvent != nil {
		handler.OnEvent(code, msg)
	}
}
` + "`" + `` + "`" + `` + "`" + `
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/c_memory/malloc_free.md",
			Body: `# malloc/free to Go Allocation

## Pipeline: C → AST → IR → Go

### C Source Pattern

` + "`" + `` + "`" + `` + "`" + `c
#include <stdlib.h>
#include <string.h>

// Single object allocation
int* create_int(int value) {
    int* p = (int*)malloc(sizeof(int));
    if (p == NULL) return NULL;
    *p = value;
    return p;
}

// Array allocation
double* create_array(size_t count) {
    double* arr = (double*)calloc(count, sizeof(double));
    if (arr == NULL) return NULL;
    return arr;
}

// Reallocation
int* grow_array(int* arr, size_t old_count, size_t new_count) {
    int* new_arr = (int*)realloc(arr, new_count * sizeof(int));
    if (new_arr == NULL) {
        free(arr);
        return NULL;
    }
    return new_arr;
}

void use_allocations() {
    int* num = create_int(42);
    double* arr = create_array(10);
    int* buf = (int*)malloc(5 * sizeof(int));

    buf = grow_array(buf, 5, 10);

    free(num);
    free(arr);
    free(buf);
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. ` + "`" + `malloc(sizeof(T))` + "`" + ` for a single object → ` + "`" + `new(T)` + "`" + ` or composite literal ` + "`" + `&T{}` + "`" + `
2. ` + "`" + `calloc(count, sizeof(T))` + "`" + ` → ` + "`" + `make([]T, count)` + "`" + ` (Go zero-initializes)
3. ` + "`" + `realloc(ptr, size)` + "`" + ` → create new slice with ` + "`" + `make` + "`" + ` + ` + "`" + `copy` + "`" + `, or use ` + "`" + `append` + "`" + `
4. ` + "`" + `free(ptr)` + "`" + ` → remove entirely (Go GC handles deallocation)
5. NULL checks after malloc → return error instead of NULL pointer
6. Cast ` + "`" + `(T*)malloc(...)` + "`" + ` → type is inferred in Go

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

// CreateInt allocates and returns a pointer to an int.
func CreateInt(value int) *int {
	p := new(int)
	*p = value
	return p
}

// CreateArray allocates a zero-initialized slice of float64.
func CreateArray(count int) []float64 {
	return make([]float64, count)
}

// GrowArray returns a new slice with increased capacity.
func GrowArray(arr []int, newCount int) []int {
	newArr := make([]int, newCount)
	copy(newArr, arr)
	return newArr
}

func UseAllocations() {
	num := CreateInt(42)
	arr := CreateArray(10)
	buf := make([]int, 5)

	buf = GrowArray(buf, 10)

	_ = num
	_ = arr
	_ = buf
	// No free() needed — GC handles cleanup
}
` + "`" + `` + "`" + `` + "`" + `
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/c_patterns/goto_labels.md",
			Body: `# goto/label Restructuring Strategies

## Pipeline: C → AST → IR → Go

### C Source Pattern

` + "`" + `` + "`" + `` + "`" + `c
#include <stdio.h>
#include <stdlib.h>

// Common pattern: goto for error cleanup
int process_file(const char* path) {
    FILE* fp = NULL;
    char* buf = NULL;
    int result = -1;

    fp = fopen(path, "r");
    if (fp == NULL) goto cleanup;

    buf = (char*)malloc(1024);
    if (buf == NULL) goto cleanup;

    if (fread(buf, 1, 1024, fp) == 0) goto cleanup;

    result = 0;

cleanup:
    free(buf);
    if (fp != NULL) fclose(fp);
    return result;
}

// Loop control with goto
void search_matrix(int matrix[3][3], int target) {
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            if (matrix[i][j] == target) {
                printf("Found at [%d][%d]\n", i, j);
                goto done;
            }
        }
    }
    printf("Not found\n");
done:
    return;
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Error cleanup goto** → ` + "`" + `defer` + "`" + ` for cleanup + early ` + "`" + `return err` + "`" + `
2. **Loop-break goto** → labeled ` + "`" + `break` + "`" + ` or restructure to use ` + "`" + `return` + "`" + `
3. **State machine goto** → ` + "`" + `for` + "`" + `/` + "`" + `switch` + "`" + ` state machine
4. **Simple forward goto** → restructure control flow with ` + "`" + `if/else` + "`" + `
5. Add ` + "`" + `// goto restructured` + "`" + ` comment when transformation is non-trivial

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"os"
)

// ProcessFile reads from a file with proper cleanup via defer.
func ProcessFile(path string) error {
	fp, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = fp.Close() }()

	buf := make([]byte, 1024)
	_, err = fp.Read(buf)
	if err != nil {
		return err
	}

	return nil
}

// SearchMatrix searches for a target value in a 3x3 matrix.
func SearchMatrix(matrix [3][3]int, target int) {
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			if matrix[i][j] == target {
				fmt.Printf("Found at [%d][%d]\n", i, j)
				return // replaces goto done
			}
		}
	}
	fmt.Println("Not found")
}
` + "`" + `` + "`" + `` + "`" + `
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/c_patterns/string_handling.md",
			Body: `# C String (char*) to Go string/[]byte

## Pipeline: C → AST → IR → Go

### C Source Pattern

` + "`" + `` + "`" + `` + "`" + `c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// String creation and copying
char* create_greeting(const char* name) {
    size_t len = strlen("Hello, ") + strlen(name) + 2;
    char* buf = (char*)malloc(len);
    if (buf == NULL) return NULL;
    sprintf(buf, "Hello, %s!", name);
    return buf;
}

// String comparison
int compare_names(const char* a, const char* b) {
    return strcmp(a, b);
}

// String searching
const char* find_extension(const char* filename) {
    const char* dot = strrchr(filename, '.');
    if (dot == NULL) return "";
    return dot + 1;
}

// String manipulation
void to_uppercase(char* str) {
    for (size_t i = 0; i < strlen(str); i++) {
        str[i] = toupper(str[i]);
    }
}

// String tokenization
void split_csv(const char* line) {
    char* copy = strdup(line);
    char* token = strtok(copy, ",");
    while (token != NULL) {
        printf("Field: %s\n", token);
        token = strtok(NULL, ",");
    }
    free(copy);
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. ` + "`" + `char*` + "`" + ` used as text → Go ` + "`" + `string` + "`" + ` (immutable, GC-managed)
2. ` + "`" + `char*` + "`" + ` used as binary buffer → Go ` + "`" + `[]byte` + "`" + `
3. ` + "`" + `strlen(s)` + "`" + ` → ` + "`" + `len(s)` + "`" + `
4. ` + "`" + `strcmp(a, b) == 0` + "`" + ` → ` + "`" + `a == b` + "`" + `
5. ` + "`" + `strcpy/strcat` + "`" + ` → string concatenation ` + "`" + `+` + "`" + ` or ` + "`" + `strings.Builder` + "`" + `
6. ` + "`" + `strstr/strchr/strrchr` + "`" + ` → ` + "`" + `strings.Contains/IndexByte/LastIndexByte` + "`" + `
7. ` + "`" + `strtok` + "`" + ` → ` + "`" + `strings.Split` + "`" + `
8. ` + "`" + `sprintf(buf, fmt, ...)` + "`" + ` → ` + "`" + `fmt.Sprintf(fmt, ...)` + "`" + `
9. ` + "`" + `toupper/tolower` + "`" + ` → ` + "`" + `strings.ToUpper/ToLower` + "`" + `
10. ` + "`" + `strdup` + "`" + ` → string assignment (strings are value types in Go)
11. ` + "`" + `malloc` + "`" + ` + string ops → direct string construction
12. ` + "`" + `free` + "`" + ` on strings → remove (GC-managed)

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"strings"
)

// CreateGreeting returns a greeting string for the given name.
func CreateGreeting(name string) string {
	return fmt.Sprintf("Hello, %s!", name)
}

// CompareNames compares two names lexicographically.
func CompareNames(a, b string) int {
	return strings.Compare(a, b)
}

// FindExtension returns the file extension without the dot.
func FindExtension(filename string) string {
	dot := strings.LastIndexByte(filename, '.')
	if dot == -1 {
		return ""
	}
	return filename[dot+1:]
}

// ToUppercase converts a string to uppercase.
func ToUppercase(str string) string {
	return strings.ToUpper(str)
}

// SplitCSV prints each field from a comma-separated line.
func SplitCSV(line string) {
	fields := strings.Split(line, ",")
	for _, field := range fields {
		fmt.Printf("Field: %s\n", field)
	}
}
` + "`" + `` + "`" + `` + "`" + `
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/c_patterns/typedef_struct.md",
			Body: `# typedef struct to Go Named Struct

## Pipeline: C → AST → IR → Go

### C Source Pattern

` + "`" + `` + "`" + `` + "`" + `c
// Anonymous struct with typedef
typedef struct {
    double x;
    double y;
} Point;

// Named struct with typedef
typedef struct node {
    int value;
    struct node* next;
} Node;

// Struct with function pointer members
typedef struct {
    int (*compare)(const void*, const void*);
    void (*destroy)(void*);
    size_t element_size;
} Collection;

// Usage
Point make_point(double x, double y) {
    Point p;
    p.x = x;
    p.y = y;
    return p;
}

Node* create_node(int value) {
    Node* n = (Node*)malloc(sizeof(Node));
    n->value = value;
    n->next = NULL;
    return n;
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. ` + "`" + `typedef struct { ... } Name` + "`" + ` → ` + "`" + `type Name struct { ... }` + "`" + `
2. ` + "`" + `typedef struct tag { ... } Name` + "`" + ` → ` + "`" + `type Name struct { ... }` + "`" + ` (ignore tag)
3. Self-referential ` + "`" + `struct node*` + "`" + ` → ` + "`" + `*Node` + "`" + ` pointer
4. Function pointer fields → ` + "`" + `func(...)` + "`" + ` type fields
5. ` + "`" + `sizeof(T)` + "`" + ` → removed (Go manages sizes)
6. Arrow operator ` + "`" + `ptr->field` + "`" + ` → dot operator ` + "`" + `ptr.Field` + "`" + `

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

// Point represents a 2D point.
type Point struct {
	X float64
	Y float64
}

// Node represents a linked list node.
type Node struct {
	Value int
	Next  *Node
}

// Collection holds function pointers for generic operations.
type Collection struct {
	Compare     func(a, b any) int
	Destroy     func(item any)
	ElementSize int
}

func MakePoint(x, y float64) Point {
	return Point{X: x, Y: y}
}

func CreateNode(value int) *Node {
	return &Node{Value: value}
}
` + "`" + `` + "`" + `` + "`" + `
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/c_patterns/variadic_functions.md",
			Body: `# va_list to Go Variadic Functions

## Pipeline: C → AST → IR → Go

### C Source Pattern

` + "`" + `` + "`" + `` + "`" + `c
#include <stdio.h>
#include <stdarg.h>

// Simple variadic function
int sum(int count, ...) {
    va_list ap;
    va_start(ap, count);

    int total = 0;
    for (int i = 0; i < count; i++) {
        total += va_arg(ap, int);
    }

    va_end(ap);
    return total;
}

// Printf-like variadic function
void log_message(const char* level, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    printf("[%s] ", level);
    vprintf(fmt, ap);
    printf("\n");

    va_end(ap);
}

// Variadic with mixed types via format string
void print_values(const char* types, ...) {
    va_list ap;
    va_start(ap, types);

    for (const char* t = types; *t != '\0'; t++) {
        switch (*t) {
        case 'd': printf("%d ", va_arg(ap, int)); break;
        case 'f': printf("%f ", va_arg(ap, double)); break;
        case 's': printf("%s ", va_arg(ap, char*)); break;
        }
    }

    va_end(ap);
    printf("\n");
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. ` + "`" + `int func(int count, ...)` + "`" + ` with known type → ` + "`" + `func(values ...int)` + "`" + `
2. ` + "`" + `va_list` + "`" + `/` + "`" + `va_start` + "`" + `/` + "`" + `va_arg` + "`" + `/` + "`" + `va_end` + "`" + ` → remove, use ` + "`" + `...Type` + "`" + ` directly
3. Printf-like variadics → ` + "`" + `func(format string, args ...any)` + "`" + ` with ` + "`" + `fmt.Sprintf` + "`" + `
4. Mixed-type variadics → ` + "`" + `func(args ...any)` + "`" + ` with type switches
5. ` + "`" + `count` + "`" + ` parameter for array length → ` + "`" + `len(args)` + "`" + ` on variadic slice

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

// Sum returns the sum of all provided integers.
func Sum(values ...int) int {
	total := 0
	for _, v := range values {
		total += v
	}
	return total
}

// LogMessage prints a formatted log message with the given level.
func LogMessage(level string, format string, args ...any) {
	fmt.Printf("[%s] %s\n", level, fmt.Sprintf(format, args...))
}

// PrintValues prints values based on type format string.
func PrintValues(types string, args ...any) {
	idx := 0
	for _, t := range types {
		if idx >= len(args) {
			break
		}
		switch t {
		case 'd':
			fmt.Printf("%d ", args[idx])
		case 'f':
			fmt.Printf("%f ", args[idx])
		case 's':
			fmt.Printf("%s ", args[idx])
		}
		idx++
	}
	fmt.Println()
}
` + "`" + `` + "`" + `` + "`" + `
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/concurrency/async_select.md",
			Body: `# Async Patterns to Select

C++ futures, promises, and event-loop patterns mapped to Go channels and ` + "`" + `select` + "`" + ` through the full pipeline.

## Pattern 1: Future and Promise to Channel

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <future>
#include <iostream>
#include <string>

std::string fetchUser(int id) {
    // simulate network call
    return "user_" + std::to_string(id);
}

double fetchBalance(int id) {
    // simulate network call
    return 1234.56;
}

int main() {
    std::future<std::string> userFut = std::async(std::launch::async, fetchUser, 42);
    std::future<double> balanceFut = std::async(std::launch::async, fetchBalance, 42);

    std::string user = userFut.get();
    double balance = balanceFut.get();

    std::cout << user << ": $" << balance << std::endl;
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "future", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    { "kind": "Include", "path": "string", "system": true },
    {
      "kind": "Function",
      "name": "fetchUser",
      "returnType": { "kind": "TypeRef", "name": "std::string" },
      "params": [
        { "kind": "Variable", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }
      ],
      "body": [
        { "kind": "ReturnStmt", "value": "\"user_\" + std::to_string(id)" }
      ]
    },
    {
      "kind": "Function",
      "name": "fetchBalance",
      "returnType": { "kind": "TypeRef", "name": "double" },
      "params": [
        { "kind": "Variable", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }
      ],
      "body": [
        { "kind": "ReturnStmt", "value": 1234.56 }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "userFut",
          "type": {
            "kind": "TypeRef",
            "name": "std::future",
            "templateArgs": [{ "kind": "TypeRef", "name": "std::string" }]
          },
          "init": {
            "kind": "CallExpr",
            "callee": "std::async",
            "args": ["std::launch::async", "fetchUser", 42]
          }
        },
        {
          "kind": "Variable",
          "name": "balanceFut",
          "type": {
            "kind": "TypeRef",
            "name": "std::future",
            "templateArgs": [{ "kind": "TypeRef", "name": "double" }]
          },
          "init": {
            "kind": "CallExpr",
            "callee": "std::async",
            "args": ["std::launch::async", "fetchBalance", 42]
          }
        },
        {
          "kind": "Variable",
          "name": "user",
          "type": { "kind": "TypeRef", "name": "std::string" },
          "init": { "kind": "CallExpr", "callee": "userFut.get" }
        },
        {
          "kind": "Variable",
          "name": "balance",
          "type": { "kind": "TypeRef", "name": "double" },
          "init": { "kind": "CallExpr", "callee": "balanceFut.get" }
        },
        {
          "kind": "CallExpr",
          "callee": "std::cout::operator<<",
          "args": ["user", "\": $\"", "balance"]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "fetchUser",
      "params": [{ "kind": "VarDecl", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }],
      "returnType": { "kind": "TypeRef", "name": "string" },
      "body": [
        { "kind": "ReturnStmt", "value": "fmt.Sprintf(\"user_%d\", id)" }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "fetchBalance",
      "params": [{ "kind": "VarDecl", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }],
      "returnType": { "kind": "TypeRef", "name": "float64" },
      "body": [
        { "kind": "ReturnStmt", "value": 1234.56 }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "userCh",
          "type": { "kind": "TypeRef", "kind": "channel", "elem": "string" },
          "init": { "kind": "MakeExpr", "type": { "kind": "channel", "elem": "string" }, "bufferSize": 1 }
        },
        {
          "kind": "VarDecl",
          "name": "balanceCh",
          "type": { "kind": "TypeRef", "kind": "channel", "elem": "float64" },
          "init": { "kind": "MakeExpr", "type": { "kind": "channel", "elem": "float64" }, "bufferSize": 1 }
        },
        {
          "kind": "GoStmt",
          "call": {
            "kind": "FuncLit",
            "body": [{ "kind": "SendStmt", "chan": "userCh", "value": { "kind": "CallExpr", "callee": "fetchUser", "args": [42] } }]
          }
        },
        {
          "kind": "GoStmt",
          "call": {
            "kind": "FuncLit",
            "body": [{ "kind": "SendStmt", "chan": "balanceCh", "value": { "kind": "CallExpr", "callee": "fetchBalance", "args": [42] } }]
          }
        },
        {
          "kind": "VarDecl",
          "name": "user",
          "init": { "kind": "RecvExpr", "chan": "userCh" }
        },
        {
          "kind": "VarDecl",
          "name": "balance",
          "init": { "kind": "RecvExpr", "chan": "balanceCh" }
        },
        {
          "kind": "CallExpr",
          "callee": "fmt.Printf",
          "args": ["\"%s: $%.2f\\n\"", "user", "balance"]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::future<T>` + "`" + ` | ` + "`" + `chan T` + "`" + ` (buffered, size 1) | Buffered channel avoids goroutine leak if result is never read |
| ` + "`" + `std::promise<T>` + "`" + ` | Send side of ` + "`" + `chan T` + "`" + ` | Promise is just the write end; in Go, any goroutine can send |
| ` + "`" + `std::async(launch::async, f, args)` + "`" + ` | ` + "`" + `go func() { ch <- f(args) }()` + "`" + ` | Launch goroutine that sends result to channel |
| ` + "`" + `future.get()` + "`" + ` | ` + "`" + `<-ch` + "`" + ` | Blocks until the goroutine sends |
| Two parallel ` + "`" + `async` + "`" + ` calls | Two goroutines, two channels | Each result has its own channel |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

func fetchUser(id int) string {
	return fmt.Sprintf("user_%d", id)
}

func fetchBalance(id int) float64 {
	return 1234.56
}

func main() {
	userCh := make(chan string, 1)
	balanceCh := make(chan float64, 1)

	go func() { userCh <- fetchUser(42) }()
	go func() { balanceCh <- fetchBalance(42) }()

	user := <-userCh
	balance := <-balanceCh

	fmt.Printf("%s: $%.2f\n", user, balance)
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 2: Packaged Task to Function Returning via Channel

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <future>
#include <functional>
#include <iostream>

int heavyComputation(int x, int y) {
    return x * y + x + y;
}

int main() {
    std::packaged_task<int(int, int)> task(heavyComputation);
    std::future<int> result = task.get_future();

    std::thread t(std::move(task), 10, 20);

    std::cout << "Result: " << result.get() << std::endl;
    t.join();
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "future", "system": true },
    { "kind": "Include", "path": "functional", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    {
      "kind": "Function",
      "name": "heavyComputation",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "params": [
        { "kind": "Variable", "name": "x", "type": { "kind": "TypeRef", "name": "int" } },
        { "kind": "Variable", "name": "y", "type": { "kind": "TypeRef", "name": "int" } }
      ],
      "body": [
        { "kind": "ReturnStmt", "value": "x * y + x + y" }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "task",
          "type": {
            "kind": "TypeRef",
            "name": "std::packaged_task",
            "templateArgs": [{ "kind": "TypeRef", "name": "int(int, int)" }]
          },
          "init": { "kind": "CallExpr", "callee": "std::packaged_task", "args": ["heavyComputation"] }
        },
        {
          "kind": "Variable",
          "name": "result",
          "type": {
            "kind": "TypeRef",
            "name": "std::future",
            "templateArgs": [{ "kind": "TypeRef", "name": "int" }]
          },
          "init": { "kind": "CallExpr", "callee": "task.get_future" }
        },
        {
          "kind": "Variable",
          "name": "t",
          "type": { "kind": "TypeRef", "name": "std::thread" },
          "init": { "kind": "CallExpr", "callee": "std::thread", "args": ["std::move(task)", 10, 20] }
        },
        {
          "kind": "CallExpr",
          "callee": "std::cout::operator<<",
          "args": ["\"Result: \"", "result.get()"]
        },
        { "kind": "CallExpr", "callee": "t.join" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "heavyComputation",
      "params": [
        { "kind": "VarDecl", "name": "x", "type": { "kind": "TypeRef", "name": "int" } },
        { "kind": "VarDecl", "name": "y", "type": { "kind": "TypeRef", "name": "int" } }
      ],
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [{ "kind": "ReturnStmt", "value": "x*y + x + y" }]
    },
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "resultCh",
          "init": { "kind": "MakeExpr", "type": { "kind": "channel", "elem": "int" }, "bufferSize": 1 }
        },
        {
          "kind": "GoStmt",
          "call": {
            "kind": "FuncLit",
            "body": [
              { "kind": "SendStmt", "chan": "resultCh", "value": { "kind": "CallExpr", "callee": "heavyComputation", "args": [10, 20] } }
            ]
          }
        },
        {
          "kind": "CallExpr",
          "callee": "fmt.Printf",
          "args": ["\"Result: %d\\n\"", { "kind": "RecvExpr", "chan": "resultCh" }]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::packaged_task<R(Args...)>` + "`" + ` | ` + "`" + `go func() { ch <- f(args) }()` + "`" + ` | The entire packaged_task + thread collapses to a goroutine |
| ` + "`" + `task.get_future()` + "`" + ` | Channel declaration | Future is the receive end of the channel |
| ` + "`" + `std::move(task)` + "`" + ` | Not needed | Go has no move semantics |
| ` + "`" + `result.get()` + "`" + ` | ` + "`" + `<-resultCh` + "`" + ` | Channel receive blocks until result available |
| Thread + join | Goroutine (no join needed for result) | Receiving from channel implicitly waits |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

func heavyComputation(x, y int) int {
	return x*y + x + y
}

func main() {
	resultCh := make(chan int, 1)

	go func() {
		resultCh <- heavyComputation(10, 20)
	}()

	fmt.Printf("Result: %d\n", <-resultCh)
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 3: Multiple Async Operations with Timeout using Select

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <future>
#include <chrono>
#include <iostream>
#include <string>

std::string queryDatabase(int id) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return "db_result_" + std::to_string(id);
}

std::string queryCache(int id) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    return "cache_result_" + std::to_string(id);
}

std::string queryExternal(int id) {
    std::this_thread::sleep_for(std::chrono::seconds(5));
    return "external_result_" + std::to_string(id);
}

int main() {
    auto dbFut = std::async(std::launch::async, queryDatabase, 1);
    auto cacheFut = std::async(std::launch::async, queryCache, 1);
    auto extFut = std::async(std::launch::async, queryExternal, 1);

    // Wait for cache with short timeout
    if (cacheFut.wait_for(std::chrono::milliseconds(50)) == std::future_status::ready) {
        std::cout << "Cache hit: " << cacheFut.get() << std::endl;
    }

    // Wait for DB with medium timeout
    if (dbFut.wait_for(std::chrono::milliseconds(200)) == std::future_status::ready) {
        std::cout << "DB result: " << dbFut.get() << std::endl;
    }

    // Wait for external with timeout
    if (extFut.wait_for(std::chrono::seconds(2)) == std::future_status::ready) {
        std::cout << "External: " << extFut.get() << std::endl;
    } else {
        std::cout << "External service timed out" << std::endl;
    }

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "future", "system": true },
    { "kind": "Include", "path": "chrono", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    { "kind": "Include", "path": "string", "system": true },
    {
      "kind": "Function",
      "name": "queryDatabase",
      "returnType": { "kind": "TypeRef", "name": "std::string" },
      "params": [{ "kind": "Variable", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }],
      "body": [
        { "kind": "CallExpr", "callee": "std::this_thread::sleep_for", "args": ["std::chrono::milliseconds(100)"] },
        { "kind": "ReturnStmt", "value": "\"db_result_\" + std::to_string(id)" }
      ]
    },
    {
      "kind": "Function",
      "name": "queryCache",
      "returnType": { "kind": "TypeRef", "name": "std::string" },
      "params": [{ "kind": "Variable", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }],
      "body": [
        { "kind": "CallExpr", "callee": "std::this_thread::sleep_for", "args": ["std::chrono::milliseconds(10)"] },
        { "kind": "ReturnStmt", "value": "\"cache_result_\" + std::to_string(id)" }
      ]
    },
    {
      "kind": "Function",
      "name": "queryExternal",
      "returnType": { "kind": "TypeRef", "name": "std::string" },
      "params": [{ "kind": "Variable", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }],
      "body": [
        { "kind": "CallExpr", "callee": "std::this_thread::sleep_for", "args": ["std::chrono::seconds(5)"] },
        { "kind": "ReturnStmt", "value": "\"external_result_\" + std::to_string(id)" }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "dbFut",
          "type": { "kind": "TypeRef", "name": "auto" },
          "init": { "kind": "CallExpr", "callee": "std::async", "args": ["std::launch::async", "queryDatabase", 1] }
        },
        {
          "kind": "Variable",
          "name": "cacheFut",
          "type": { "kind": "TypeRef", "name": "auto" },
          "init": { "kind": "CallExpr", "callee": "std::async", "args": ["std::launch::async", "queryCache", 1] }
        },
        {
          "kind": "Variable",
          "name": "extFut",
          "type": { "kind": "TypeRef", "name": "auto" },
          "init": { "kind": "CallExpr", "callee": "std::async", "args": ["std::launch::async", "queryExternal", 1] }
        },
        {
          "kind": "IfStmt",
          "cond": "cacheFut.wait_for(50ms) == ready",
          "body": [{ "kind": "CallExpr", "callee": "cout", "args": ["cacheFut.get()"] }]
        },
        {
          "kind": "IfStmt",
          "cond": "dbFut.wait_for(200ms) == ready",
          "body": [{ "kind": "CallExpr", "callee": "cout", "args": ["dbFut.get()"] }]
        },
        {
          "kind": "IfStmt",
          "cond": "extFut.wait_for(2s) == ready",
          "body": [{ "kind": "CallExpr", "callee": "cout", "args": ["extFut.get()"] }],
          "else": [{ "kind": "CallExpr", "callee": "cout", "args": ["\"timed out\""] }]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "time"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "queryDatabase",
      "params": [{ "kind": "VarDecl", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }],
      "returnType": { "kind": "TypeRef", "name": "string" },
      "body": [
        { "kind": "CallExpr", "callee": "time.Sleep", "args": ["100 * time.Millisecond"] },
        { "kind": "ReturnStmt", "value": "fmt.Sprintf(\"db_result_%d\", id)" }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "queryCache",
      "params": [{ "kind": "VarDecl", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }],
      "returnType": { "kind": "TypeRef", "name": "string" },
      "body": [
        { "kind": "CallExpr", "callee": "time.Sleep", "args": ["10 * time.Millisecond"] },
        { "kind": "ReturnStmt", "value": "fmt.Sprintf(\"cache_result_%d\", id)" }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "queryExternal",
      "params": [{ "kind": "VarDecl", "name": "id", "type": { "kind": "TypeRef", "name": "int" } }],
      "returnType": { "kind": "TypeRef", "name": "string" },
      "body": [
        { "kind": "CallExpr", "callee": "time.Sleep", "args": ["5 * time.Second"] },
        { "kind": "ReturnStmt", "value": "fmt.Sprintf(\"external_result_%d\", id)" }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "asyncQuery",
      "comment": "Helper: launch function in goroutine, return result channel",
      "params": [
        { "kind": "VarDecl", "name": "fn", "type": { "kind": "TypeRef", "name": "func() string" } }
      ],
      "returnType": { "kind": "TypeRef", "kind": "channel", "elem": "string", "direction": "recv" },
      "body": [
        {
          "kind": "VarDecl",
          "name": "ch",
          "init": { "kind": "MakeExpr", "type": { "kind": "channel", "elem": "string" }, "bufferSize": 1 }
        },
        {
          "kind": "GoStmt",
          "call": {
            "kind": "FuncLit",
            "body": [{ "kind": "SendStmt", "chan": "ch", "value": { "kind": "CallExpr", "callee": "fn" } }]
          }
        },
        { "kind": "ReturnStmt", "value": "ch" }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "dbCh",
          "init": { "kind": "CallExpr", "callee": "asyncQuery", "args": ["func() string { return queryDatabase(1) }"] }
        },
        {
          "kind": "VarDecl",
          "name": "cacheCh",
          "init": { "kind": "CallExpr", "callee": "asyncQuery", "args": ["func() string { return queryCache(1) }"] }
        },
        {
          "kind": "VarDecl",
          "name": "extCh",
          "init": { "kind": "CallExpr", "callee": "asyncQuery", "args": ["func() string { return queryExternal(1) }"] }
        },
        {
          "kind": "SelectStmt",
          "cases": [
            { "kind": "RecvCase", "chan": "cacheCh", "var": "result", "body": [{ "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"Cache hit: %s\\n\"", "result"] }] },
            { "kind": "TimeoutCase", "duration": "50 * time.Millisecond", "body": [{ "kind": "CallExpr", "callee": "fmt.Println", "args": ["\"Cache miss\""] }] }
          ]
        },
        {
          "kind": "SelectStmt",
          "cases": [
            { "kind": "RecvCase", "chan": "dbCh", "var": "result", "body": [{ "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"DB result: %s\\n\"", "result"] }] },
            { "kind": "TimeoutCase", "duration": "200 * time.Millisecond", "body": [{ "kind": "CallExpr", "callee": "fmt.Println", "args": ["\"DB timed out\""] }] }
          ]
        },
        {
          "kind": "SelectStmt",
          "cases": [
            { "kind": "RecvCase", "chan": "extCh", "var": "result", "body": [{ "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"External: %s\\n\"", "result"] }] },
            { "kind": "TimeoutCase", "duration": "2 * time.Second", "body": [{ "kind": "CallExpr", "callee": "fmt.Println", "args": ["\"External service timed out\""] }] }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::async` + "`" + ` + ` + "`" + `std::future` + "`" + ` | Goroutine + ` + "`" + `chan T` + "`" + ` | Goroutine writes result; channel is the future |
| ` + "`" + `future.wait_for(duration)` + "`" + ` | ` + "`" + `select` + "`" + ` with ` + "`" + `time.After(duration)` + "`" + ` | Select provides non-blocking timeout on channel receive |
| ` + "`" + `future_status::ready` + "`" + ` check | ` + "`" + `case result := <-ch` + "`" + ` | Select case fires when channel has data |
| ` + "`" + `future_status::timeout` + "`" + ` | ` + "`" + `case <-time.After(d)` + "`" + ` | Timeout case fires if channel has no data in time |
| Multiple sequential ` + "`" + `wait_for` + "`" + ` | Multiple ` + "`" + `select` + "`" + ` blocks | Each async result gets its own select with timeout |
| ` + "`" + `std::chrono::milliseconds(n)` + "`" + ` | ` + "`" + `n * time.Millisecond` + "`" + ` | Direct duration mapping |
| ` + "`" + `std::chrono::seconds(n)` + "`" + ` | ` + "`" + `n * time.Second` + "`" + ` | Direct duration mapping |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"time"
)

func queryDatabase(id int) string {
	time.Sleep(100 * time.Millisecond)
	return fmt.Sprintf("db_result_%d", id)
}

func queryCache(id int) string {
	time.Sleep(10 * time.Millisecond)
	return fmt.Sprintf("cache_result_%d", id)
}

func queryExternal(id int) string {
	time.Sleep(5 * time.Second)
	return fmt.Sprintf("external_result_%d", id)
}

func asyncQuery(fn func() string) <-chan string {
	ch := make(chan string, 1)
	go func() {
		ch <- fn()
	}()
	return ch
}

func main() {
	dbCh := asyncQuery(func() string { return queryDatabase(1) })
	cacheCh := asyncQuery(func() string { return queryCache(1) })
	extCh := asyncQuery(func() string { return queryExternal(1) })

	// Wait for cache with short timeout
	select {
	case result := <-cacheCh:
		fmt.Printf("Cache hit: %s\n", result)
	case <-time.After(50 * time.Millisecond):
		fmt.Println("Cache miss")
	}

	// Wait for DB with medium timeout
	select {
	case result := <-dbCh:
		fmt.Printf("DB result: %s\n", result)
	case <-time.After(200 * time.Millisecond):
		fmt.Println("DB timed out")
	}

	// Wait for external with long timeout
	select {
	case result := <-extCh:
		fmt.Printf("External: %s\n", result)
	case <-time.After(2 * time.Second):
		fmt.Println("External service timed out")
	}
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 4: Event Loop with Select

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <chrono>

class EventLoop {
public:
    void post(std::function<void()> handler) {
        std::lock_guard<std::mutex> lock(mu_);
        events_.push(std::move(handler));
        cv_.notify_one();
    }

    void runFor(std::chrono::milliseconds duration) {
        auto deadline = std::chrono::steady_clock::now() + duration;
        while (std::chrono::steady_clock::now() < deadline) {
            std::function<void()> handler;
            {
                std::unique_lock<std::mutex> lock(mu_);
                auto remaining = deadline - std::chrono::steady_clock::now();
                if (!cv_.wait_for(lock, remaining, [this] { return !events_.empty(); })) {
                    break;
                }
                handler = std::move(events_.front());
                events_.pop();
            }
            handler();
        }
    }

    void stop() { done_.store(true); cv_.notify_all(); }

private:
    std::queue<std::function<void()>> events_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::atomic<bool> done_{false};
};
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "thread", "system": true },
    { "kind": "Include", "path": "atomic", "system": true },
    { "kind": "Include", "path": "queue", "system": true },
    { "kind": "Include", "path": "mutex", "system": true },
    { "kind": "Include", "path": "condition_variable", "system": true },
    { "kind": "Include", "path": "functional", "system": true },
    { "kind": "Include", "path": "chrono", "system": true },
    {
      "kind": "Class",
      "name": "EventLoop",
      "members": [
        {
          "kind": "Function",
          "name": "post",
          "params": [
            {
              "kind": "Variable",
              "name": "handler",
              "type": { "kind": "TypeRef", "name": "std::function", "templateArgs": [{ "kind": "TypeRef", "name": "void()" }] }
            }
          ],
          "access": "public"
        },
        {
          "kind": "Function",
          "name": "runFor",
          "params": [
            {
              "kind": "Variable",
              "name": "duration",
              "type": { "kind": "TypeRef", "name": "std::chrono::milliseconds" }
            }
          ],
          "access": "public"
        },
        {
          "kind": "Function",
          "name": "stop",
          "access": "public"
        },
        {
          "kind": "Variable", "name": "events_",
          "type": { "kind": "TypeRef", "name": "std::queue", "templateArgs": [{ "kind": "TypeRef", "name": "std::function<void()>" }] },
          "access": "private"
        },
        { "kind": "Variable", "name": "mu_", "type": { "kind": "TypeRef", "name": "std::mutex" }, "access": "private" },
        { "kind": "Variable", "name": "cv_", "type": { "kind": "TypeRef", "name": "std::condition_variable" }, "access": "private" },
        {
          "kind": "Variable", "name": "done_",
          "type": { "kind": "TypeRef", "name": "std::atomic", "templateArgs": [{ "kind": "TypeRef", "name": "bool" }] },
          "access": "private", "init": false
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "time"],
  "decls": [
    {
      "kind": "TypeDecl",
      "name": "EventLoop",
      "fields": [
        {
          "kind": "VarDecl",
          "name": "events",
          "type": { "kind": "TypeRef", "kind": "channel", "elem": "func()" }
        },
        {
          "kind": "VarDecl",
          "name": "done",
          "type": { "kind": "TypeRef", "kind": "channel", "elem": "struct{}" }
        }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "NewEventLoop",
      "params": [{ "kind": "VarDecl", "name": "bufferSize", "type": { "kind": "TypeRef", "name": "int" } }],
      "returnType": { "kind": "TypeRef", "name": "*EventLoop" },
      "body": [
        {
          "kind": "ReturnStmt",
          "value": {
            "kind": "CompositeLit",
            "type": "EventLoop",
            "fields": {
              "events": { "kind": "MakeExpr", "type": { "kind": "channel", "elem": "func()" }, "bufferSize": "bufferSize" },
              "done": { "kind": "MakeExpr", "type": { "kind": "channel", "elem": "struct{}" } }
            }
          }
        }
      ]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "el", "type": "*EventLoop" },
      "name": "Post",
      "params": [{ "kind": "VarDecl", "name": "handler", "type": { "kind": "TypeRef", "name": "func()" } }],
      "body": [{ "kind": "SendStmt", "chan": "el.events", "value": "handler" }]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "el", "type": "*EventLoop" },
      "name": "RunFor",
      "params": [{ "kind": "VarDecl", "name": "duration", "type": { "kind": "TypeRef", "name": "time.Duration" } }],
      "body": [
        {
          "kind": "VarDecl",
          "name": "timer",
          "init": { "kind": "CallExpr", "callee": "time.After", "args": ["duration"] }
        },
        {
          "kind": "ForStmt",
          "body": [
            {
              "kind": "SelectStmt",
              "cases": [
                { "kind": "RecvCase", "chan": "el.events", "var": "handler", "body": [{ "kind": "CallExpr", "callee": "handler" }] },
                { "kind": "RecvCase", "chan": "el.done", "body": [{ "kind": "ReturnStmt" }] },
                { "kind": "RecvCase", "chan": "timer", "body": [{ "kind": "ReturnStmt" }] }
              ]
            }
          ]
        }
      ]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "el", "type": "*EventLoop" },
      "name": "Stop",
      "body": [{ "kind": "CallExpr", "callee": "close", "args": ["el.done"] }]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `EventLoop` + "`" + ` class | Struct with ` + "`" + `chan func()` + "`" + ` + ` + "`" + `chan struct{}` + "`" + ` | Event channel replaces queue+mutex+condvar; done channel for stop |
| ` + "`" + `post(handler)` + "`" + ` | ` + "`" + `el.events <- handler` + "`" + ` | Channel send replaces locked enqueue |
| ` + "`" + `runFor(duration)` + "`" + ` with condvar wait | ` + "`" + `select` + "`" + ` with ` + "`" + `time.After` + "`" + ` | Select multiplexes events, done signal, and timeout |
| ` + "`" + `stop()` + "`" + ` with atomic + notify_all | ` + "`" + `close(el.done)` + "`" + ` | Closing done channel unblocks select in all iterations |
| Event loop poll cycle | ` + "`" + `for { select { ... } }` + "`" + ` | Infinite select loop is the idiomatic Go event loop |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"time"
)

type EventLoop struct {
	events chan func()
	done   chan struct{}
}

func NewEventLoop(bufferSize int) *EventLoop {
	return &EventLoop{
		events: make(chan func(), bufferSize),
		done:   make(chan struct{}),
	}
}

func (el *EventLoop) Post(handler func()) {
	el.events <- handler
}

func (el *EventLoop) RunFor(duration time.Duration) {
	timer := time.After(duration)
	for {
		select {
		case handler := <-el.events:
			handler()
		case <-el.done:
			return
		case <-timer:
			return
		}
	}
}

func (el *EventLoop) Stop() {
	close(el.done)
}

func main() {
	el := NewEventLoop(100)

	go func() {
		for i := 0; i < 5; i++ {
			i := i
			el.Post(func() {
				fmt.Printf("Event %d handled\n", i)
			})
			time.Sleep(50 * time.Millisecond)
		}
	}()

	el.RunFor(500 * time.Millisecond)
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Pattern | Notes |
|---|---|---|
| ` + "`" + `std::future<T>` + "`" + ` | ` + "`" + `chan T` + "`" + ` (buffered, size 1) | Channel is the Go future; buffer prevents goroutine leak |
| ` + "`" + `std::promise<T>` + "`" + ` | Send side of ` + "`" + `chan T` + "`" + ` | No separate promise type in Go |
| ` + "`" + `std::async(launch::async, f)` + "`" + ` | ` + "`" + `go func() { ch <- f() }()` + "`" + ` | Goroutine + channel replaces async launch |
| ` + "`" + `future.get()` + "`" + ` | ` + "`" + `<-ch` + "`" + ` | Blocking receive |
| ` + "`" + `future.wait_for(duration)` + "`" + ` | ` + "`" + `select` + "`" + ` with ` + "`" + `time.After(d)` + "`" + ` | Non-blocking timeout check |
| ` + "`" + `future_status::ready` + "`" + ` | ` + "`" + `case v := <-ch` + "`" + ` | Select case fires on ready |
| ` + "`" + `future_status::timeout` + "`" + ` | ` + "`" + `case <-time.After(d)` + "`" + ` | Timeout arm of select |
| ` + "`" + `std::packaged_task` + "`" + ` | Goroutine sending to channel | No separate abstraction needed |
| ` + "`" + `std::chrono::milliseconds(n)` + "`" + ` | ` + "`" + `n * time.Millisecond` + "`" + ` | Duration type mapping |
| Event loop with condvar | ` + "`" + `for { select { ... } }` + "`" + ` | Select is the native multiplexer |
| ` + "`" + `cv.wait_for(lock, dur, pred)` + "`" + ` | ` + "`" + `select` + "`" + ` with timeout | Select replaces timed condvar wait |
| Multiple futures polled | Multiple ` + "`" + `select` + "`" + ` blocks | Each result gets its own select |
| ` + "`" + `std::launch::deferred` + "`" + ` | Direct function call (no goroutine) | Deferred = synchronous = just call it |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/concurrency/mutex_channels.md",
			Body: `# Mutex and Synchronization to Channels

C++ mutual exclusion and synchronization primitives mapped to Go equivalents through the full pipeline.

## Pattern 1: Mutex with Lock Guard

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <mutex>
#include <vector>
#include <thread>
#include <iostream>

class SafeCounter {
public:
    void increment(const std::string& key) {
        std::lock_guard<std::mutex> lock(mu_);
        counts_[key]++;
    }

    int get(const std::string& key) {
        std::lock_guard<std::mutex> lock(mu_);
        return counts_[key];
    }

private:
    std::mutex mu_;
    std::map<std::string, int> counts_;
};

int main() {
    SafeCounter counter;
    std::vector<std::thread> threads;

    for (int i = 0; i < 100; ++i) {
        threads.emplace_back([&counter] {
            counter.increment("hits");
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    std::cout << "Final count: " << counter.get("hits") << std::endl;
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "mutex", "system": true },
    { "kind": "Include", "path": "vector", "system": true },
    { "kind": "Include", "path": "thread", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    {
      "kind": "Class",
      "name": "SafeCounter",
      "members": [
        {
          "kind": "Function",
          "name": "increment",
          "returnType": { "kind": "TypeRef", "name": "void" },
          "params": [
            {
              "kind": "Variable",
              "name": "key",
              "type": { "kind": "TypeRef", "name": "std::string", "const": true, "ref": true }
            }
          ],
          "access": "public",
          "body": [
            {
              "kind": "Variable",
              "name": "lock",
              "type": {
                "kind": "TypeRef",
                "name": "std::lock_guard",
                "templateArgs": [{ "kind": "TypeRef", "name": "std::mutex" }]
              },
              "init": { "kind": "CallExpr", "callee": "std::lock_guard", "args": ["mu_"] }
            },
            { "kind": "ExprStmt", "expr": "counts_[key]++" }
          ]
        },
        {
          "kind": "Function",
          "name": "get",
          "returnType": { "kind": "TypeRef", "name": "int" },
          "params": [
            {
              "kind": "Variable",
              "name": "key",
              "type": { "kind": "TypeRef", "name": "std::string", "const": true, "ref": true }
            }
          ],
          "access": "public",
          "body": [
            {
              "kind": "Variable",
              "name": "lock",
              "type": {
                "kind": "TypeRef",
                "name": "std::lock_guard",
                "templateArgs": [{ "kind": "TypeRef", "name": "std::mutex" }]
              }
            },
            { "kind": "ReturnStmt", "value": "counts_[key]" }
          ]
        },
        {
          "kind": "Variable",
          "name": "mu_",
          "type": { "kind": "TypeRef", "name": "std::mutex" },
          "access": "private"
        },
        {
          "kind": "Variable",
          "name": "counts_",
          "type": {
            "kind": "TypeRef",
            "name": "std::map",
            "templateArgs": [
              { "kind": "TypeRef", "name": "std::string" },
              { "kind": "TypeRef", "name": "int" }
            ]
          },
          "access": "private"
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "sync"],
  "decls": [
    {
      "kind": "TypeDecl",
      "name": "SafeCounter",
      "fields": [
        { "kind": "VarDecl", "name": "mu", "type": { "kind": "TypeRef", "name": "sync.Mutex" } },
        {
          "kind": "VarDecl",
          "name": "counts",
          "type": { "kind": "TypeRef", "kind": "map", "key": "string", "value": "int" }
        }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "NewSafeCounter",
      "returnType": { "kind": "TypeRef", "name": "*SafeCounter" },
      "body": [
        {
          "kind": "ReturnStmt",
          "value": {
            "kind": "CompositeLit",
            "type": "SafeCounter",
            "fields": {
              "counts": { "kind": "MakeExpr", "type": { "kind": "map", "key": "string", "value": "int" } }
            }
          }
        }
      ]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "c", "type": "*SafeCounter" },
      "name": "Increment",
      "params": [{ "kind": "VarDecl", "name": "key", "type": { "kind": "TypeRef", "name": "string" } }],
      "body": [
        { "kind": "CallExpr", "callee": "c.mu.Lock" },
        { "kind": "DeferStmt", "call": { "kind": "CallExpr", "callee": "c.mu.Unlock" } },
        { "kind": "ExprStmt", "expr": "c.counts[key]++" }
      ]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "c", "type": "*SafeCounter" },
      "name": "Get",
      "params": [{ "kind": "VarDecl", "name": "key", "type": { "kind": "TypeRef", "name": "string" } }],
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        { "kind": "CallExpr", "callee": "c.mu.Lock" },
        { "kind": "DeferStmt", "call": { "kind": "CallExpr", "callee": "c.mu.Unlock" } },
        { "kind": "ReturnStmt", "value": "c.counts[key]" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::mutex` + "`" + ` | ` + "`" + `sync.Mutex` + "`" + ` | Direct equivalent |
| ` + "`" + `std::lock_guard<std::mutex>` + "`" + ` | ` + "`" + `mu.Lock()` + "`" + ` + ` + "`" + `defer mu.Unlock()` + "`" + ` | ` + "`" + `defer` + "`" + ` guarantees unlock on all exit paths, like RAII |
| ` + "`" + `class` + "`" + ` with private mutex | ` + "`" + `struct` + "`" + ` with unexported mutex field | Mutex embedded in struct, not exposed |
| ` + "`" + `std::map<K,V>` + "`" + ` (private) | ` + "`" + `map[K]V` + "`" + ` field | Map requires initialization in constructor |
| Constructor | ` + "`" + `NewSafeCounter()` + "`" + ` factory | Idiomatic Go factory function |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sync"
)

type SafeCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewSafeCounter() *SafeCounter {
	return &SafeCounter{
		counts: make(map[string]int),
	}
}

func (c *SafeCounter) Increment(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[key]++
}

func (c *SafeCounter) Get(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[key]
}

func main() {
	counter := NewSafeCounter()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counter.Increment("hits")
		}()
	}

	wg.Wait()
	fmt.Printf("Final count: %d\n", counter.Get("hits"))
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 2: Shared Mutex (Read-Write Lock)

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <shared_mutex>
#include <string>
#include <map>

class Config {
public:
    std::string get(const std::string& key) const {
        std::shared_lock<std::shared_mutex> lock(mu_);
        auto it = data_.find(key);
        if (it != data_.end()) return it->second;
        return "";
    }

    void set(const std::string& key, const std::string& value) {
        std::unique_lock<std::shared_mutex> lock(mu_);
        data_[key] = value;
    }

private:
    mutable std::shared_mutex mu_;
    std::map<std::string, std::string> data_;
};
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "shared_mutex", "system": true },
    { "kind": "Include", "path": "string", "system": true },
    { "kind": "Include", "path": "map", "system": true },
    {
      "kind": "Class",
      "name": "Config",
      "members": [
        {
          "kind": "Function",
          "name": "get",
          "returnType": { "kind": "TypeRef", "name": "std::string" },
          "params": [
            { "kind": "Variable", "name": "key", "type": { "kind": "TypeRef", "name": "std::string", "const": true, "ref": true } }
          ],
          "const": true,
          "access": "public",
          "body": [
            {
              "kind": "Variable",
              "name": "lock",
              "type": {
                "kind": "TypeRef",
                "name": "std::shared_lock",
                "templateArgs": [{ "kind": "TypeRef", "name": "std::shared_mutex" }]
              }
            },
            { "kind": "IfStmt", "cond": "it != data_.end()", "body": [{ "kind": "ReturnStmt", "value": "it->second" }] },
            { "kind": "ReturnStmt", "value": "\"\"" }
          ]
        },
        {
          "kind": "Function",
          "name": "set",
          "returnType": { "kind": "TypeRef", "name": "void" },
          "params": [
            { "kind": "Variable", "name": "key", "type": { "kind": "TypeRef", "name": "std::string", "const": true, "ref": true } },
            { "kind": "Variable", "name": "value", "type": { "kind": "TypeRef", "name": "std::string", "const": true, "ref": true } }
          ],
          "access": "public"
        },
        {
          "kind": "Variable",
          "name": "mu_",
          "type": { "kind": "TypeRef", "name": "std::shared_mutex" },
          "access": "private",
          "mutable": true
        },
        {
          "kind": "Variable",
          "name": "data_",
          "type": {
            "kind": "TypeRef",
            "name": "std::map",
            "templateArgs": [
              { "kind": "TypeRef", "name": "std::string" },
              { "kind": "TypeRef", "name": "std::string" }
            ]
          },
          "access": "private"
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["sync"],
  "decls": [
    {
      "kind": "TypeDecl",
      "name": "Config",
      "fields": [
        { "kind": "VarDecl", "name": "mu", "type": { "kind": "TypeRef", "name": "sync.RWMutex" } },
        {
          "kind": "VarDecl",
          "name": "data",
          "type": { "kind": "TypeRef", "kind": "map", "key": "string", "value": "string" }
        }
      ]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "c", "type": "*Config" },
      "name": "Get",
      "params": [{ "kind": "VarDecl", "name": "key", "type": { "kind": "TypeRef", "name": "string" } }],
      "returnType": { "kind": "TypeRef", "name": "string" },
      "body": [
        { "kind": "CallExpr", "callee": "c.mu.RLock" },
        { "kind": "DeferStmt", "call": { "kind": "CallExpr", "callee": "c.mu.RUnlock" } },
        { "kind": "ReturnStmt", "value": "c.data[key]" }
      ]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "c", "type": "*Config" },
      "name": "Set",
      "params": [
        { "kind": "VarDecl", "name": "key", "type": { "kind": "TypeRef", "name": "string" } },
        { "kind": "VarDecl", "name": "value", "type": { "kind": "TypeRef", "name": "string" } }
      ],
      "body": [
        { "kind": "CallExpr", "callee": "c.mu.Lock" },
        { "kind": "DeferStmt", "call": { "kind": "CallExpr", "callee": "c.mu.Unlock" } },
        { "kind": "AssignStmt", "target": "c.data[key]", "value": "value" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::shared_mutex` + "`" + ` | ` + "`" + `sync.RWMutex` + "`" + ` | Both support multiple readers or single writer |
| ` + "`" + `std::shared_lock` + "`" + ` (read lock) | ` + "`" + `mu.RLock()` + "`" + ` + ` + "`" + `defer mu.RUnlock()` + "`" + ` | Allows concurrent readers |
| ` + "`" + `std::unique_lock` + "`" + ` (write lock) | ` + "`" + `mu.Lock()` + "`" + ` + ` + "`" + `defer mu.Unlock()` + "`" + ` | Exclusive write access |
| ` + "`" + `mutable` + "`" + ` keyword | Not needed | Go has no ` + "`" + `const` + "`" + ` methods; receiver mutability determined by pointer |
| ` + "`" + `find != end` + "`" + ` pattern | Direct map access | Go maps return zero value for missing keys |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "sync"

type Config struct {
	mu   sync.RWMutex
	data map[string]string
}

func NewConfig() *Config {
	return &Config{
		data: make(map[string]string),
	}
}

func (c *Config) Get(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data[key]
}

func (c *Config) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 3: Atomic Operations

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <atomic>
#include <thread>
#include <vector>
#include <iostream>

class Stats {
public:
    void recordHit() { hits_.fetch_add(1, std::memory_order_relaxed); }
    void recordError() { errors_.fetch_add(1, std::memory_order_relaxed); }
    int64_t getHits() const { return hits_.load(std::memory_order_relaxed); }
    int64_t getErrors() const { return errors_.load(std::memory_order_relaxed); }

private:
    std::atomic<int64_t> hits_{0};
    std::atomic<int64_t> errors_{0};
};
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "atomic", "system": true },
    {
      "kind": "Class",
      "name": "Stats",
      "members": [
        {
          "kind": "Function",
          "name": "recordHit",
          "access": "public",
          "body": [
            { "kind": "CallExpr", "callee": "hits_.fetch_add", "args": [1, "std::memory_order_relaxed"] }
          ]
        },
        {
          "kind": "Function",
          "name": "recordError",
          "access": "public",
          "body": [
            { "kind": "CallExpr", "callee": "errors_.fetch_add", "args": [1, "std::memory_order_relaxed"] }
          ]
        },
        {
          "kind": "Function",
          "name": "getHits",
          "returnType": { "kind": "TypeRef", "name": "int64_t" },
          "const": true,
          "access": "public"
        },
        {
          "kind": "Function",
          "name": "getErrors",
          "returnType": { "kind": "TypeRef", "name": "int64_t" },
          "const": true,
          "access": "public"
        },
        {
          "kind": "Variable",
          "name": "hits_",
          "type": {
            "kind": "TypeRef",
            "name": "std::atomic",
            "templateArgs": [{ "kind": "TypeRef", "name": "int64_t" }]
          },
          "access": "private",
          "init": 0
        },
        {
          "kind": "Variable",
          "name": "errors_",
          "type": {
            "kind": "TypeRef",
            "name": "std::atomic",
            "templateArgs": [{ "kind": "TypeRef", "name": "int64_t" }]
          },
          "access": "private",
          "init": 0
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["sync/atomic"],
  "decls": [
    {
      "kind": "TypeDecl",
      "name": "Stats",
      "fields": [
        { "kind": "VarDecl", "name": "hits", "type": { "kind": "TypeRef", "name": "atomic.Int64" } },
        { "kind": "VarDecl", "name": "errors", "type": { "kind": "TypeRef", "name": "atomic.Int64" } }
      ]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "s", "type": "*Stats" },
      "name": "RecordHit",
      "body": [{ "kind": "CallExpr", "callee": "s.hits.Add", "args": [1] }]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "s", "type": "*Stats" },
      "name": "RecordError",
      "body": [{ "kind": "CallExpr", "callee": "s.errors.Add", "args": [1] }]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "s", "type": "*Stats" },
      "name": "GetHits",
      "returnType": { "kind": "TypeRef", "name": "int64" },
      "body": [{ "kind": "ReturnStmt", "value": { "kind": "CallExpr", "callee": "s.hits.Load" } }]
    },
    {
      "kind": "FuncDecl",
      "receiver": { "name": "s", "type": "*Stats" },
      "name": "GetErrors",
      "returnType": { "kind": "TypeRef", "name": "int64" },
      "body": [{ "kind": "ReturnStmt", "value": { "kind": "CallExpr", "callee": "s.errors.Load" } }]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::atomic<int64_t>` + "`" + ` | ` + "`" + `atomic.Int64` + "`" + ` | Go 1.19+ typed atomics are safer and cleaner |
| ` + "`" + `fetch_add(1, order)` + "`" + ` | ` + "`" + `.Add(1)` + "`" + ` | Go atomics do not expose memory ordering (sequential consistency) |
| ` + "`" + `load(order)` + "`" + ` | ` + "`" + `.Load()` + "`" + ` | Same semantics, no ordering parameter |
| ` + "`" + `store(val, order)` + "`" + ` | ` + "`" + `.Store(val)` + "`" + ` | Direct mapping |
| ` + "`" + `compare_exchange_strong` + "`" + ` | ` + "`" + `.CompareAndSwap(old, new)` + "`" + ` | Returns bool only (no output parameter) |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "sync/atomic"

type Stats struct {
	hits   atomic.Int64
	errors atomic.Int64
}

func (s *Stats) RecordHit()      { s.hits.Add(1) }
func (s *Stats) RecordError()    { s.errors.Add(1) }
func (s *Stats) GetHits() int64  { return s.hits.Load() }
func (s *Stats) GetErrors() int64 { return s.errors.Load() }
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 4: Producer-Consumer with Condition Variable

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <iostream>

class Channel {
public:
    void send(int value) {
        std::lock_guard<std::mutex> lock(mu_);
        queue_.push(value);
        cv_.notify_one();
    }

    int receive() {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [this] { return !queue_.empty() || closed_; });
        if (queue_.empty()) return -1;
        int val = queue_.front();
        queue_.pop();
        return val;
    }

    void close() {
        std::lock_guard<std::mutex> lock(mu_);
        closed_ = true;
        cv_.notify_all();
    }

private:
    std::queue<int> queue_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool closed_ = false;
};

int main() {
    Channel ch;

    std::thread producer([&ch] {
        for (int i = 0; i < 10; ++i) {
            ch.send(i * i);
        }
        ch.close();
    });

    std::thread consumer([&ch] {
        while (true) {
            int val = ch.receive();
            if (val == -1) break;
            std::cout << "Received: " << val << std::endl;
        }
    });

    producer.join();
    consumer.join();
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "thread", "system": true },
    { "kind": "Include", "path": "mutex", "system": true },
    { "kind": "Include", "path": "condition_variable", "system": true },
    { "kind": "Include", "path": "queue", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    {
      "kind": "Class",
      "name": "Channel",
      "members": [
        {
          "kind": "Function",
          "name": "send",
          "params": [{ "kind": "Variable", "name": "value", "type": { "kind": "TypeRef", "name": "int" } }],
          "access": "public"
        },
        {
          "kind": "Function",
          "name": "receive",
          "returnType": { "kind": "TypeRef", "name": "int" },
          "access": "public"
        },
        {
          "kind": "Function",
          "name": "close",
          "access": "public"
        },
        { "kind": "Variable", "name": "queue_", "type": { "kind": "TypeRef", "name": "std::queue", "templateArgs": [{ "kind": "TypeRef", "name": "int" }] }, "access": "private" },
        { "kind": "Variable", "name": "mu_", "type": { "kind": "TypeRef", "name": "std::mutex" }, "access": "private" },
        { "kind": "Variable", "name": "cv_", "type": { "kind": "TypeRef", "name": "std::condition_variable" }, "access": "private" },
        { "kind": "Variable", "name": "closed_", "type": { "kind": "TypeRef", "name": "bool" }, "access": "private", "init": false }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        { "kind": "Variable", "name": "ch", "type": { "kind": "TypeRef", "name": "Channel" } },
        {
          "kind": "Variable",
          "name": "producer",
          "type": { "kind": "TypeRef", "name": "std::thread" },
          "init": { "kind": "CallExpr", "callee": "std::thread", "args": ["lambda: send squares, close"] }
        },
        {
          "kind": "Variable",
          "name": "consumer",
          "type": { "kind": "TypeRef", "name": "std::thread" },
          "init": { "kind": "CallExpr", "callee": "std::thread", "args": ["lambda: receive and print"] }
        },
        { "kind": "CallExpr", "callee": "producer.join" },
        { "kind": "CallExpr", "callee": "consumer.join" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "sync"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "ch",
          "type": { "kind": "TypeRef", "kind": "channel", "elem": "int" },
          "init": { "kind": "MakeExpr", "type": { "kind": "channel", "elem": "int" } }
        },
        {
          "kind": "VarDecl",
          "name": "wg",
          "type": { "kind": "TypeRef", "name": "sync.WaitGroup" }
        },
        {
          "kind": "ExprStmt",
          "expr": { "kind": "CallExpr", "callee": "wg.Add", "args": [2] }
        },
        {
          "kind": "GoStmt",
          "comment": "producer",
          "call": {
            "kind": "FuncLit",
            "body": [
              { "kind": "DeferStmt", "call": { "kind": "CallExpr", "callee": "wg.Done" } },
              { "kind": "DeferStmt", "call": { "kind": "CallExpr", "callee": "close", "args": ["ch"] } },
              {
                "kind": "ForStmt",
                "init": { "kind": "VarDecl", "name": "i", "init": 0 },
                "cond": "i < 10",
                "body": [
                  { "kind": "SendStmt", "chan": "ch", "value": "i * i" }
                ]
              }
            ]
          }
        },
        {
          "kind": "GoStmt",
          "comment": "consumer",
          "call": {
            "kind": "FuncLit",
            "body": [
              { "kind": "DeferStmt", "call": { "kind": "CallExpr", "callee": "wg.Done" } },
              {
                "kind": "RangeStmt",
                "value": "val",
                "collection": "ch",
                "body": [
                  { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"Received: %d\\n\"", "val"] }
                ]
              }
            ]
          }
        },
        { "kind": "CallExpr", "callee": "wg.Wait" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::queue` + "`" + ` + mutex + condvar | ` + "`" + `chan int` + "`" + ` | Go channel is a built-in concurrent queue |
| ` + "`" + `Channel` + "`" + ` class (entire thing) | ` + "`" + `chan int` + "`" + ` | The whole class is replaced by a single channel |
| ` + "`" + `send(value)` + "`" + ` | ` + "`" + `ch <- value` + "`" + ` | Channel send |
| ` + "`" + `receive()` + "`" + ` | ` + "`" + `val := <-ch` + "`" + ` or ` + "`" + `for val := range ch` + "`" + ` | Channel receive; range exits on close |
| ` + "`" + `close()` + "`" + ` with notify_all | ` + "`" + `close(ch)` + "`" + ` | Closing channel unblocks all receivers |
| ` + "`" + `cv_.wait(lock, pred)` + "`" + ` | Implicit in ` + "`" + `<-ch` + "`" + ` | Channel receive blocks until data or close |
| Sentinel value ` + "`" + `-1` + "`" + ` for closed | Range loop exits on close | No sentinel needed; ` + "`" + `range` + "`" + ` detects closed channel |
| Producer + consumer threads | ` + "`" + `go func()` + "`" + ` | Goroutines replace threads |
| ` + "`" + `join()` + "`" + ` both threads | ` + "`" + `wg.Wait()` + "`" + ` | WaitGroup replaces explicit joins |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sync"
)

func main() {
	ch := make(chan int)
	var wg sync.WaitGroup
	wg.Add(2)

	// Producer
	go func() {
		defer wg.Done()
		defer close(ch)
		for i := 0; i < 10; i++ {
			ch <- i * i
		}
	}()

	// Consumer
	go func() {
		defer wg.Done()
		for val := range ch {
			fmt.Printf("Received: %d\n", val)
		}
	}()

	wg.Wait()
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Pattern | Notes |
|---|---|---|
| ` + "`" + `std::mutex` + "`" + ` | ` + "`" + `sync.Mutex` + "`" + ` | Direct equivalent |
| ` + "`" + `std::lock_guard<std::mutex>` + "`" + ` | ` + "`" + `mu.Lock()` + "`" + ` + ` + "`" + `defer mu.Unlock()` + "`" + ` | ` + "`" + `defer` + "`" + ` ensures unlock on all paths |
| ` + "`" + `std::unique_lock<std::mutex>` + "`" + ` | ` + "`" + `mu.Lock()` + "`" + ` + ` + "`" + `defer mu.Unlock()` + "`" + ` | Use plain Lock when condvar not needed |
| ` + "`" + `std::shared_mutex` + "`" + ` | ` + "`" + `sync.RWMutex` + "`" + ` | Multiple readers or single writer |
| ` + "`" + `std::shared_lock` + "`" + ` | ` + "`" + `mu.RLock()` + "`" + ` + ` + "`" + `defer mu.RUnlock()` + "`" + ` | Read lock for concurrent reads |
| ` + "`" + `std::condition_variable` + "`" + ` | ` + "`" + `chan T` + "`" + ` | Channels replace condvar + mutex + queue |
| ` + "`" + `cv.wait(lock, pred)` + "`" + ` | ` + "`" + `<-ch` + "`" + ` or ` + "`" + `for range ch` + "`" + ` | Channel blocks until data or close |
| ` + "`" + `cv.notify_one()` + "`" + ` | ` + "`" + `ch <- val` + "`" + ` | Send unblocks one receiver |
| ` + "`" + `cv.notify_all()` + "`" + ` | ` + "`" + `close(ch)` + "`" + ` | Closing unblocks all receivers (one-time) |
| ` + "`" + `std::atomic<int64_t>` + "`" + ` | ` + "`" + `atomic.Int64` + "`" + ` | Go 1.19+ typed atomics |
| ` + "`" + `fetch_add` + "`" + ` / ` + "`" + `load` + "`" + ` / ` + "`" + `store` + "`" + ` | ` + "`" + `.Add()` + "`" + ` / ` + "`" + `.Load()` + "`" + ` / ` + "`" + `.Store()` + "`" + ` | No memory ordering parameter in Go |
| ` + "`" + `compare_exchange_strong` + "`" + ` | ` + "`" + `.CompareAndSwap(old, new)` + "`" + ` | Returns bool only |
| ` + "`" + `std::atomic<T>` + "`" + ` (generic) | ` + "`" + `atomic.Value` + "`" + ` | For non-numeric types; stores ` + "`" + `any` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/concurrency/threads_goroutines.md",
			Body: `# Threads to Goroutines

C++ threading primitives mapped to Go concurrency patterns through the full pipeline.

## Pattern 1: Basic Thread with Join

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <thread>
#include <iostream>
#include <vector>

void worker(int id, const std::string& data) {
    std::cout << "Worker " << id << " processing: " << data << std::endl;
}

int main() {
    std::vector<std::thread> threads;
    std::vector<std::string> items = {"alpha", "beta", "gamma", "delta"};

    for (int i = 0; i < items.size(); ++i) {
        threads.emplace_back(worker, i, std::ref(items[i]));
    }

    for (auto& t : threads) {
        t.join();
    }

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    {
      "kind": "Include",
      "path": "thread",
      "system": true
    },
    {
      "kind": "Include",
      "path": "iostream",
      "system": true
    },
    {
      "kind": "Include",
      "path": "vector",
      "system": true
    },
    {
      "kind": "Function",
      "name": "worker",
      "returnType": { "kind": "TypeRef", "name": "void" },
      "params": [
        {
          "kind": "Variable",
          "name": "id",
          "type": { "kind": "TypeRef", "name": "int" }
        },
        {
          "kind": "Variable",
          "name": "data",
          "type": { "kind": "TypeRef", "name": "std::string", "const": true, "ref": true }
        }
      ],
      "body": [
        {
          "kind": "CallExpr",
          "callee": "std::cout::operator<<",
          "args": ["Worker ", "id", " processing: ", "data"]
        }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "threads",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "std::thread" }]
          }
        },
        {
          "kind": "Variable",
          "name": "items",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "std::string" }]
          },
          "init": ["alpha", "beta", "gamma", "delta"]
        },
        {
          "kind": "ForStmt",
          "init": { "kind": "Variable", "name": "i", "type": { "kind": "TypeRef", "name": "int" }, "init": 0 },
          "cond": "i < items.size()",
          "step": "++i",
          "body": [
            {
              "kind": "CallExpr",
              "callee": "threads.emplace_back",
              "args": ["worker", "i", "std::ref(items[i])"]
            }
          ]
        },
        {
          "kind": "ForStmt",
          "range": { "var": "t", "container": "threads" },
          "body": [
            {
              "kind": "CallExpr",
              "callee": "t.join"
            }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "sync"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "worker",
      "params": [
        { "kind": "VarDecl", "name": "id", "type": { "kind": "TypeRef", "name": "int" } },
        { "kind": "VarDecl", "name": "data", "type": { "kind": "TypeRef", "name": "string" } }
      ],
      "returnType": null,
      "body": [
        {
          "kind": "CallExpr",
          "callee": "fmt.Println",
          "args": ["fmt.Sprintf(\"Worker %d processing: %s\", id, data)"]
        }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "wg",
          "type": { "kind": "TypeRef", "name": "sync.WaitGroup" }
        },
        {
          "kind": "VarDecl",
          "name": "items",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "string" },
          "init": ["alpha", "beta", "gamma", "delta"]
        },
        {
          "kind": "RangeStmt",
          "key": "i",
          "value": "item",
          "collection": "items",
          "body": [
            { "kind": "CallExpr", "callee": "wg.Add", "args": [1] },
            {
              "kind": "GoStmt",
              "call": {
                "kind": "FuncLit",
                "params": [
                  { "kind": "VarDecl", "name": "id", "type": { "kind": "TypeRef", "name": "int" } },
                  { "kind": "VarDecl", "name": "data", "type": { "kind": "TypeRef", "name": "string" } }
                ],
                "body": [
                  { "kind": "DeferStmt", "call": { "kind": "CallExpr", "callee": "wg.Done" } },
                  { "kind": "CallExpr", "callee": "worker", "args": ["id", "data"] }
                ],
                "args": ["i", "item"]
              }
            }
          ]
        },
        { "kind": "CallExpr", "callee": "wg.Wait" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::thread t(func, args)` + "`" + ` | ` + "`" + `go func(args)` + "`" + ` | Goroutines are lightweight; no explicit thread object needed |
| ` + "`" + `t.join()` + "`" + ` | ` + "`" + `wg.Wait()` + "`" + ` | ` + "`" + `sync.WaitGroup` + "`" + ` replaces join-all pattern |
| ` + "`" + `std::vector<std::thread>` + "`" + ` | ` + "`" + `sync.WaitGroup` + "`" + ` | No need to collect goroutine handles |
| ` + "`" + `std::ref(x)` + "`" + ` | pass value directly | Go closures capture by reference; pass as param to avoid races |
| ` + "`" + `emplace_back(func, args)` + "`" + ` | ` + "`" + `wg.Add(1)` + "`" + ` + ` + "`" + `go func()` + "`" + ` | Each goroutine decrements via ` + "`" + `defer wg.Done()` + "`" + ` |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sync"
)

func worker(id int, data string) {
	fmt.Printf("Worker %d processing: %s\n", id, data)
}

func main() {
	var wg sync.WaitGroup
	items := []string{"alpha", "beta", "gamma", "delta"}

	for i, item := range items {
		wg.Add(1)
		go func(id int, data string) {
			defer wg.Done()
			worker(id, data)
		}(i, item)
	}

	wg.Wait()
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 2: std::async with Return Value

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <future>
#include <iostream>

int compute(int x) {
    return x * x;
}

int main() {
    auto fut = std::async(std::launch::async, compute, 42);
    int result = fut.get();
    std::cout << "Result: " << result << std::endl;
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "future", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    {
      "kind": "Function",
      "name": "compute",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "params": [
        { "kind": "Variable", "name": "x", "type": { "kind": "TypeRef", "name": "int" } }
      ],
      "body": [
        { "kind": "ReturnStmt", "value": "x * x" }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "fut",
          "type": { "kind": "TypeRef", "name": "auto" },
          "init": {
            "kind": "CallExpr",
            "callee": "std::async",
            "args": ["std::launch::async", "compute", 42]
          }
        },
        {
          "kind": "Variable",
          "name": "result",
          "type": { "kind": "TypeRef", "name": "int" },
          "init": { "kind": "CallExpr", "callee": "fut.get" }
        },
        {
          "kind": "CallExpr",
          "callee": "std::cout::operator<<",
          "args": ["Result: ", "result"]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "compute",
      "params": [{ "kind": "VarDecl", "name": "x", "type": { "kind": "TypeRef", "name": "int" } }],
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [{ "kind": "ReturnStmt", "value": "x * x" }]
    },
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "ch",
          "type": { "kind": "TypeRef", "kind": "channel", "elem": "int" },
          "init": { "kind": "MakeExpr", "type": { "kind": "channel", "elem": "int" }, "bufferSize": 1 }
        },
        {
          "kind": "GoStmt",
          "call": {
            "kind": "FuncLit",
            "body": [
              { "kind": "SendStmt", "chan": "ch", "value": { "kind": "CallExpr", "callee": "compute", "args": [42] } }
            ]
          }
        },
        {
          "kind": "VarDecl",
          "name": "result",
          "type": { "kind": "TypeRef", "name": "int" },
          "init": { "kind": "RecvExpr", "chan": "ch" }
        },
        {
          "kind": "CallExpr",
          "callee": "fmt.Printf",
          "args": ["\"Result: %d\\n\"", "result"]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::async(launch::async, f, args)` + "`" + ` | ` + "`" + `go func() { ch <- f(args) }()` + "`" + ` | Goroutine + buffered channel replaces future |
| ` + "`" + `future.get()` + "`" + ` | ` + "`" + `<-ch` + "`" + ` | Channel receive blocks until value is available |
| ` + "`" + `std::future<T>` + "`" + ` | ` + "`" + `chan T` + "`" + ` | Buffered channel of size 1 models a single-value future |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

func compute(x int) int {
	return x * x
}

func main() {
	ch := make(chan int, 1)
	go func() {
		ch <- compute(42)
	}()

	result := <-ch
	fmt.Printf("Result: %d\n", result)
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 3: Thread Pool with Worker Pool

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <iostream>

class ThreadPool {
public:
    ThreadPool(size_t numThreads) : stop_(false) {
        for (size_t i = 0; i < numThreads; ++i) {
            workers_.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(mu_);
                        cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                }
            });
        }
    }

    void enqueue(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            tasks_.push(std::move(task));
        }
        cv_.notify_one();
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& w : workers_) {
            w.join();
        }
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool stop_;
};

int main() {
    ThreadPool pool(4);
    std::vector<std::string> data = {"a", "b", "c", "d", "e", "f", "g", "h"};

    for (const auto& item : data) {
        pool.enqueue([item] {
            std::cout << "Processing: " << item << std::endl;
        });
    }

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "thread", "system": true },
    { "kind": "Include", "path": "vector", "system": true },
    { "kind": "Include", "path": "queue", "system": true },
    { "kind": "Include", "path": "mutex", "system": true },
    { "kind": "Include", "path": "condition_variable", "system": true },
    { "kind": "Include", "path": "functional", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    {
      "kind": "Class",
      "name": "ThreadPool",
      "members": [
        {
          "kind": "Function",
          "name": "ThreadPool",
          "constructor": true,
          "params": [
            { "kind": "Variable", "name": "numThreads", "type": { "kind": "TypeRef", "name": "size_t" } }
          ],
          "access": "public"
        },
        {
          "kind": "Function",
          "name": "enqueue",
          "returnType": { "kind": "TypeRef", "name": "void" },
          "params": [
            {
              "kind": "Variable",
              "name": "task",
              "type": { "kind": "TypeRef", "name": "std::function", "templateArgs": [{ "kind": "TypeRef", "name": "void()" }] }
            }
          ],
          "access": "public"
        },
        {
          "kind": "Function",
          "name": "~ThreadPool",
          "destructor": true,
          "access": "public"
        },
        {
          "kind": "Variable",
          "name": "workers_",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "std::thread" }]
          },
          "access": "private"
        },
        {
          "kind": "Variable",
          "name": "tasks_",
          "type": {
            "kind": "TypeRef",
            "name": "std::queue",
            "templateArgs": [{ "kind": "TypeRef", "name": "std::function<void()>" }]
          },
          "access": "private"
        },
        {
          "kind": "Variable",
          "name": "mu_",
          "type": { "kind": "TypeRef", "name": "std::mutex" },
          "access": "private"
        },
        {
          "kind": "Variable",
          "name": "cv_",
          "type": { "kind": "TypeRef", "name": "std::condition_variable" },
          "access": "private"
        },
        {
          "kind": "Variable",
          "name": "stop_",
          "type": { "kind": "TypeRef", "name": "bool" },
          "access": "private"
        }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "pool",
          "type": { "kind": "TypeRef", "name": "ThreadPool" },
          "init": { "kind": "CallExpr", "callee": "ThreadPool", "args": [4] }
        },
        {
          "kind": "Variable",
          "name": "data",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "std::string" }]
          },
          "init": ["a", "b", "c", "d", "e", "f", "g", "h"]
        },
        {
          "kind": "ForStmt",
          "range": { "var": "item", "container": "data" },
          "body": [
            {
              "kind": "CallExpr",
              "callee": "pool.enqueue",
              "args": ["lambda: print item"]
            }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "sync"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "workerPool",
      "params": [
        { "kind": "VarDecl", "name": "numWorkers", "type": { "kind": "TypeRef", "name": "int" } },
        { "kind": "VarDecl", "name": "jobs", "type": { "kind": "TypeRef", "kind": "channel", "elem": "func()", "direction": "recv" } },
        { "kind": "VarDecl", "name": "wg", "type": { "kind": "TypeRef", "name": "*sync.WaitGroup" } }
      ],
      "body": [
        {
          "kind": "ForStmt",
          "init": { "kind": "VarDecl", "name": "i", "init": 0 },
          "cond": "i < numWorkers",
          "body": [
            {
              "kind": "GoStmt",
              "call": {
                "kind": "FuncLit",
                "body": [
                  { "kind": "DeferStmt", "call": { "kind": "CallExpr", "callee": "wg.Done" } },
                  {
                    "kind": "RangeStmt",
                    "value": "job",
                    "collection": "jobs",
                    "body": [
                      { "kind": "CallExpr", "callee": "job" }
                    ]
                  }
                ]
              }
            }
          ]
        }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "data",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "string" },
          "init": ["a", "b", "c", "d", "e", "f", "g", "h"]
        },
        {
          "kind": "VarDecl",
          "name": "jobs",
          "init": { "kind": "MakeExpr", "type": { "kind": "channel", "elem": "func()" }, "bufferSize": "len(data)" }
        },
        {
          "kind": "VarDecl",
          "name": "wg",
          "type": { "kind": "TypeRef", "name": "sync.WaitGroup" }
        },
        { "kind": "CallExpr", "callee": "wg.Add", "args": [4] },
        { "kind": "CallExpr", "callee": "workerPool", "args": [4, "jobs", "&wg"] },
        {
          "kind": "RangeStmt",
          "value": "item",
          "collection": "data",
          "body": [
            {
              "kind": "SendStmt",
              "chan": "jobs",
              "value": {
                "kind": "FuncLit",
                "captures": ["item"],
                "body": [
                  { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"Processing: %s\\n\"", "item"] }
                ]
              }
            }
          ]
        },
        { "kind": "CallExpr", "callee": "close", "args": ["jobs"] },
        { "kind": "CallExpr", "callee": "wg.Wait" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `ThreadPool` + "`" + ` class | Function + ` + "`" + `chan func()` + "`" + ` | Go channels replace the entire class; no wrapper needed |
| ` + "`" + `std::queue<task>` + "`" + ` + mutex + condvar | ` + "`" + `chan func()` + "`" + ` | Buffered channel is a thread-safe bounded queue |
| Constructor spawning threads | Goroutines ranging over channel | Workers consume from channel until it closes |
| Destructor joining threads | ` + "`" + `close(jobs)` + "`" + ` + ` + "`" + `wg.Wait()` + "`" + ` | Closing channel signals workers to stop |
| ` + "`" + `enqueue(task)` + "`" + ` | ` + "`" + `jobs <- task` + "`" + ` | Channel send replaces locked queue push |
| ` + "`" + `cv_.wait(lock, pred)` + "`" + ` | implicit in ` + "`" + `range ch` + "`" + ` | Channel range blocks until data available or closed |
| ` + "`" + `cv_.notify_one()` + "`" + ` | implicit in channel send | Channel send unblocks exactly one receiver |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sync"
)

func workerPool(numWorkers int, jobs <-chan func(), wg *sync.WaitGroup) {
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for job := range jobs {
				job()
			}
		}()
	}
}

func main() {
	data := []string{"a", "b", "c", "d", "e", "f", "g", "h"}

	jobs := make(chan func(), len(data))
	var wg sync.WaitGroup
	wg.Add(4)

	workerPool(4, jobs, &wg)

	for _, item := range data {
		item := item // capture loop variable
		jobs <- func() {
			fmt.Printf("Processing: %s\n", item)
		}
	}

	close(jobs)
	wg.Wait()
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Pattern | Notes |
|---|---|---|
| ` + "`" + `std::thread t(f, args); t.join()` + "`" + ` | ` + "`" + `go f(args)` + "`" + ` + ` + "`" + `sync.WaitGroup` + "`" + ` | Always use WaitGroup when you need to wait for completion |
| ` + "`" + `std::async(launch::async, f)` + "`" + ` | ` + "`" + `go func() { ch <- f() }()` + "`" + ` | Buffered channel of size 1 for single result |
| ` + "`" + `future.get()` + "`" + ` | ` + "`" + `<-ch` + "`" + ` | Blocks until goroutine sends result |
| ` + "`" + `vector<thread>` + "`" + ` + join loop | ` + "`" + `WaitGroup.Add(n)` + "`" + ` + ` + "`" + `defer Done()` + "`" + ` + ` + "`" + `Wait()` + "`" + ` | No need to track goroutine handles |
| Thread pool class | ` + "`" + `chan func()` + "`" + ` + goroutine workers | Entire class collapses to a few lines |
| ` + "`" + `std::ref(x)` + "`" + ` | Pass as function argument | Go closures capture by reference; pass values to avoid races |
| ` + "`" + `detach()` + "`" + ` | ` + "`" + `go f()` + "`" + ` (no WaitGroup) | Fire-and-forget goroutine; use sparingly |
| Thread-local storage | No direct equivalent | Use goroutine parameters or context.Value |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/containers/iterators_range.md",
			Body: `# Iterators to Range

C++ iterator patterns and STL algorithms mapped to Go ` + "`" + `for range` + "`" + ` loops through the full pipeline.

## Pattern 1: Pipeline of STL Algorithms

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <vector>
#include <algorithm>
#include <numeric>
#include <iostream>
#include <string>

struct Employee {
    std::string name;
    std::string department;
    double salary;
};

int main() {
    std::vector<Employee> employees = {
        {"Alice", "Engineering", 95000},
        {"Bob", "Marketing", 72000},
        {"Charlie", "Engineering", 110000},
        {"Diana", "Engineering", 88000},
        {"Eve", "Marketing", 65000},
        {"Frank", "Sales", 78000},
        {"Grace", "Engineering", 102000},
        {"Hank", "Sales", 81000}
    };

    // Step 1: Filter to Engineering department
    std::vector<Employee> engineers;
    std::copy_if(employees.begin(), employees.end(), std::back_inserter(engineers),
        [](const Employee& e) { return e.department == "Engineering"; });

    // Step 2: Sort by salary descending
    std::sort(engineers.begin(), engineers.end(),
        [](const Employee& a, const Employee& b) { return a.salary > b.salary; });

    // Step 3: Extract names (transform)
    std::vector<std::string> names;
    std::transform(engineers.begin(), engineers.end(), std::back_inserter(names),
        [](const Employee& e) { return e.name; });

    // Step 4: Find first engineer with salary > 100k
    auto it = std::find_if(employees.begin(), employees.end(),
        [](const Employee& e) { return e.department == "Engineering" && e.salary > 100000; });
    if (it != employees.end()) {
        std::cout << "First 100k+ engineer: " << it->name << std::endl;
    }

    // Step 5: Accumulate total engineering salary
    double totalSalary = std::accumulate(engineers.begin(), engineers.end(), 0.0,
        [](double sum, const Employee& e) { return sum + e.salary; });

    // Step 6: Check if all engineers earn > 80k
    bool allAbove80k = std::all_of(engineers.begin(), engineers.end(),
        [](const Employee& e) { return e.salary > 80000; });

    // Step 7: Count engineers earning > 90k
    auto count = std::count_if(engineers.begin(), engineers.end(),
        [](const Employee& e) { return e.salary > 90000; });

    // Print results
    std::cout << "Engineering team (by salary):" << std::endl;
    for (const auto& name : names) {
        std::cout << "  " << name << std::endl;
    }
    std::cout << "Total salary: " << totalSalary << std::endl;
    std::cout << "All above 80k: " << (allAbove80k ? "yes" : "no") << std::endl;
    std::cout << "Count above 90k: " << count << std::endl;

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "vector", "system": true },
    { "kind": "Include", "path": "algorithm", "system": true },
    { "kind": "Include", "path": "numeric", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    { "kind": "Include", "path": "string", "system": true },
    {
      "kind": "Class",
      "name": "Employee",
      "isStruct": true,
      "members": [
        { "kind": "Variable", "name": "name", "type": { "kind": "TypeRef", "name": "std::string" }, "access": "public" },
        { "kind": "Variable", "name": "department", "type": { "kind": "TypeRef", "name": "std::string" }, "access": "public" },
        { "kind": "Variable", "name": "salary", "type": { "kind": "TypeRef", "name": "double" }, "access": "public" }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "employees",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "Employee" }]
          },
          "init": "list of Employee structs"
        },
        {
          "kind": "Variable", "name": "engineers",
          "type": { "kind": "TypeRef", "name": "std::vector", "templateArgs": [{ "kind": "TypeRef", "name": "Employee" }] }
        },
        {
          "kind": "CallExpr",
          "callee": "std::copy_if",
          "args": ["employees.begin()", "employees.end()", "back_inserter(engineers)", "lambda: e.department == Engineering"]
        },
        {
          "kind": "CallExpr",
          "callee": "std::sort",
          "args": ["engineers.begin()", "engineers.end()", "lambda: a.salary > b.salary"]
        },
        {
          "kind": "Variable", "name": "names",
          "type": { "kind": "TypeRef", "name": "std::vector", "templateArgs": [{ "kind": "TypeRef", "name": "std::string" }] }
        },
        {
          "kind": "CallExpr",
          "callee": "std::transform",
          "args": ["engineers.begin()", "engineers.end()", "back_inserter(names)", "lambda: e.name"]
        },
        {
          "kind": "Variable",
          "name": "it",
          "init": { "kind": "CallExpr", "callee": "std::find_if", "args": ["...", "lambda: eng && salary > 100k"] }
        },
        {
          "kind": "IfStmt",
          "cond": "it != employees.end()",
          "body": [{ "kind": "CallExpr", "callee": "cout", "args": ["it->name"] }]
        },
        {
          "kind": "Variable",
          "name": "totalSalary",
          "type": { "kind": "TypeRef", "name": "double" },
          "init": { "kind": "CallExpr", "callee": "std::accumulate", "args": ["engineers.begin()", "engineers.end()", 0.0, "lambda: sum + e.salary"] }
        },
        {
          "kind": "Variable",
          "name": "allAbove80k",
          "type": { "kind": "TypeRef", "name": "bool" },
          "init": { "kind": "CallExpr", "callee": "std::all_of", "args": ["...", "lambda: e.salary > 80000"] }
        },
        {
          "kind": "Variable",
          "name": "count",
          "type": { "kind": "TypeRef", "name": "auto" },
          "init": { "kind": "CallExpr", "callee": "std::count_if", "args": ["...", "lambda: e.salary > 90000"] }
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "slices"],
  "decls": [
    {
      "kind": "TypeDecl",
      "name": "Employee",
      "fields": [
        { "kind": "VarDecl", "name": "Name", "type": { "kind": "TypeRef", "name": "string" } },
        { "kind": "VarDecl", "name": "Department", "type": { "kind": "TypeRef", "name": "string" } },
        { "kind": "VarDecl", "name": "Salary", "type": { "kind": "TypeRef", "name": "float64" } }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "employees",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "Employee" },
          "init": "slice literal"
        },
        {
          "kind": "Comment",
          "text": "Step 1: Filter"
        },
        {
          "kind": "VarDecl",
          "name": "engineers",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "Employee" }
        },
        {
          "kind": "RangeStmt",
          "key": "_", "value": "e", "collection": "employees",
          "body": [{
            "kind": "IfStmt",
            "cond": "e.Department == \"Engineering\"",
            "body": [{ "kind": "ExprStmt", "expr": "engineers = append(engineers, e)" }]
          }]
        },
        {
          "kind": "Comment",
          "text": "Step 2: Sort descending"
        },
        {
          "kind": "CallExpr",
          "callee": "slices.SortFunc",
          "args": ["engineers", "func(a, b Employee) int { return cmp(b.Salary, a.Salary) }"]
        },
        {
          "kind": "Comment",
          "text": "Step 3: Transform to names"
        },
        {
          "kind": "VarDecl",
          "name": "names",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "string" },
          "init": { "kind": "MakeExpr", "type": { "kind": "slice", "elem": "string" }, "len": 0, "cap": "len(engineers)" }
        },
        {
          "kind": "RangeStmt",
          "key": "_", "value": "e", "collection": "engineers",
          "body": [{ "kind": "ExprStmt", "expr": "names = append(names, e.Name)" }]
        },
        {
          "kind": "Comment",
          "text": "Step 4: Find first matching"
        },
        {
          "kind": "VarDecl", "name": "firstHighEarner", "type": { "kind": "TypeRef", "name": "string" }
        },
        {
          "kind": "RangeStmt",
          "key": "_", "value": "e", "collection": "employees",
          "body": [{
            "kind": "IfStmt",
            "cond": "e.Department == \"Engineering\" && e.Salary > 100000",
            "body": [
              { "kind": "AssignStmt", "target": "firstHighEarner", "value": "e.Name" },
              { "kind": "BreakStmt" }
            ]
          }]
        },
        {
          "kind": "Comment",
          "text": "Step 5: Accumulate"
        },
        {
          "kind": "VarDecl", "name": "totalSalary", "type": { "kind": "TypeRef", "name": "float64" }
        },
        {
          "kind": "RangeStmt",
          "key": "_", "value": "e", "collection": "engineers",
          "body": [{ "kind": "ExprStmt", "expr": "totalSalary += e.Salary" }]
        },
        {
          "kind": "Comment",
          "text": "Step 6: All-of check"
        },
        {
          "kind": "VarDecl", "name": "allAbove80k", "type": { "kind": "TypeRef", "name": "bool" }, "init": true
        },
        {
          "kind": "RangeStmt",
          "key": "_", "value": "e", "collection": "engineers",
          "body": [{
            "kind": "IfStmt",
            "cond": "e.Salary <= 80000",
            "body": [
              { "kind": "AssignStmt", "target": "allAbove80k", "value": false },
              { "kind": "BreakStmt" }
            ]
          }]
        },
        {
          "kind": "Comment",
          "text": "Step 7: Count-if"
        },
        {
          "kind": "VarDecl", "name": "countAbove90k", "type": { "kind": "TypeRef", "name": "int" }
        },
        {
          "kind": "RangeStmt",
          "key": "_", "value": "e", "collection": "engineers",
          "body": [{
            "kind": "IfStmt",
            "cond": "e.Salary > 90000",
            "body": [{ "kind": "ExprStmt", "expr": "countAbove90k++" }]
          }]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::copy_if` + "`" + ` | ` + "`" + `for range` + "`" + ` + ` + "`" + `if` + "`" + ` + ` + "`" + `append` + "`" + ` | Filter loop building new slice |
| ` + "`" + `std::sort` + "`" + ` with comparator | ` + "`" + `slices.SortFunc(s, cmp)` + "`" + ` | Custom comparison function |
| ` + "`" + `std::transform` + "`" + ` | ` + "`" + `for range` + "`" + ` + ` + "`" + `append` + "`" + ` | Map operation as explicit loop |
| ` + "`" + `std::find_if` + "`" + ` | ` + "`" + `for range` + "`" + ` + ` + "`" + `if` + "`" + ` + ` + "`" + `break` + "`" + ` | Linear search with early exit |
| ` + "`" + `std::accumulate` + "`" + ` | ` + "`" + `for range` + "`" + ` + accumulator variable | Fold as explicit loop |
| ` + "`" + `std::all_of` + "`" + ` | ` + "`" + `for range` + "`" + ` + negative check + ` + "`" + `break` + "`" + ` | Start true, set false on violation |
| ` + "`" + `std::count_if` + "`" + ` | ` + "`" + `for range` + "`" + ` + ` + "`" + `if` + "`" + ` + counter | Count matching elements |
| Iterator pair ` + "`" + `begin/end` + "`" + ` | Implicit in ` + "`" + `for range` + "`" + ` | Range handles bounds automatically |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"cmp"
	"fmt"
	"slices"
)

type Employee struct {
	Name       string
	Department string
	Salary     float64
}

func main() {
	employees := []Employee{
		{"Alice", "Engineering", 95000},
		{"Bob", "Marketing", 72000},
		{"Charlie", "Engineering", 110000},
		{"Diana", "Engineering", 88000},
		{"Eve", "Marketing", 65000},
		{"Frank", "Sales", 78000},
		{"Grace", "Engineering", 102000},
		{"Hank", "Sales", 81000},
	}

	// Step 1: Filter to Engineering department
	var engineers []Employee
	for _, e := range employees {
		if e.Department == "Engineering" {
			engineers = append(engineers, e)
		}
	}

	// Step 2: Sort by salary descending
	slices.SortFunc(engineers, func(a, b Employee) int {
		return cmp.Compare(b.Salary, a.Salary)
	})

	// Step 3: Extract names
	names := make([]string, 0, len(engineers))
	for _, e := range engineers {
		names = append(names, e.Name)
	}

	// Step 4: Find first engineer with salary > 100k
	var firstHighEarner string
	for _, e := range employees {
		if e.Department == "Engineering" && e.Salary > 100000 {
			firstHighEarner = e.Name
			break
		}
	}
	if firstHighEarner != "" {
		fmt.Printf("First 100k+ engineer: %s\n", firstHighEarner)
	}

	// Step 5: Accumulate total engineering salary
	var totalSalary float64
	for _, e := range engineers {
		totalSalary += e.Salary
	}

	// Step 6: Check if all engineers earn > 80k
	allAbove80k := true
	for _, e := range engineers {
		if e.Salary <= 80000 {
			allAbove80k = false
			break
		}
	}

	// Step 7: Count engineers earning > 90k
	var countAbove90k int
	for _, e := range engineers {
		if e.Salary > 90000 {
			countAbove90k++
		}
	}

	// Print results
	fmt.Println("Engineering team (by salary):")
	for _, name := range names {
		fmt.Printf("  %s\n", name)
	}
	fmt.Printf("Total salary: %.0f\n", totalSalary)
	if allAbove80k {
		fmt.Println("All above 80k: yes")
	} else {
		fmt.Println("All above 80k: no")
	}
	fmt.Printf("Count above 90k: %d\n", countAbove90k)
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 2: Reverse Iteration and Index-Based Access

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <vector>
#include <iostream>
#include <algorithm>

int main() {
    std::vector<int> nums = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    // Reverse iterate
    std::cout << "Reversed: ";
    for (auto it = nums.rbegin(); it != nums.rend(); ++it) {
        std::cout << *it << " ";
    }
    std::cout << std::endl;

    // std::for_each
    std::cout << "Doubled: ";
    std::for_each(nums.begin(), nums.end(), [](int n) {
        std::cout << n * 2 << " ";
    });
    std::cout << std::endl;

    // std::reverse (in-place)
    std::reverse(nums.begin(), nums.end());

    // Iterate with index
    for (size_t i = 0; i < nums.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << "[" << i << "]=" << nums[i];
    }
    std::cout << std::endl;

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "vector", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    { "kind": "Include", "path": "algorithm", "system": true },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "nums",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "int" }]
          },
          "init": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        },
        {
          "kind": "ForStmt",
          "init": { "kind": "Variable", "name": "it", "init": "nums.rbegin()" },
          "cond": "it != nums.rend()",
          "step": "++it",
          "body": [
            { "kind": "CallExpr", "callee": "cout", "args": ["*it", "\" \""] }
          ]
        },
        {
          "kind": "CallExpr",
          "callee": "std::for_each",
          "args": ["nums.begin()", "nums.end()", "lambda: print n*2"]
        },
        {
          "kind": "CallExpr",
          "callee": "std::reverse",
          "args": ["nums.begin()", "nums.end()"]
        },
        {
          "kind": "ForStmt",
          "init": { "kind": "Variable", "name": "i", "type": { "kind": "TypeRef", "name": "size_t" }, "init": 0 },
          "cond": "i < nums.size()",
          "step": "++i",
          "body": [
            { "kind": "CallExpr", "callee": "cout", "args": ["\"[\"", "i", "\"]=\"", "nums[i]"] }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "slices"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "nums",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "int" },
          "init": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        },
        {
          "kind": "CallExpr",
          "callee": "fmt.Print",
          "args": ["\"Reversed: \""]
        },
        {
          "kind": "ForStmt",
          "init": { "kind": "VarDecl", "name": "i", "init": "len(nums) - 1" },
          "cond": "i >= 0",
          "step": "i--",
          "body": [
            { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"%d \"", "nums[i]"] }
          ]
        },
        { "kind": "CallExpr", "callee": "fmt.Println" },
        {
          "kind": "CallExpr",
          "callee": "fmt.Print",
          "args": ["\"Doubled: \""]
        },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "n",
          "collection": "nums",
          "body": [
            { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"%d \"", "n * 2"] }
          ]
        },
        { "kind": "CallExpr", "callee": "fmt.Println" },
        {
          "kind": "CallExpr",
          "callee": "slices.Reverse",
          "args": ["nums"]
        },
        {
          "kind": "RangeStmt",
          "key": "i",
          "value": "v",
          "collection": "nums",
          "body": [
            {
              "kind": "IfStmt",
              "cond": "i > 0",
              "body": [{ "kind": "CallExpr", "callee": "fmt.Print", "args": ["\", \""] }]
            },
            { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"[%d]=%d\"", "i", "v"] }
          ]
        },
        { "kind": "CallExpr", "callee": "fmt.Println" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `rbegin()/rend()` + "`" + ` | ` + "`" + `for i := len(s)-1; i >= 0; i--` + "`" + ` | Backwards index loop |
| ` + "`" + `std::for_each(begin, end, fn)` + "`" + ` | ` + "`" + `for _, v := range s { fn(v) }` + "`" + ` | Range with inline body |
| ` + "`" + `std::reverse(begin, end)` + "`" + ` | ` + "`" + `slices.Reverse(s)` + "`" + ` | In-place reversal (Go 1.21+) |
| Index-based ` + "`" + `for(i=0; i<size; i++)` + "`" + ` | ` + "`" + `for i, v := range s` + "`" + ` | Range provides both index and value |
| ` + "`" + `*it` + "`" + ` dereference | Direct value from range | No pointer indirection needed |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"slices"
)

func main() {
	nums := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	// Reverse iterate
	fmt.Print("Reversed: ")
	for i := len(nums) - 1; i >= 0; i-- {
		fmt.Printf("%d ", nums[i])
	}
	fmt.Println()

	// for_each equivalent
	fmt.Print("Doubled: ")
	for _, n := range nums {
		fmt.Printf("%d ", n*2)
	}
	fmt.Println()

	// Reverse in-place
	slices.Reverse(nums)

	// Iterate with index
	for i, v := range nums {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("[%d]=%d", i, v)
	}
	fmt.Println()
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 3: std::sort with Custom Comparator

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <vector>
#include <algorithm>
#include <iostream>
#include <string>

struct Task {
    std::string name;
    int priority;
    double estimatedHours;
};

int main() {
    std::vector<Task> tasks = {
        {"Bug fix", 1, 2.0},
        {"Feature A", 3, 8.0},
        {"Refactor", 2, 4.0},
        {"Docs", 3, 1.5},
        {"Feature B", 1, 12.0},
        {"Testing", 2, 3.0}
    };

    // Sort by priority (ascending), then by estimated hours (ascending)
    std::sort(tasks.begin(), tasks.end(), [](const Task& a, const Task& b) {
        if (a.priority != b.priority) return a.priority < b.priority;
        return a.estimatedHours < b.estimatedHours;
    });

    // stable_sort preserving original order for equal elements
    std::stable_sort(tasks.begin(), tasks.end(), [](const Task& a, const Task& b) {
        return a.priority < b.priority;
    });

    for (const auto& t : tasks) {
        std::cout << "[P" << t.priority << "] " << t.name
                  << " (" << t.estimatedHours << "h)" << std::endl;
    }

    // Partial sort: get top 3 by priority
    std::partial_sort(tasks.begin(), tasks.begin() + 3, tasks.end(),
        [](const Task& a, const Task& b) { return a.priority < b.priority; });

    // nth_element: find median by hours
    std::nth_element(tasks.begin(), tasks.begin() + tasks.size()/2, tasks.end(),
        [](const Task& a, const Task& b) { return a.estimatedHours < b.estimatedHours; });

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "vector", "system": true },
    { "kind": "Include", "path": "algorithm", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    { "kind": "Include", "path": "string", "system": true },
    {
      "kind": "Class",
      "name": "Task",
      "isStruct": true,
      "members": [
        { "kind": "Variable", "name": "name", "type": { "kind": "TypeRef", "name": "std::string" }, "access": "public" },
        { "kind": "Variable", "name": "priority", "type": { "kind": "TypeRef", "name": "int" }, "access": "public" },
        { "kind": "Variable", "name": "estimatedHours", "type": { "kind": "TypeRef", "name": "double" }, "access": "public" }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "tasks",
          "type": { "kind": "TypeRef", "name": "std::vector", "templateArgs": [{ "kind": "TypeRef", "name": "Task" }] },
          "init": "list of Task structs"
        },
        {
          "kind": "CallExpr",
          "callee": "std::sort",
          "args": ["tasks.begin()", "tasks.end()", "lambda: multi-key compare"]
        },
        {
          "kind": "CallExpr",
          "callee": "std::stable_sort",
          "args": ["tasks.begin()", "tasks.end()", "lambda: priority compare"]
        },
        {
          "kind": "CallExpr",
          "callee": "std::partial_sort",
          "args": ["tasks.begin()", "tasks.begin()+3", "tasks.end()", "lambda"]
        },
        {
          "kind": "CallExpr",
          "callee": "std::nth_element",
          "args": ["tasks.begin()", "tasks.begin()+size/2", "tasks.end()", "lambda"]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["cmp", "fmt", "slices"],
  "decls": [
    {
      "kind": "TypeDecl",
      "name": "Task",
      "fields": [
        { "kind": "VarDecl", "name": "Name", "type": { "kind": "TypeRef", "name": "string" } },
        { "kind": "VarDecl", "name": "Priority", "type": { "kind": "TypeRef", "name": "int" } },
        { "kind": "VarDecl", "name": "EstimatedHours", "type": { "kind": "TypeRef", "name": "float64" } }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "tasks",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "Task" },
          "init": "slice literal"
        },
        {
          "kind": "CallExpr",
          "callee": "slices.SortFunc",
          "args": ["tasks", "multi-key comparator using cmp.Compare"]
        },
        {
          "kind": "CallExpr",
          "callee": "slices.SortStableFunc",
          "args": ["tasks", "priority comparator"]
        },
        {
          "kind": "RangeStmt",
          "key": "_", "value": "t", "collection": "tasks",
          "body": [
            { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"[P%d] %s (%.1fh)\\n\"", "t.Priority", "t.Name", "t.EstimatedHours"] }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::sort` + "`" + ` with lambda | ` + "`" + `slices.SortFunc(s, cmp)` + "`" + ` | Comparator returns ` + "`" + `int` + "`" + ` (-1, 0, 1) via ` + "`" + `cmp.Compare` + "`" + ` |
| ` + "`" + `std::stable_sort` + "`" + ` | ` + "`" + `slices.SortStableFunc(s, cmp)` + "`" + ` | Preserves relative order of equal elements |
| Multi-key comparison | Chain ` + "`" + `cmp.Compare` + "`" + ` calls | Check primary key first, fallback to secondary |
| ` + "`" + `bool` + "`" + ` comparator ` + "`" + `a < b` + "`" + ` | ` + "`" + `int` + "`" + ` comparator ` + "`" + `cmp.Compare(a, b)` + "`" + ` | Go sort functions use three-way comparison |
| ` + "`" + `std::partial_sort` + "`" + ` | ` + "`" + `slices.SortFunc` + "`" + ` + slice to N | Sort all, then take first N (or use heap for efficiency) |
| ` + "`" + `std::nth_element` + "`" + ` | Sort + index | No direct equivalent; full sort or custom selection |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"cmp"
	"fmt"
	"slices"
)

type Task struct {
	Name           string
	Priority       int
	EstimatedHours float64
}

func main() {
	tasks := []Task{
		{"Bug fix", 1, 2.0},
		{"Feature A", 3, 8.0},
		{"Refactor", 2, 4.0},
		{"Docs", 3, 1.5},
		{"Feature B", 1, 12.0},
		{"Testing", 2, 3.0},
	}

	// Sort by priority (ascending), then by estimated hours (ascending)
	slices.SortFunc(tasks, func(a, b Task) int {
		if c := cmp.Compare(a.Priority, b.Priority); c != 0 {
			return c
		}
		return cmp.Compare(a.EstimatedHours, b.EstimatedHours)
	})

	// Stable sort by priority only (preserves order for equal priorities)
	slices.SortStableFunc(tasks, func(a, b Task) int {
		return cmp.Compare(a.Priority, b.Priority)
	})

	for _, t := range tasks {
		fmt.Printf("[P%d] %s (%.1fh)\n", t.Priority, t.Name, t.EstimatedHours)
	}

	// Top 3 by priority: sort and take first 3
	slices.SortFunc(tasks, func(a, b Task) int {
		return cmp.Compare(a.Priority, b.Priority)
	})
	top3 := tasks[:3]
	_ = top3

	// Median by hours: sort by hours and take middle element
	slices.SortFunc(tasks, func(a, b Task) int {
		return cmp.Compare(a.EstimatedHours, b.EstimatedHours)
	})
	median := tasks[len(tasks)/2]
	_ = median
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Pattern | Notes |
|---|---|---|
| ` + "`" + `begin()/end()` + "`" + ` | Implicit in ` + "`" + `for range` + "`" + ` | Range handles bounds |
| ` + "`" + `for(auto it = begin; it != end; ++it)` + "`" + ` | ` + "`" + `for _, v := range s` + "`" + ` | Range provides value directly |
| ` + "`" + `for(auto it = rbegin; it != rend; ++it)` + "`" + ` | ` + "`" + `for i := len(s)-1; i >= 0; i--` + "`" + ` | Backward index loop |
| ` + "`" + `*it` + "`" + ` (dereference) | Direct value | No indirection in Go range |
| ` + "`" + `it->field` + "`" + ` | ` + "`" + `v.Field` + "`" + ` | Direct field access |
| ` + "`" + `std::for_each(begin, end, fn)` + "`" + ` | ` + "`" + `for _, v := range s { fn(v) }` + "`" + ` | Inline loop body |
| ` + "`" + `std::find(begin, end, val)` + "`" + ` | Loop + ` + "`" + `if v == val { break }` + "`" + ` | Manual linear search |
| ` + "`" + `std::find_if(begin, end, pred)` + "`" + ` | Loop + ` + "`" + `if pred(v) { break }` + "`" + ` | Manual predicate search |
| ` + "`" + `std::count_if(begin, end, pred)` + "`" + ` | Loop + ` + "`" + `if pred(v) { count++ }` + "`" + ` | Manual counting |
| ` + "`" + `std::transform(begin, end, out, fn)` + "`" + ` | Loop + ` + "`" + `append(out, fn(v))` + "`" + ` | Build new slice |
| ` + "`" + `std::accumulate(begin, end, init, fn)` + "`" + ` | Loop + ` + "`" + `acc = fn(acc, v)` + "`" + ` | Fold with accumulator |
| ` + "`" + `std::copy_if(begin, end, out, pred)` + "`" + ` | Loop + ` + "`" + `if pred(v) { append }` + "`" + ` | Filter loop |
| ` + "`" + `std::remove_if` + "`" + ` + ` + "`" + `erase` + "`" + ` | Filter loop building new slice | Cleaner than in-place |
| ` + "`" + `std::all_of(begin, end, pred)` + "`" + ` | Loop + ` + "`" + `if !pred { false; break }` + "`" + ` | Early exit on first failure |
| ` + "`" + `std::any_of(begin, end, pred)` + "`" + ` | Loop + ` + "`" + `if pred { true; break }` + "`" + ` | Early exit on first match |
| ` + "`" + `std::none_of(begin, end, pred)` + "`" + ` | Loop + ` + "`" + `if pred { false; break }` + "`" + ` | Early exit on first match |
| ` + "`" + `std::sort(begin, end)` + "`" + ` | ` + "`" + `slices.Sort(s)` + "`" + ` | Go 1.21+ slices package |
| ` + "`" + `std::sort(begin, end, cmp)` + "`" + ` | ` + "`" + `slices.SortFunc(s, cmp)` + "`" + ` | Comparator returns int |
| ` + "`" + `std::stable_sort(begin, end, cmp)` + "`" + ` | ` + "`" + `slices.SortStableFunc(s, cmp)` + "`" + ` | Preserves equal element order |
| ` + "`" + `std::reverse(begin, end)` + "`" + ` | ` + "`" + `slices.Reverse(s)` + "`" + ` | In-place reversal |
| ` + "`" + `std::min_element(begin, end)` + "`" + ` | ` + "`" + `slices.Min(s)` + "`" + ` or loop | Built-in for ordered types |
| ` + "`" + `std::max_element(begin, end)` + "`" + ` | ` + "`" + `slices.Max(s)` + "`" + ` or loop | Built-in for ordered types |
| ` + "`" + `std::partial_sort` + "`" + ` | Sort + slice | No direct partial sort |
| ` + "`" + `std::nth_element` + "`" + ` | Sort + index | No direct selection algorithm |
| ` + "`" + `std::binary_search` + "`" + ` | ` + "`" + `sort.Search` + "`" + ` or ` + "`" + `slices.BinarySearch` + "`" + ` | Requires sorted input |
| ` + "`" + `std::lower_bound` + "`" + ` | ` + "`" + `sort.Search` + "`" + ` with custom function | Returns insertion point |
| ` + "`" + `std::unique(begin, end)` + "`" + ` | ` + "`" + `slices.Compact(s)` + "`" + ` | Removes consecutive duplicates |
| ` + "`" + `std::next/std::prev` + "`" + ` | ` + "`" + `i+1` + "`" + ` / ` + "`" + `i-1` + "`" + ` | Direct index arithmetic |
| ` + "`" + `std::distance(begin, end)` + "`" + ` | ` + "`" + `len(s)` + "`" + ` or ` + "`" + `j - i` + "`" + ` | Index subtraction |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/containers/map_set.md",
			Body: `# Map and Set

C++ associative containers mapped to Go ` + "`" + `map` + "`" + ` types through the full pipeline.

## Pattern 1: Word Frequency Counter

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <map>
#include <unordered_map>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

int main() {
    std::vector<std::string> words = {
        "the", "quick", "brown", "fox", "jumps",
        "over", "the", "lazy", "dog", "the",
        "fox", "the", "dog", "quick", "the"
    };

    // Count word frequencies
    std::unordered_map<std::string, int> freq;
    for (const auto& word : words) {
        freq[word]++;
    }

    // Check if a word exists
    auto it = freq.find("cat");
    if (it != freq.end()) {
        std::cout << "Found cat: " << it->second << std::endl;
    } else {
        std::cout << "cat not found" << std::endl;
    }

    // Delete a word
    freq.erase("lazy");

    // Ordered iteration: copy to sorted container
    std::map<std::string, int> ordered(freq.begin(), freq.end());
    for (const auto& [word, count] : ordered) {
        std::cout << word << ": " << count << std::endl;
    }

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "map", "system": true },
    { "kind": "Include", "path": "unordered_map", "system": true },
    { "kind": "Include", "path": "string", "system": true },
    { "kind": "Include", "path": "vector", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    { "kind": "Include", "path": "algorithm", "system": true },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "words",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "std::string" }]
          },
          "init": ["the", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog", "the", "fox", "the", "dog", "quick", "the"]
        },
        {
          "kind": "Variable",
          "name": "freq",
          "type": {
            "kind": "TypeRef",
            "name": "std::unordered_map",
            "templateArgs": [
              { "kind": "TypeRef", "name": "std::string" },
              { "kind": "TypeRef", "name": "int" }
            ]
          }
        },
        {
          "kind": "ForStmt",
          "range": { "var": "word", "container": "words" },
          "body": [
            { "kind": "ExprStmt", "expr": "freq[word]++" }
          ]
        },
        {
          "kind": "Variable",
          "name": "it",
          "type": { "kind": "TypeRef", "name": "auto" },
          "init": { "kind": "CallExpr", "callee": "freq.find", "args": ["\"cat\""] }
        },
        {
          "kind": "IfStmt",
          "cond": "it != freq.end()",
          "body": [
            { "kind": "CallExpr", "callee": "cout", "args": ["\"Found cat: \"", "it->second"] }
          ],
          "else": [
            { "kind": "CallExpr", "callee": "cout", "args": ["\"cat not found\""] }
          ]
        },
        { "kind": "CallExpr", "callee": "freq.erase", "args": ["\"lazy\""] },
        {
          "kind": "Variable",
          "name": "ordered",
          "type": {
            "kind": "TypeRef",
            "name": "std::map",
            "templateArgs": [
              { "kind": "TypeRef", "name": "std::string" },
              { "kind": "TypeRef", "name": "int" }
            ]
          },
          "init": { "kind": "CallExpr", "callee": "std::map", "args": ["freq.begin()", "freq.end()"] }
        },
        {
          "kind": "ForStmt",
          "range": { "var": ["word", "count"], "container": "ordered", "structured": true },
          "body": [
            { "kind": "CallExpr", "callee": "cout", "args": ["word", "\": \"", "count"] }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "slices", "sort"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "words",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "string" },
          "init": ["the", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog", "the", "fox", "the", "dog", "quick", "the"]
        },
        {
          "kind": "VarDecl",
          "name": "freq",
          "type": { "kind": "TypeRef", "kind": "map", "key": "string", "value": "int" },
          "init": { "kind": "MakeExpr", "type": { "kind": "map", "key": "string", "value": "int" } }
        },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "word",
          "collection": "words",
          "body": [
            { "kind": "ExprStmt", "expr": "freq[word]++" }
          ]
        },
        {
          "kind": "IfStmt",
          "init": { "kind": "VarDecl", "name": "count", "init": "freq[\"cat\"]", "secondVar": "ok" },
          "cond": "ok",
          "body": [
            { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"Found cat: %d\\n\"", "count"] }
          ],
          "else": [
            { "kind": "CallExpr", "callee": "fmt.Println", "args": ["\"cat not found\""] }
          ]
        },
        {
          "kind": "CallExpr",
          "callee": "delete",
          "args": ["freq", "\"lazy\""]
        },
        {
          "kind": "VarDecl",
          "name": "keys",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "string" },
          "init": { "kind": "MakeExpr", "type": { "kind": "slice", "elem": "string" }, "len": 0, "cap": "len(freq)" }
        },
        {
          "kind": "RangeStmt",
          "key": "word",
          "collection": "freq",
          "body": [
            { "kind": "ExprStmt", "expr": "keys = append(keys, word)" }
          ]
        },
        { "kind": "CallExpr", "callee": "sort.Strings", "args": ["keys"] },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "word",
          "collection": "keys",
          "body": [
            { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"%s: %d\\n\"", "word", "freq[word]"] }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::unordered_map<K,V>` + "`" + ` | ` + "`" + `map[K]V` + "`" + ` | Go maps are hash maps by default |
| ` + "`" + `std::map<K,V>` + "`" + ` | ` + "`" + `map[K]V` + "`" + ` + sorted keys | Go has no ordered map; sort keys for ordered iteration |
| ` + "`" + `map[key]++` + "`" + ` | ` + "`" + `m[key]++` + "`" + ` | Zero-value initialization (int defaults to 0) |
| ` + "`" + `find(key) != end()` + "`" + ` | ` + "`" + `_, ok := m[key]; ok` + "`" + ` | Comma-ok idiom for existence check |
| ` + "`" + `erase(key)` + "`" + ` | ` + "`" + `delete(m, key)` + "`" + ` | Built-in delete function |
| ` + "`" + `insert({key, val})` + "`" + ` / ` + "`" + `emplace` + "`" + ` | ` + "`" + `m[key] = val` + "`" + ` | Direct assignment |
| Ordered iteration (` + "`" + `std::map` + "`" + `) | Sort keys, iterate sorted keys | Extract keys, sort, then range over sorted keys |
| Structured bindings ` + "`" + `[k, v]` + "`" + ` | ` + "`" + `for k, v := range m` + "`" + ` | Range provides key and value |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sort"
)

func main() {
	words := []string{
		"the", "quick", "brown", "fox", "jumps",
		"over", "the", "lazy", "dog", "the",
		"fox", "the", "dog", "quick", "the",
	}

	// Count word frequencies
	freq := make(map[string]int)
	for _, word := range words {
		freq[word]++
	}

	// Check if a word exists
	if count, ok := freq["cat"]; ok {
		fmt.Printf("Found cat: %d\n", count)
	} else {
		fmt.Println("cat not found")
	}

	// Delete a word
	delete(freq, "lazy")

	// Ordered iteration: sort keys first
	keys := make([]string, 0, len(freq))
	for word := range freq {
		keys = append(keys, word)
	}
	sort.Strings(keys)

	for _, word := range keys {
		fmt.Printf("%s: %d\n", word, freq[word])
	}
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 2: Set Operations (Union, Intersection, Difference)

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <set>
#include <iostream>
#include <algorithm>
#include <iterator>

int main() {
    std::set<int> a = {1, 2, 3, 4, 5};
    std::set<int> b = {3, 4, 5, 6, 7};

    // Union
    std::set<int> unionSet;
    std::set_union(a.begin(), a.end(), b.begin(), b.end(),
                   std::inserter(unionSet, unionSet.begin()));

    // Intersection
    std::set<int> interSet;
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(),
                          std::inserter(interSet, interSet.begin()));

    // Difference (a - b)
    std::set<int> diffSet;
    std::set_difference(a.begin(), a.end(), b.begin(), b.end(),
                        std::inserter(diffSet, diffSet.begin()));

    // Contains check
    if (a.count(3) > 0) {
        std::cout << "a contains 3" << std::endl;
    }

    // Insert and erase
    a.insert(10);
    a.erase(1);

    std::cout << "Union: ";
    for (int v : unionSet) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Intersection: ";
    for (int v : interSet) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Difference: ";
    for (int v : diffSet) std::cout << v << " ";
    std::cout << std::endl;

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "set", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    { "kind": "Include", "path": "algorithm", "system": true },
    { "kind": "Include", "path": "iterator", "system": true },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "a",
          "type": { "kind": "TypeRef", "name": "std::set", "templateArgs": [{ "kind": "TypeRef", "name": "int" }] },
          "init": [1, 2, 3, 4, 5]
        },
        {
          "kind": "Variable",
          "name": "b",
          "type": { "kind": "TypeRef", "name": "std::set", "templateArgs": [{ "kind": "TypeRef", "name": "int" }] },
          "init": [3, 4, 5, 6, 7]
        },
        {
          "kind": "Variable",
          "name": "unionSet",
          "type": { "kind": "TypeRef", "name": "std::set", "templateArgs": [{ "kind": "TypeRef", "name": "int" }] }
        },
        {
          "kind": "CallExpr",
          "callee": "std::set_union",
          "args": ["a.begin()", "a.end()", "b.begin()", "b.end()", "inserter(unionSet)"]
        },
        {
          "kind": "Variable",
          "name": "interSet",
          "type": { "kind": "TypeRef", "name": "std::set", "templateArgs": [{ "kind": "TypeRef", "name": "int" }] }
        },
        {
          "kind": "CallExpr",
          "callee": "std::set_intersection",
          "args": ["a.begin()", "a.end()", "b.begin()", "b.end()", "inserter(interSet)"]
        },
        {
          "kind": "Variable",
          "name": "diffSet",
          "type": { "kind": "TypeRef", "name": "std::set", "templateArgs": [{ "kind": "TypeRef", "name": "int" }] }
        },
        {
          "kind": "CallExpr",
          "callee": "std::set_difference",
          "args": ["a.begin()", "a.end()", "b.begin()", "b.end()", "inserter(diffSet)"]
        },
        {
          "kind": "IfStmt",
          "cond": { "kind": "CallExpr", "callee": "a.count", "args": [3], "op": "> 0" },
          "body": [
            { "kind": "CallExpr", "callee": "cout", "args": ["\"a contains 3\""] }
          ]
        },
        { "kind": "CallExpr", "callee": "a.insert", "args": [10] },
        { "kind": "CallExpr", "callee": "a.erase", "args": [1] }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "sort"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "union",
      "typeParams": [{ "name": "T", "constraint": "comparable" }],
      "params": [
        { "kind": "VarDecl", "name": "a", "type": { "kind": "TypeRef", "kind": "map", "key": "T", "value": "struct{}" } },
        { "kind": "VarDecl", "name": "b", "type": { "kind": "TypeRef", "kind": "map", "key": "T", "value": "struct{}" } }
      ],
      "returnType": { "kind": "TypeRef", "kind": "map", "key": "T", "value": "struct{}" },
      "body": [
        { "kind": "VarDecl", "name": "result", "init": { "kind": "MakeExpr", "type": { "kind": "map", "key": "T", "value": "struct{}" } } },
        { "kind": "RangeStmt", "key": "k", "collection": "a", "body": [{ "kind": "AssignStmt", "target": "result[k]", "value": "struct{}{}" }] },
        { "kind": "RangeStmt", "key": "k", "collection": "b", "body": [{ "kind": "AssignStmt", "target": "result[k]", "value": "struct{}{}" }] },
        { "kind": "ReturnStmt", "value": "result" }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "intersection",
      "typeParams": [{ "name": "T", "constraint": "comparable" }],
      "params": [
        { "kind": "VarDecl", "name": "a", "type": { "kind": "TypeRef", "kind": "map", "key": "T", "value": "struct{}" } },
        { "kind": "VarDecl", "name": "b", "type": { "kind": "TypeRef", "kind": "map", "key": "T", "value": "struct{}" } }
      ],
      "returnType": { "kind": "TypeRef", "kind": "map", "key": "T", "value": "struct{}" },
      "body": [
        { "kind": "VarDecl", "name": "result", "init": { "kind": "MakeExpr", "type": { "kind": "map", "key": "T", "value": "struct{}" } } },
        {
          "kind": "RangeStmt", "key": "k", "collection": "a",
          "body": [{
            "kind": "IfStmt",
            "cond": "_, ok := b[k]; ok",
            "body": [{ "kind": "AssignStmt", "target": "result[k]", "value": "struct{}{}" }]
          }]
        },
        { "kind": "ReturnStmt", "value": "result" }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "difference",
      "typeParams": [{ "name": "T", "constraint": "comparable" }],
      "params": [
        { "kind": "VarDecl", "name": "a", "type": { "kind": "TypeRef", "kind": "map", "key": "T", "value": "struct{}" } },
        { "kind": "VarDecl", "name": "b", "type": { "kind": "TypeRef", "kind": "map", "key": "T", "value": "struct{}" } }
      ],
      "returnType": { "kind": "TypeRef", "kind": "map", "key": "T", "value": "struct{}" }
    },
    {
      "kind": "FuncDecl",
      "name": "main"
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::set<T>` + "`" + ` | ` + "`" + `map[T]struct{}` + "`" + ` | ` + "`" + `struct{}` + "`" + ` uses zero bytes; presence = membership |
| ` + "`" + `set.insert(val)` + "`" + ` | ` + "`" + `m[val] = struct{}{}` + "`" + ` | Assignment adds to set |
| ` + "`" + `set.erase(val)` + "`" + ` | ` + "`" + `delete(m, val)` + "`" + ` | Built-in delete |
| ` + "`" + `set.count(val) > 0` + "`" + ` | ` + "`" + `_, ok := m[val]; ok` + "`" + ` | Comma-ok idiom |
| ` + "`" + `std::set_union` + "`" + ` | Loop over both maps, add to result | No stdlib set operations |
| ` + "`" + `std::set_intersection` + "`" + ` | Loop a, check in b, add matches | Manual intersection |
| ` + "`" + `std::set_difference` + "`" + ` | Loop a, add if not in b | Manual difference |
| Ordered ` + "`" + `std::set` + "`" + ` iteration | Sort keys, iterate sorted | Go maps are unordered |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sort"
)

func setUnion(a, b map[int]struct{}) map[int]struct{} {
	result := make(map[int]struct{}, len(a)+len(b))
	for k := range a {
		result[k] = struct{}{}
	}
	for k := range b {
		result[k] = struct{}{}
	}
	return result
}

func setIntersection(a, b map[int]struct{}) map[int]struct{} {
	result := make(map[int]struct{})
	for k := range a {
		if _, ok := b[k]; ok {
			result[k] = struct{}{}
		}
	}
	return result
}

func setDifference(a, b map[int]struct{}) map[int]struct{} {
	result := make(map[int]struct{})
	for k := range a {
		if _, ok := b[k]; !ok {
			result[k] = struct{}{}
		}
	}
	return result
}

func sortedKeys(s map[int]struct{}) []int {
	keys := make([]int, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func main() {
	a := map[int]struct{}{1: {}, 2: {}, 3: {}, 4: {}, 5: {}}
	b := map[int]struct{}{3: {}, 4: {}, 5: {}, 6: {}, 7: {}}

	unionSet := setUnion(a, b)
	interSet := setIntersection(a, b)
	diffSet := setDifference(a, b)

	// Contains check
	if _, ok := a[3]; ok {
		fmt.Println("a contains 3")
	}

	// Insert and erase
	a[10] = struct{}{}
	delete(a, 1)

	fmt.Print("Union: ")
	for _, v := range sortedKeys(unionSet) {
		fmt.Printf("%d ", v)
	}
	fmt.Println()

	fmt.Print("Intersection: ")
	for _, v := range sortedKeys(interSet) {
		fmt.Printf("%d ", v)
	}
	fmt.Println()

	fmt.Print("Difference: ")
	for _, v := range sortedKeys(diffSet) {
		fmt.Printf("%d ", v)
	}
	fmt.Println()
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 3: Multimap to Map of Slices

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <map>
#include <string>
#include <iostream>

int main() {
    std::multimap<std::string, std::string> tags;
    tags.insert({"color", "red"});
    tags.insert({"color", "blue"});
    tags.insert({"color", "green"});
    tags.insert({"size", "large"});
    tags.insert({"size", "medium"});
    tags.insert({"material", "cotton"});

    // Count entries for a key
    std::cout << "color has " << tags.count("color") << " entries" << std::endl;

    // Get all values for a key
    auto range = tags.equal_range("color");
    for (auto it = range.first; it != range.second; ++it) {
        std::cout << it->first << " -> " << it->second << std::endl;
    }

    // Erase all entries for a key
    tags.erase("size");

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "map", "system": true },
    { "kind": "Include", "path": "string", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "tags",
          "type": {
            "kind": "TypeRef",
            "name": "std::multimap",
            "templateArgs": [
              { "kind": "TypeRef", "name": "std::string" },
              { "kind": "TypeRef", "name": "std::string" }
            ]
          }
        },
        { "kind": "CallExpr", "callee": "tags.insert", "args": ["{\"color\", \"red\"}"] },
        { "kind": "CallExpr", "callee": "tags.insert", "args": ["{\"color\", \"blue\"}"] },
        { "kind": "CallExpr", "callee": "tags.insert", "args": ["{\"color\", \"green\"}"] },
        { "kind": "CallExpr", "callee": "tags.insert", "args": ["{\"size\", \"large\"}"] },
        { "kind": "CallExpr", "callee": "tags.insert", "args": ["{\"size\", \"medium\"}"] },
        { "kind": "CallExpr", "callee": "tags.insert", "args": ["{\"material\", \"cotton\"}"] },
        {
          "kind": "CallExpr",
          "callee": "cout",
          "args": ["\"color has \"", "tags.count(\"color\")", "\" entries\""]
        },
        {
          "kind": "Variable",
          "name": "range",
          "type": { "kind": "TypeRef", "name": "auto" },
          "init": { "kind": "CallExpr", "callee": "tags.equal_range", "args": ["\"color\""] }
        },
        {
          "kind": "ForStmt",
          "init": { "kind": "Variable", "name": "it", "init": "range.first" },
          "cond": "it != range.second",
          "step": "++it",
          "body": [
            { "kind": "CallExpr", "callee": "cout", "args": ["it->first", "\" -> \"", "it->second"] }
          ]
        },
        { "kind": "CallExpr", "callee": "tags.erase", "args": ["\"size\""] }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "tags",
          "type": { "kind": "TypeRef", "kind": "map", "key": "string", "value": { "kind": "slice", "elem": "string" } },
          "init": { "kind": "MakeExpr", "type": { "kind": "map", "key": "string", "value": "[]string" } }
        },
        {
          "kind": "ExprStmt",
          "expr": "tags[\"color\"] = append(tags[\"color\"], \"red\")",
          "comment": "repeated for each insert"
        },
        {
          "kind": "CallExpr",
          "callee": "fmt.Printf",
          "args": ["\"color has %d entries\\n\"", "len(tags[\"color\"])"]
        },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "val",
          "collection": "tags[\"color\"]",
          "body": [
            { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"color -> %s\\n\"", "val"] }
          ]
        },
        { "kind": "CallExpr", "callee": "delete", "args": ["tags", "\"size\""] }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::multimap<K,V>` + "`" + ` | ` + "`" + `map[K][]V` + "`" + ` | Slice value allows multiple values per key |
| ` + "`" + `multimap.insert({k, v})` + "`" + ` | ` + "`" + `m[k] = append(m[k], v)` + "`" + ` | Append to existing or nil slice |
| ` + "`" + `multimap.count(k)` + "`" + ` | ` + "`" + `len(m[k])` + "`" + ` | Length of value slice |
| ` + "`" + `equal_range(k)` + "`" + ` + iterator loop | ` + "`" + `for _, v := range m[k]` + "`" + ` | Direct range over value slice |
| ` + "`" + `multimap.erase(k)` + "`" + ` | ` + "`" + `delete(m, k)` + "`" + ` | Removes entire key and all values |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

func main() {
	tags := make(map[string][]string)
	tags["color"] = append(tags["color"], "red")
	tags["color"] = append(tags["color"], "blue")
	tags["color"] = append(tags["color"], "green")
	tags["size"] = append(tags["size"], "large")
	tags["size"] = append(tags["size"], "medium")
	tags["material"] = append(tags["material"], "cotton")

	// Count entries for a key
	fmt.Printf("color has %d entries\n", len(tags["color"]))

	// Get all values for a key
	for _, val := range tags["color"] {
		fmt.Printf("color -> %s\n", val)
	}

	// Erase all entries for a key
	delete(tags, "size")
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Pattern | Notes |
|---|---|---|
| ` + "`" + `std::map<K,V>` + "`" + ` | ` + "`" + `map[K]V` + "`" + ` | Go maps are hash maps (unordered) |
| ` + "`" + `std::unordered_map<K,V>` + "`" + ` | ` + "`" + `map[K]V` + "`" + ` | Same type; Go maps are hash maps by default |
| ` + "`" + `std::set<T>` + "`" + ` | ` + "`" + `map[T]struct{}` + "`" + ` | Empty struct uses zero memory |
| ` + "`" + `std::unordered_set<T>` + "`" + ` | ` + "`" + `map[T]struct{}` + "`" + ` | Same as set |
| ` + "`" + `std::multimap<K,V>` + "`" + ` | ` + "`" + `map[K][]V` + "`" + ` | Slice value for multiple entries |
| ` + "`" + `std::multiset<T>` + "`" + ` | ` + "`" + `map[T]int` + "`" + ` | Count-based multiset |
| ` + "`" + `map[key] = val` + "`" + ` | ` + "`" + `m[key] = val` + "`" + ` | Direct assignment |
| ` + "`" + `insert({key, val})` + "`" + ` | ` + "`" + `m[key] = val` + "`" + ` | Same as assignment (no duplicate key support) |
| ` + "`" + `emplace(key, val)` + "`" + ` | ` + "`" + `m[key] = val` + "`" + ` | No performance difference in Go |
| ` + "`" + `find(key) != end()` + "`" + ` | ` + "`" + `_, ok := m[key]; ok` + "`" + ` | Comma-ok idiom |
| ` + "`" + `at(key)` + "`" + ` (throws) | ` + "`" + `m[key]` + "`" + ` (returns zero) + ok check | Go returns zero value; check ok for safety |
| ` + "`" + `count(key)` + "`" + ` | Check with comma-ok | Returns 0 or 1 for map |
| ` + "`" + `erase(key)` + "`" + ` | ` + "`" + `delete(m, key)` + "`" + ` | Built-in delete; no-op if key absent |
| ` + "`" + `clear()` + "`" + ` | ` + "`" + `m = make(map[K]V)` + "`" + ` or ` + "`" + `clear(m)` + "`" + ` (Go 1.21+) | Recreate or use built-in clear |
| ` + "`" + `size()` + "`" + ` | ` + "`" + `len(m)` + "`" + ` | Built-in |
| ` + "`" + `empty()` + "`" + ` | ` + "`" + `len(m) == 0` + "`" + ` | Check length |
| Ordered iteration | Sort keys, iterate | ` + "`" + `sort.Strings(keys)` + "`" + ` or ` + "`" + `slices.Sort(keys)` + "`" + ` |
| Structured bindings ` + "`" + `[k, v]` + "`" + ` | ` + "`" + `for k, v := range m` + "`" + ` | Range yields key-value pairs |
| ` + "`" + `lower_bound` + "`" + ` / ` + "`" + `upper_bound` + "`" + ` | ` + "`" + `sort.Search` + "`" + ` on sorted slice | No equivalent on maps; use sorted slice |
| Custom comparator (` + "`" + `std::less` + "`" + `) | ` + "`" + `slices.SortFunc` + "`" + ` on keys | Sort keys with custom function |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/containers/vector_slice.md",
			Body: `# Vector to Slice

C++ ` + "`" + `std::vector<T>` + "`" + ` operations mapped to Go slice idioms through the full pipeline.

## Pattern 1: Building, Filtering, and Transforming a List

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>

struct Product {
    std::string name;
    double price;
    int quantity;
};

int main() {
    std::vector<Product> products;
    products.reserve(6);

    products.push_back({"Widget", 9.99, 100});
    products.push_back({"Gadget", 24.99, 50});
    products.push_back({"Doohickey", 4.99, 200});
    products.push_back({"Thingamajig", 49.99, 10});
    products.push_back({"Whatchamacallit", 14.99, 75});
    products.push_back({"Gizmo", 34.99, 30});

    // Filter: only products with price > 10
    std::vector<Product> expensive;
    std::copy_if(products.begin(), products.end(), std::back_inserter(expensive),
        [](const Product& p) { return p.price > 10.0; });

    // Transform: extract names
    std::vector<std::string> names;
    names.reserve(expensive.size());
    std::transform(expensive.begin(), expensive.end(), std::back_inserter(names),
        [](const Product& p) { return p.name; });

    // Sort by name
    std::sort(names.begin(), names.end());

    for (const auto& name : names) {
        std::cout << name << std::endl;
    }

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "vector", "system": true },
    { "kind": "Include", "path": "string", "system": true },
    { "kind": "Include", "path": "algorithm", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    {
      "kind": "Class",
      "name": "Product",
      "isStruct": true,
      "members": [
        { "kind": "Variable", "name": "name", "type": { "kind": "TypeRef", "name": "std::string" }, "access": "public" },
        { "kind": "Variable", "name": "price", "type": { "kind": "TypeRef", "name": "double" }, "access": "public" },
        { "kind": "Variable", "name": "quantity", "type": { "kind": "TypeRef", "name": "int" }, "access": "public" }
      ]
    },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "products",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "Product" }]
          }
        },
        { "kind": "CallExpr", "callee": "products.reserve", "args": [6] },
        { "kind": "CallExpr", "callee": "products.push_back", "args": ["{\"Widget\", 9.99, 100}"] },
        { "kind": "CallExpr", "callee": "products.push_back", "args": ["{\"Gadget\", 24.99, 50}"] },
        { "kind": "CallExpr", "callee": "products.push_back", "args": ["{\"Doohickey\", 4.99, 200}"] },
        { "kind": "CallExpr", "callee": "products.push_back", "args": ["{\"Thingamajig\", 49.99, 10}"] },
        { "kind": "CallExpr", "callee": "products.push_back", "args": ["{\"Whatchamacallit\", 14.99, 75}"] },
        { "kind": "CallExpr", "callee": "products.push_back", "args": ["{\"Gizmo\", 34.99, 30}"] },
        {
          "kind": "Variable",
          "name": "expensive",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "Product" }]
          }
        },
        {
          "kind": "CallExpr",
          "callee": "std::copy_if",
          "args": ["products.begin()", "products.end()", "std::back_inserter(expensive)", "lambda: p.price > 10.0"]
        },
        {
          "kind": "Variable",
          "name": "names",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "std::string" }]
          }
        },
        { "kind": "CallExpr", "callee": "names.reserve", "args": ["expensive.size()"] },
        {
          "kind": "CallExpr",
          "callee": "std::transform",
          "args": ["expensive.begin()", "expensive.end()", "std::back_inserter(names)", "lambda: p.name"]
        },
        {
          "kind": "CallExpr",
          "callee": "std::sort",
          "args": ["names.begin()", "names.end()"]
        },
        {
          "kind": "ForStmt",
          "range": { "var": "name", "container": "names" },
          "body": [
            { "kind": "CallExpr", "callee": "std::cout::operator<<", "args": ["name"] }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt", "slices"],
  "decls": [
    {
      "kind": "TypeDecl",
      "name": "Product",
      "fields": [
        { "kind": "VarDecl", "name": "Name", "type": { "kind": "TypeRef", "name": "string" } },
        { "kind": "VarDecl", "name": "Price", "type": { "kind": "TypeRef", "name": "float64" } },
        { "kind": "VarDecl", "name": "Quantity", "type": { "kind": "TypeRef", "name": "int" } }
      ]
    },
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "products",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "Product" },
          "init": {
            "kind": "MakeExpr",
            "type": { "kind": "slice", "elem": "Product" },
            "len": 0,
            "cap": 6
          }
        },
        {
          "kind": "ExprStmt",
          "expr": { "kind": "CallExpr", "callee": "append", "args": ["products", "{\"Widget\", 9.99, 100}"] },
          "comment": "repeated for each push_back"
        },
        {
          "kind": "VarDecl",
          "name": "expensive",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "Product" }
        },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "p",
          "collection": "products",
          "body": [
            {
              "kind": "IfStmt",
              "cond": "p.Price > 10.0",
              "body": [
                { "kind": "ExprStmt", "expr": { "kind": "CallExpr", "callee": "append", "args": ["expensive", "p"] } }
              ]
            }
          ]
        },
        {
          "kind": "VarDecl",
          "name": "names",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "string" },
          "init": { "kind": "MakeExpr", "type": { "kind": "slice", "elem": "string" }, "len": 0, "cap": "len(expensive)" }
        },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "p",
          "collection": "expensive",
          "body": [
            { "kind": "ExprStmt", "expr": { "kind": "CallExpr", "callee": "append", "args": ["names", "p.Name"] } }
          ]
        },
        {
          "kind": "CallExpr",
          "callee": "slices.Sort",
          "args": ["names"]
        },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "name",
          "collection": "names",
          "body": [
            { "kind": "CallExpr", "callee": "fmt.Println", "args": ["name"] }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `std::vector<T>` + "`" + ` | ` + "`" + `[]T` + "`" + ` | Go slices are dynamic arrays with the same semantics |
| ` + "`" + `reserve(n)` + "`" + ` | ` + "`" + `make([]T, 0, n)` + "`" + ` | Pre-allocates capacity without setting length |
| ` + "`" + `push_back(val)` + "`" + ` | ` + "`" + `s = append(s, val)` + "`" + ` | ` + "`" + `append` + "`" + ` may reallocate; must reassign |
| ` + "`" + `emplace_back(args...)` + "`" + ` | ` + "`" + `s = append(s, T{args...})` + "`" + ` | Construct literal inline |
| ` + "`" + `size()` + "`" + ` | ` + "`" + `len(s)` + "`" + ` | Built-in function |
| ` + "`" + `capacity()` + "`" + ` | ` + "`" + `cap(s)` + "`" + ` | Built-in function |
| ` + "`" + `std::copy_if` + "`" + ` | ` + "`" + `for range` + "`" + ` + ` + "`" + `if` + "`" + ` + ` + "`" + `append` + "`" + ` | No generic filter in stdlib; explicit loop is idiomatic |
| ` + "`" + `std::transform` + "`" + ` | ` + "`" + `for range` + "`" + ` + ` + "`" + `append` + "`" + ` | Map operation expressed as loop |
| ` + "`" + `std::sort(begin, end)` + "`" + ` | ` + "`" + `slices.Sort(s)` + "`" + ` | Go 1.21+ ` + "`" + `slices` + "`" + ` package |
| ` + "`" + `struct` + "`" + ` (C++ POD) | ` + "`" + `struct` + "`" + ` (exported fields) | Fields capitalized for visibility |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"slices"
)

type Product struct {
	Name     string
	Price    float64
	Quantity int
}

func main() {
	products := make([]Product, 0, 6)
	products = append(products,
		Product{"Widget", 9.99, 100},
		Product{"Gadget", 24.99, 50},
		Product{"Doohickey", 4.99, 200},
		Product{"Thingamajig", 49.99, 10},
		Product{"Whatchamacallit", 14.99, 75},
		Product{"Gizmo", 34.99, 30},
	)

	// Filter: only products with price > 10
	var expensive []Product
	for _, p := range products {
		if p.Price > 10.0 {
			expensive = append(expensive, p)
		}
	}

	// Transform: extract names
	names := make([]string, 0, len(expensive))
	for _, p := range expensive {
		names = append(names, p.Name)
	}

	// Sort by name
	slices.Sort(names)

	for _, name := range names {
		fmt.Println(name)
	}
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 2: Erase, Insert, and Resize

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <vector>
#include <iostream>
#include <algorithm>

int main() {
    std::vector<int> nums = {10, 20, 30, 40, 50, 60, 70};

    // Erase element at index 2
    nums.erase(nums.begin() + 2);

    // Insert 25 at index 2
    nums.insert(nums.begin() + 2, 25);

    // Erase range [4, 6)
    nums.erase(nums.begin() + 4, nums.begin() + 6);

    // Resize to 10, filling with zeros
    nums.resize(10);

    // Remove all odd numbers (erase-remove idiom)
    nums.erase(
        std::remove_if(nums.begin(), nums.end(), [](int n) { return n % 2 != 0; }),
        nums.end()
    );

    for (int n : nums) {
        std::cout << n << " ";
    }
    std::cout << std::endl;

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "vector", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    { "kind": "Include", "path": "algorithm", "system": true },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "nums",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{ "kind": "TypeRef", "name": "int" }]
          },
          "init": [10, 20, 30, 40, 50, 60, 70]
        },
        { "kind": "CallExpr", "callee": "nums.erase", "args": ["nums.begin() + 2"] },
        { "kind": "CallExpr", "callee": "nums.insert", "args": ["nums.begin() + 2", 25] },
        { "kind": "CallExpr", "callee": "nums.erase", "args": ["nums.begin() + 4", "nums.begin() + 6"] },
        { "kind": "CallExpr", "callee": "nums.resize", "args": [10] },
        {
          "kind": "CallExpr",
          "callee": "nums.erase",
          "args": [
            { "kind": "CallExpr", "callee": "std::remove_if", "args": ["nums.begin()", "nums.end()", "lambda: n%2 != 0"] },
            "nums.end()"
          ]
        },
        {
          "kind": "ForStmt",
          "range": { "var": "n", "container": "nums" },
          "body": [
            { "kind": "CallExpr", "callee": "std::cout::operator<<", "args": ["n", "\" \""] }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "nums",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "int" },
          "init": [10, 20, 30, 40, 50, 60, 70]
        },
        {
          "kind": "AssignStmt",
          "target": "nums",
          "value": "append(nums[:2], nums[3:]...)",
          "comment": "erase at index 2"
        },
        {
          "kind": "AssignStmt",
          "target": "nums",
          "value": "append(nums[:2], append([]int{25}, nums[2:]...)...)",
          "comment": "insert 25 at index 2"
        },
        {
          "kind": "AssignStmt",
          "target": "nums",
          "value": "append(nums[:4], nums[6:]...)",
          "comment": "erase range [4, 6)"
        },
        {
          "kind": "IfStmt",
          "comment": "resize to 10",
          "cond": "len(nums) < 10",
          "body": [
            { "kind": "AssignStmt", "target": "nums", "value": "append(nums, make([]int, 10-len(nums))...)" }
          ],
          "else": [
            { "kind": "AssignStmt", "target": "nums", "value": "nums[:10]" }
          ]
        },
        {
          "kind": "VarDecl",
          "name": "filtered",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "int" },
          "init": { "kind": "MakeExpr", "type": { "kind": "slice", "elem": "int" }, "len": 0, "cap": "len(nums)" }
        },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "n",
          "collection": "nums",
          "body": [
            {
              "kind": "IfStmt",
              "cond": "n%2 == 0",
              "body": [
                { "kind": "ExprStmt", "expr": { "kind": "CallExpr", "callee": "append", "args": ["filtered", "n"] } }
              ]
            }
          ]
        },
        { "kind": "AssignStmt", "target": "nums", "value": "filtered" },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "n",
          "collection": "nums",
          "body": [
            { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"%d \"", "n"] }
          ]
        },
        { "kind": "CallExpr", "callee": "fmt.Println" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `erase(begin+i)` + "`" + ` | ` + "`" + `s = append(s[:i], s[i+1:]...)` + "`" + ` | Splice around the removed index |
| ` + "`" + `insert(begin+i, val)` + "`" + ` | ` + "`" + `s = append(s[:i], append([]T{val}, s[i:]...)...)` + "`" + ` | Splice with new element in between |
| ` + "`" + `erase(begin+i, begin+j)` + "`" + ` | ` + "`" + `s = append(s[:i], s[j:]...)` + "`" + ` | Splice around the removed range |
| ` + "`" + `resize(n)` + "`" + ` (grow) | ` + "`" + `s = append(s, make([]T, n-len(s))...)` + "`" + ` | Append zero values to extend |
| ` + "`" + `resize(n)` + "`" + ` (shrink) | ` + "`" + `s = s[:n]` + "`" + ` | Re-slice to truncate |
| Erase-remove idiom | Filter loop building new slice | Clearer than in-place manipulation |
| ` + "`" + `std::remove_if` + "`" + ` + ` + "`" + `erase` + "`" + ` | ` + "`" + `for range` + "`" + ` + ` + "`" + `if` + "`" + ` + ` + "`" + `append` + "`" + ` | Build filtered result; assign back |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

func main() {
	nums := []int{10, 20, 30, 40, 50, 60, 70}

	// Erase element at index 2 (removes 30)
	nums = append(nums[:2], nums[3:]...)

	// Insert 25 at index 2
	nums = append(nums[:2], append([]int{25}, nums[2:]...)...)

	// Erase range [4, 6)
	nums = append(nums[:4], nums[6:]...)

	// Resize to 10 (fill with zero values)
	if len(nums) < 10 {
		nums = append(nums, make([]int, 10-len(nums))...)
	} else {
		nums = nums[:10]
	}

	// Remove all odd numbers
	filtered := make([]int, 0, len(nums))
	for _, n := range nums {
		if n%2 == 0 {
			filtered = append(filtered, n)
		}
	}
	nums = filtered

	for _, n := range nums {
		fmt.Printf("%d ", n)
	}
	fmt.Println()
}
` + "`" + `` + "`" + `` + "`" + `

---

## Pattern 3: 2D Vector and Nested Iteration

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <vector>
#include <iostream>

int main() {
    // Create a 3x4 matrix
    std::vector<std::vector<int>> matrix(3, std::vector<int>(4, 0));

    // Fill with values
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 4; ++j) {
            matrix[i][j] = i * 4 + j + 1;
        }
    }

    // Flatten
    std::vector<int> flat;
    flat.reserve(3 * 4);
    for (const auto& row : matrix) {
        for (int val : row) {
            flat.push_back(val);
        }
    }

    // Print flat
    for (int v : flat) {
        std::cout << v << " ";
    }
    std::cout << std::endl;

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "TranslationUnit",
  "children": [
    { "kind": "Include", "path": "vector", "system": true },
    { "kind": "Include", "path": "iostream", "system": true },
    {
      "kind": "Function",
      "name": "main",
      "returnType": { "kind": "TypeRef", "name": "int" },
      "body": [
        {
          "kind": "Variable",
          "name": "matrix",
          "type": {
            "kind": "TypeRef",
            "name": "std::vector",
            "templateArgs": [{
              "kind": "TypeRef",
              "name": "std::vector",
              "templateArgs": [{ "kind": "TypeRef", "name": "int" }]
            }]
          },
          "init": { "kind": "CallExpr", "callee": "std::vector", "args": [3, "std::vector<int>(4, 0)"] }
        },
        {
          "kind": "ForStmt",
          "init": { "kind": "Variable", "name": "i", "init": 0 },
          "cond": "i < 3",
          "step": "++i",
          "body": [
            {
              "kind": "ForStmt",
              "init": { "kind": "Variable", "name": "j", "init": 0 },
              "cond": "j < 4",
              "step": "++j",
              "body": [
                { "kind": "ExprStmt", "expr": "matrix[i][j] = i * 4 + j + 1" }
              ]
            }
          ]
        },
        {
          "kind": "Variable",
          "name": "flat",
          "type": { "kind": "TypeRef", "name": "std::vector", "templateArgs": [{ "kind": "TypeRef", "name": "int" }] }
        },
        { "kind": "CallExpr", "callee": "flat.reserve", "args": ["3 * 4"] },
        {
          "kind": "ForStmt",
          "range": { "var": "row", "container": "matrix" },
          "body": [
            {
              "kind": "ForStmt",
              "range": { "var": "val", "container": "row" },
              "body": [
                { "kind": "CallExpr", "callee": "flat.push_back", "args": ["val"] }
              ]
            }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "kind": "Module",
  "package": "main",
  "imports": ["fmt"],
  "decls": [
    {
      "kind": "FuncDecl",
      "name": "main",
      "body": [
        {
          "kind": "VarDecl",
          "name": "matrix",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": { "kind": "slice", "elem": "int" } },
          "init": { "kind": "MakeExpr", "type": { "kind": "slice", "elem": "[]int" }, "len": 3 }
        },
        {
          "kind": "RangeStmt",
          "key": "i",
          "collection": "matrix",
          "body": [
            {
              "kind": "AssignStmt",
              "target": "matrix[i]",
              "value": { "kind": "MakeExpr", "type": { "kind": "slice", "elem": "int" }, "len": 4 }
            },
            {
              "kind": "RangeStmt",
              "key": "j",
              "collection": "matrix[i]",
              "body": [
                { "kind": "AssignStmt", "target": "matrix[i][j]", "value": "i*4 + j + 1" }
              ]
            }
          ]
        },
        {
          "kind": "VarDecl",
          "name": "flat",
          "type": { "kind": "TypeRef", "kind": "slice", "elem": "int" },
          "init": { "kind": "MakeExpr", "type": { "kind": "slice", "elem": "int" }, "len": 0, "cap": "3 * 4" }
        },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "row",
          "collection": "matrix",
          "body": [
            { "kind": "AssignStmt", "target": "flat", "value": "append(flat, row...)" }
          ]
        },
        {
          "kind": "RangeStmt",
          "key": "_",
          "value": "v",
          "collection": "flat",
          "body": [
            { "kind": "CallExpr", "callee": "fmt.Printf", "args": ["\"%d \"", "v"] }
          ]
        },
        { "kind": "CallExpr", "callee": "fmt.Println" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

| C++ Construct | Go Equivalent | Rationale |
|---|---|---|
| ` + "`" + `vector<vector<int>>(3, vector<int>(4, 0))` + "`" + ` | ` + "`" + `make([][]int, 3)` + "`" + ` + loop ` + "`" + `make([]int, 4)` + "`" + ` | Go has no 2D slice constructor; each row allocated separately |
| Nested index-based for loops | Nested ` + "`" + `for range` + "`" + ` with index | Range provides index and value |
| Flatten with nested push_back | ` + "`" + `flat = append(flat, row...)` + "`" + ` | Variadic append spreads entire row |
| ` + "`" + `reserve(n)` + "`" + ` for flat | ` + "`" + `make([]int, 0, n)` + "`" + ` | Pre-allocate capacity |

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

func main() {
	// Create a 3x4 matrix
	matrix := make([][]int, 3)
	for i := range matrix {
		matrix[i] = make([]int, 4)
		for j := range matrix[i] {
			matrix[i][j] = i*4 + j + 1
		}
	}

	// Flatten
	flat := make([]int, 0, 3*4)
	for _, row := range matrix {
		flat = append(flat, row...)
	}

	// Print flat
	for _, v := range flat {
		fmt.Printf("%d ", v)
	}
	fmt.Println()
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Pattern | Notes |
|---|---|---|
| ` + "`" + `std::vector<T>` + "`" + ` | ` + "`" + `[]T` + "`" + ` | Go slices are dynamically-sized backed by arrays |
| ` + "`" + `vector<T> v` + "`" + ` (empty) | ` + "`" + `var s []T` + "`" + ` | Zero-value slice is nil, usable with append |
| ` + "`" + `vector<T> v(n)` + "`" + ` | ` + "`" + `make([]T, n)` + "`" + ` | Length and capacity both set to n |
| ` + "`" + `vector<T> v(n, val)` + "`" + ` | Loop + assign after ` + "`" + `make` + "`" + ` | No fill constructor in Go |
| ` + "`" + `reserve(n)` + "`" + ` | ` + "`" + `make([]T, 0, n)` + "`" + ` | Length 0, capacity n |
| ` + "`" + `push_back(val)` + "`" + ` | ` + "`" + `s = append(s, val)` + "`" + ` | Must reassign; may reallocate |
| ` + "`" + `emplace_back(args...)` + "`" + ` | ` + "`" + `s = append(s, T{args...})` + "`" + ` | Construct literal inline |
| ` + "`" + `size()` + "`" + ` | ` + "`" + `len(s)` + "`" + ` | Built-in |
| ` + "`" + `capacity()` + "`" + ` | ` + "`" + `cap(s)` + "`" + ` | Built-in |
| ` + "`" + `empty()` + "`" + ` | ` + "`" + `len(s) == 0` + "`" + ` | Nil slice has len 0 |
| ` + "`" + `clear()` + "`" + ` | ` + "`" + `s = s[:0]` + "`" + ` | Keeps capacity, resets length |
| ` + "`" + `resize(n)` + "`" + ` (grow) | ` + "`" + `append(s, make([]T, n-len(s))...)` + "`" + ` | Append zero values |
| ` + "`" + `resize(n)` + "`" + ` (shrink) | ` + "`" + `s = s[:n]` + "`" + ` | Re-slice |
| ` + "`" + `erase(begin+i)` + "`" + ` | ` + "`" + `append(s[:i], s[i+1:]...)` + "`" + ` | Splice around index |
| ` + "`" + `erase(begin+i, begin+j)` + "`" + ` | ` + "`" + `append(s[:i], s[j:]...)` + "`" + ` | Splice around range |
| ` + "`" + `insert(begin+i, val)` + "`" + ` | ` + "`" + `append(s[:i], append([]T{val}, s[i:]...)...)` + "`" + ` | Splice with insertion |
| ` + "`" + `s[i]` + "`" + ` | ` + "`" + `s[i]` + "`" + ` | Identical indexing |
| ` + "`" + `front()` + "`" + ` / ` + "`" + `back()` + "`" + ` | ` + "`" + `s[0]` + "`" + ` / ` + "`" + `s[len(s)-1]` + "`" + ` | Direct index access |
| ` + "`" + `data()` + "`" + ` | ` + "`" + `&s[0]` + "`" + ` or use ` + "`" + `unsafe.Pointer` + "`" + ` | Rarely needed in Go |
| Iterator range | ` + "`" + `for _, v := range s` + "`" + ` | Range is the standard iteration pattern |
| Erase-remove idiom | Filter loop + append | Build new slice; more readable |
| ` + "`" + `std::sort(begin, end)` + "`" + ` | ` + "`" + `slices.Sort(s)` + "`" + ` | Go 1.21+ slices package |
| ` + "`" + `std::sort` + "`" + ` with comparator | ` + "`" + `slices.SortFunc(s, cmp)` + "`" + ` | Custom comparison function |
| ` + "`" + `std::reverse(begin, end)` + "`" + ` | ` + "`" + `slices.Reverse(s)` + "`" + ` | In-place reversal |
| ` + "`" + `vector<vector<T>>` + "`" + ` | ` + "`" + `[][]T` + "`" + ` | Each inner slice allocated separately |
| Iterator invalidation | Not applicable | Go slices are value types; append may return new backing array |
| ` + "`" + `shrink_to_fit()` + "`" + ` | Copy to new slice | ` + "`" + `s2 := make([]T, len(s)); copy(s2, s)` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/error_handling/error_codes.md",
			Body: `# C-Style Error Codes to Go Error Handling

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

// Error code constants
#define SUCCESS        0
#define ERR_INVALID   -1
#define ERR_NOT_FOUND -2
#define ERR_NO_MEMORY -3
#define ERR_IO        -4

// Error code return with output parameters
int readFile(const char* path, char* buf, size_t* len) {
    if (path == nullptr || buf == nullptr || len == nullptr) {
        return ERR_INVALID;
    }

    FILE* fp = fopen(path, "r");
    if (fp == nullptr) {
        if (errno == ENOENT) {
            return ERR_NOT_FOUND;
        }
        return ERR_IO;
    }

    size_t bytesRead = fread(buf, 1, *len, fp);
    if (ferror(fp)) {
        fclose(fp);
        return ERR_IO;
    }

    *len = bytesRead;
    fclose(fp);
    return SUCCESS;
}

// errno-based error checking
int writeFile(const char* path, const char* data, size_t len) {
    FILE* fp = fopen(path, "w");
    if (fp == nullptr) {
        return ERR_IO;
    }

    size_t written = fwrite(data, 1, len, fp);
    if (written != len) {
        fclose(fp);
        return ERR_IO;
    }

    if (fclose(fp) != 0) {
        return ERR_IO;
    }

    return SUCCESS;
}

// HRESULT-style (Windows COM pattern)
typedef long HRESULT;
#define S_OK          0L
#define E_FAIL        0x80004005L
#define E_INVALIDARG  0x80070057L
#define E_OUTOFMEMORY 0x8007000EL

#define SUCCEEDED(hr) ((hr) >= 0)
#define FAILED(hr)    ((hr) < 0)

HRESULT initializeDevice(int deviceId, void** handle) {
    if (handle == nullptr) {
        return E_INVALIDARG;
    }

    if (deviceId < 0 || deviceId > 255) {
        return E_INVALIDARG;
    }

    *handle = malloc(sizeof(int));
    if (*handle == nullptr) {
        return E_OUTOFMEMORY;
    }

    *(int*)*handle = deviceId;
    return S_OK;
}

// Boolean success with errno
bool connectSocket(const char* host, int port, int* sockfd) {
    // ... connection logic ...
    if (/* connection failed */) {
        errno = ECONNREFUSED;
        return false;
    }
    *sockfd = /* fd */;
    return true;
}

// Struct-based error context (modern C)
typedef struct {
    int code;
    char message[256];
    char file[128];
    int line;
} ErrorContext;

int parseConfig(const char* path, ErrorContext* err) {
    FILE* fp = fopen(path, "r");
    if (fp == nullptr) {
        if (err != nullptr) {
            err->code = ERR_NOT_FOUND;
            snprintf(err->message, sizeof(err->message),
                     "config file not found: %s", path);
            strncpy(err->file, __FILE__, sizeof(err->file) - 1);
            err->line = __LINE__;
        }
        return ERR_NOT_FOUND;
    }
    fclose(fp);
    return SUCCESS;
}
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
[
  {
    "type": "Function",
    "name": "readFile",
    "return_type": {"name": "int"},
    "params": [
      {"name": "path", "type": {"name": "char", "const": true, "pointer": true}},
      {"name": "buf", "type": {"name": "char", "pointer": true}},
      {"name": "len", "type": {"name": "size_t", "pointer": true}}
    ],
    "body": [
      {
        "type": "IfStmt",
        "condition": {
          "type": "BinaryExpr",
          "operator": "||",
          "left": {"type": "BinaryExpr", "operator": "==", "left": "path", "right": "nullptr"},
          "right": {"type": "BinaryExpr", "operator": "==", "left": "buf", "right": "nullptr"}
        },
        "then": [
          {"type": "ReturnStmt", "value": {"type": "Identifier", "name": "ERR_INVALID"}}
        ]
      },
      {
        "type": "Variable",
        "name": "fp",
        "type": {"name": "FILE", "pointer": true},
        "init": {"type": "CallExpr", "func": "fopen", "args": ["path", "\"r\""]}
      },
      {
        "type": "IfStmt",
        "condition": {"type": "BinaryExpr", "operator": "==", "left": "fp", "right": "nullptr"},
        "then": [
          {
            "type": "IfStmt",
            "condition": {"type": "BinaryExpr", "operator": "==", "left": "errno", "right": "ENOENT"},
            "then": [{"type": "ReturnStmt", "value": "ERR_NOT_FOUND"}],
            "else": [{"type": "ReturnStmt", "value": "ERR_IO"}]
          }
        ]
      },
      {"type": "ReturnStmt", "value": {"type": "Identifier", "name": "SUCCESS"}}
    ]
  },
  {
    "type": "Function",
    "name": "writeFile",
    "return_type": {"name": "int"},
    "params": [
      {"name": "path", "type": {"name": "char", "const": true, "pointer": true}},
      {"name": "data", "type": {"name": "char", "const": true, "pointer": true}},
      {"name": "len", "type": {"name": "size_t"}}
    ],
    "body": [
      {
        "type": "Variable",
        "name": "fp",
        "type": {"name": "FILE", "pointer": true},
        "init": {"type": "CallExpr", "func": "fopen", "args": ["path", "\"w\""]}
      },
      {
        "type": "IfStmt",
        "condition": {"type": "BinaryExpr", "operator": "==", "left": "fp", "right": "nullptr"},
        "then": [{"type": "ReturnStmt", "value": "ERR_IO"}]
      },
      {"type": "ReturnStmt", "value": {"type": "Identifier", "name": "SUCCESS"}}
    ]
  },
  {
    "type": "Function",
    "name": "initializeDevice",
    "return_type": {"name": "HRESULT"},
    "params": [
      {"name": "deviceId", "type": {"name": "int"}},
      {"name": "handle", "type": {"name": "void", "pointer": true, "pointer": true}}
    ],
    "body": [
      {
        "type": "IfStmt",
        "condition": {"type": "BinaryExpr", "operator": "==", "left": "handle", "right": "nullptr"},
        "then": [{"type": "ReturnStmt", "value": "E_INVALIDARG"}]
      }
    ]
  },
  {
    "type": "Function",
    "name": "parseConfig",
    "return_type": {"name": "int"},
    "params": [
      {"name": "path", "type": {"name": "char", "const": true, "pointer": true}},
      {"name": "err", "type": {"name": "ErrorContext", "pointer": true}}
    ]
  }
]
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
[
  {
    "type": "VarDecl",
    "name": "ErrInvalid",
    "type": {"kind": "primitive", "name": "error"},
    "value": {"type": "CallExpr", "func": "errors.New", "args": ["\"invalid argument\""]},
    "const": false,
    "comment": "From C macro ERR_INVALID"
  },
  {
    "type": "VarDecl",
    "name": "ErrNotExist",
    "type": {"kind": "primitive", "name": "error"},
    "value": {"type": "CallExpr", "func": "errors.New", "args": ["\"not found\""]},
    "const": false,
    "comment": "From C macro ERR_NOT_FOUND / errno ENOENT"
  },
  {
    "type": "VarDecl",
    "name": "ErrNoMemory",
    "type": {"kind": "primitive", "name": "error"},
    "value": {"type": "CallExpr", "func": "errors.New", "args": ["\"out of memory\""]},
    "const": false,
    "comment": "From C macro ERR_NO_MEMORY / errno ENOMEM"
  },
  {
    "type": "VarDecl",
    "name": "ErrIO",
    "type": {"kind": "primitive", "name": "error"},
    "value": {"type": "CallExpr", "func": "errors.New", "args": ["\"I/O error\""]},
    "const": false,
    "comment": "From C macro ERR_IO"
  },
  {
    "type": "FuncDecl",
    "name": "ReadFile",
    "params": [{"name": "path", "type": {"kind": "primitive", "name": "string"}}],
    "returns": [
      {"type": {"kind": "slice", "elem_type": {"kind": "primitive", "name": "byte"}}},
      {"type": {"kind": "primitive", "name": "error"}}
    ],
    "body": [
      {
        "type": "ErrorHandling",
        "call": {"type": "CallExpr", "func": "os.ReadFile", "args": ["path"]},
        "err_var": "err",
        "body": [
          {
            "type": "IfStmt",
            "cond": {"type": "CallExpr", "func": "errors.Is", "args": ["err", "os.ErrNotExist"]},
            "then": [{"type": "ReturnStmt", "values": ["nil", "ErrNotExist"]}]
          },
          {"type": "ReturnStmt", "values": ["nil", "fmt.Errorf(\"read %s: %w\", path, err)"]}
        ]
      },
      {"type": "ReturnStmt", "values": ["data", "nil"]}
    ]
  },
  {
    "type": "FuncDecl",
    "name": "WriteFile",
    "params": [
      {"name": "path", "type": {"kind": "primitive", "name": "string"}},
      {"name": "data", "type": {"kind": "slice", "elem_type": {"kind": "primitive", "name": "byte"}}}
    ],
    "returns": [
      {"type": {"kind": "primitive", "name": "error"}}
    ],
    "body": [
      {
        "type": "ErrorHandling",
        "call": {"type": "CallExpr", "func": "os.WriteFile", "args": ["path", "data", "0644"]},
        "err_var": "err",
        "body": [
          {"type": "ReturnStmt", "values": ["fmt.Errorf(\"write %s: %w\", path, err)"]}
        ]
      },
      {"type": "ReturnStmt", "values": ["nil"]}
    ]
  },
  {
    "type": "FuncDecl",
    "name": "InitializeDevice",
    "params": [{"name": "deviceID", "type": {"kind": "primitive", "name": "int"}}],
    "returns": [
      {"type": {"kind": "pointer", "name": "*Device"}},
      {"type": {"kind": "primitive", "name": "error"}}
    ],
    "body": [
      {
        "type": "IfStmt",
        "cond": {"type": "BinaryExpr", "op": "||",
          "left": {"type": "BinaryExpr", "op": "<", "left": "deviceID", "right": "0"},
          "right": {"type": "BinaryExpr", "op": ">", "left": "deviceID", "right": "255"}
        },
        "then": [{"type": "ReturnStmt", "values": ["nil", "ErrInvalid"]}]
      },
      {"type": "ReturnStmt", "values": ["&Device{ID: deviceID}", "nil"]}
    ]
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "ConfigError",
    "fields": [
      {"name": "Code", "type": {"kind": "primitive", "name": "int"}},
      {"name": "Message", "type": {"kind": "primitive", "name": "string"}},
      {"name": "File", "type": {"kind": "primitive", "name": "string"}},
      {"name": "Line", "type": {"kind": "primitive", "name": "int"}}
    ],
    "comment": "From C struct ErrorContext"
  },
  {
    "type": "FuncDecl",
    "name": "Error",
    "receiver": {"name": "e", "type": {"kind": "pointer", "name": "*ConfigError"}},
    "returns": [{"type": {"kind": "primitive", "name": "string"}}],
    "body": [
      {"type": "ReturnStmt", "values": ["fmt.Sprintf(\"%s (code %d at %s:%d)\", e.Message, e.Code, e.File, e.Line)"]}
    ]
  },
  {
    "type": "FuncDecl",
    "name": "ParseConfig",
    "params": [{"name": "path", "type": {"kind": "primitive", "name": "string"}}],
    "returns": [{"type": {"kind": "primitive", "name": "error"}}],
    "body": [
      {
        "type": "ErrorHandling",
        "call": {"type": "CallExpr", "func": "os.Open", "args": ["path"]},
        "err_var": "err",
        "body": [
          {"type": "ReturnStmt", "values": ["&ConfigError{Code: -2, Message: \"config file not found: \" + path}"]}
        ]
      },
      {"type": "ReturnStmt", "values": ["nil"]}
    ]
  }
]
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `int` + "`" + ` return code → ` + "`" + `(T, error)` + "`" + ` multiple returns** functions returning int success/failure codes become functions returning ` + "`" + `(result, error)` + "`" + ` pairs; success (0) maps to ` + "`" + `nil` + "`" + ` error
2. **Output parameters (` + "`" + `char* buf, size_t* len` + "`" + `) → return values** pointer-based output parameters become additional return values in Go
3. **` + "`" + `#define ERR_*` + "`" + ` macros → sentinel ` + "`" + `errors.New()` + "`" + ` variables** error code macros become package-level ` + "`" + `var` + "`" + ` declarations using ` + "`" + `errors.New` + "`" + `
4. **` + "`" + `errno` + "`" + ` checking → ` + "`" + `errors.Is(err, os.ErrX)` + "`" + `** global errno comparisons map to Go standard library sentinel errors
5. **` + "`" + `nullptr` + "`" + ` checks on output params → removed** Go does not use output parameters, so null-guard checks on output pointers are eliminated
6. **` + "`" + `HRESULT` + "`" + ` / ` + "`" + `SUCCEEDED()` + "`" + ` / ` + "`" + `FAILED()` + "`" + ` → ` + "`" + `if err != nil` + "`" + `** COM-style HRESULT patterns collapse to standard Go error checking
7. **` + "`" + `void**` + "`" + ` handle output → return ` + "`" + `(*T, error)` + "`" + `** opaque handle allocation through double pointers becomes a typed pointer return
8. **` + "`" + `bool` + "`" + ` return with errno → ` + "`" + `(T, error)` + "`" + `** boolean success indicators with global errno context become Go's explicit error returns
9. **` + "`" + `ErrorContext` + "`" + ` struct → custom error type** C structs used for rich error context become Go structs implementing the ` + "`" + `error` + "`" + ` interface
10. **` + "`" + `fclose()` + "`" + ` error checking → ` + "`" + `defer f.Close()` + "`" + ` or explicit check** file close error codes map to defer patterns or explicit error returns in Go

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package fileio

import (
	"errors"
	"fmt"
	"os"
)

// Sentinel errors mapped from C error codes and errno values.
var (
	ErrInvalid  = errors.New("invalid argument")   // ERR_INVALID / EINVAL
	ErrNotExist = errors.New("not found")           // ERR_NOT_FOUND / ENOENT
	ErrNoMemory = errors.New("out of memory")       // ERR_NO_MEMORY / ENOMEM
	ErrIO       = errors.New("I/O error")           // ERR_IO
)

// ReadFile reads the entire file at path into a byte slice.
func ReadFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotExist, path)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// WriteFile writes data to the named file.
func WriteFile(path string, data []byte) error {
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Device represents an initialized device handle.
type Device struct {
	ID int
}

// InitializeDevice creates a device handle for the given ID.
func InitializeDevice(deviceID int) (*Device, error) {
	if deviceID < 0 || deviceID > 255 {
		return nil, fmt.Errorf("%w: device ID %d out of range [0, 255]", ErrInvalid, deviceID)
	}
	return &Device{ID: deviceID}, nil
}

// ConfigError provides structured error context (from C ErrorContext struct).
type ConfigError struct {
	Code    int
	Message string
	File    string
	Line    int
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return fmt.Sprintf("%s (code %d at %s:%d)", e.Message, e.Code, e.File, e.Line)
}

// ParseConfig validates and parses a configuration file.
func ParseConfig(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return &ConfigError{
			Code:    -2,
			Message: "config file not found: " + path,
		}
	}
	defer func() { _ = f.Close() }()

	// ... parse config ...
	return nil
}
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| ` + "`" + `return ERR_INVALID;` + "`" + ` | ` + "`" + `return nil, ErrInvalid` + "`" + ` | ` + "`" + `ReturnStmt{Value: Identifier "ERR_INVALID"}` + "`" + ` | ` + "`" + `ReturnStmt{Values: [nil, ErrInvalid]}` + "`" + ` |
| ` + "`" + `return SUCCESS;` + "`" + ` (0) | ` + "`" + `return result, nil` + "`" + ` | ` + "`" + `ReturnStmt{Value: Identifier "SUCCESS"}` + "`" + ` | ` + "`" + `ReturnStmt{Values: [result, nil]}` + "`" + ` |
| ` + "`" + `#define ERR_NOT_FOUND -2` + "`" + ` | ` + "`" + `var ErrNotExist = errors.New(...)` + "`" + ` | ` + "`" + `Variable{Name: "ERR_NOT_FOUND", Const: true}` + "`" + ` | ` + "`" + `VarDecl{Name: "ErrNotExist", Value: CallExpr}` + "`" + ` |
| ` + "`" + `errno == ENOENT` + "`" + ` | ` + "`" + `errors.Is(err, os.ErrNotExist)` + "`" + ` | ` + "`" + `BinaryExpr{Op: "==", Left: "errno", Right: "ENOENT"}` + "`" + ` | ` + "`" + `CallExpr{Func: "errors.Is"}` + "`" + ` |
| ` + "`" + `errno == EINVAL` + "`" + ` | ` + "`" + `errors.Is(err, ErrInvalid)` + "`" + ` | ` + "`" + `BinaryExpr{Op: "==", Left: "errno", Right: "EINVAL"}` + "`" + ` | ` + "`" + `CallExpr{Func: "errors.Is"}` + "`" + ` |
| ` + "`" + `errno == ENOMEM` + "`" + ` | ` + "`" + `errors.Is(err, ErrNoMemory)` + "`" + ` | ` + "`" + `BinaryExpr{Op: "==", Left: "errno", Right: "ENOMEM"}` + "`" + ` | ` + "`" + `CallExpr{Func: "errors.Is"}` + "`" + ` |
| ` + "`" + `int fn(char* buf, size_t* len)` + "`" + ` | ` + "`" + `func Fn() ([]byte, error)` + "`" + ` | ` + "`" + `Function` + "`" + ` with pointer output params | ` + "`" + `FuncDecl` + "`" + ` with multiple ` + "`" + `Returns` + "`" + ` |
| ` + "`" + `HRESULT` + "`" + ` / ` + "`" + `SUCCEEDED(hr)` + "`" + ` | ` + "`" + `if err != nil` + "`" + ` | ` + "`" + `IfStmt` + "`" + ` with macro condition | ` + "`" + `ErrorHandling{ErrVar: "err"}` + "`" + ` |
| ` + "`" + `void** handle` + "`" + ` output | ` + "`" + `(*T, error)` + "`" + ` return | ` + "`" + `Parameter{Type: void**}` + "`" + ` | ` + "`" + `ParamDecl` + "`" + ` removed; added to ` + "`" + `Returns` + "`" + ` |
| ` + "`" + `bool` + "`" + ` return + errno | ` + "`" + `(T, error)` + "`" + ` return | ` + "`" + `Function{ReturnType: bool}` + "`" + ` | ` + "`" + `FuncDecl{Returns: [T, error]}` + "`" + ` |
| ` + "`" + `ErrorContext` + "`" + ` struct param | Custom error type implementing ` + "`" + `error` + "`" + ` | ` + "`" + `Class` + "`" + ` / struct with error fields | ` + "`" + `TypeDecl` + "`" + ` + ` + "`" + `FuncDecl{Name: "Error"}` + "`" + ` |
| ` + "`" + `fclose(fp)` + "`" + ` error check | ` + "`" + `defer func() { _ = f.Close() }()` + "`" + ` | ` + "`" + `ExprStmt{CallExpr "fclose"}` + "`" + ` | ` + "`" + `DeferStmt{Call: "f.Close()"}` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/error_handling/exceptions.md",
			Body: `# C++ Exceptions to Go Error Handling

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

// Custom exception hierarchy
class AppError : public std::runtime_error {
public:
    explicit AppError(const std::string& msg) : std::runtime_error(msg) {}
};

class FileNotFoundError : public AppError {
public:
    FileNotFoundError(const std::string& path)
        : AppError("file not found: " + path), path_(path) {}
    const std::string& path() const { return path_; }
private:
    std::string path_;
};

class ParseError : public AppError {
public:
    ParseError(const std::string& msg, int line)
        : AppError(msg), line_(line) {}
    int line() const { return line_; }
private:
    int line_;
};

// Function that throws
std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw FileNotFoundError(path);
    }
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    return content;
}

// Function with multiple catch blocks
std::vector<std::string> processFile(const std::string& path) {
    try {
        std::string content = readFile(path);
        std::vector<std::string> lines;
        // ... parse content into lines ...
        if (lines.empty()) {
            throw ParseError("empty file", 0);
        }
        return lines;
    } catch (const FileNotFoundError& e) {
        // Log and provide default
        std::cerr << "Warning: " << e.what() << std::endl;
        return {};
    } catch (const ParseError& e) {
        // Re-throw with context
        throw AppError("processing failed at line " +
                        std::to_string(e.line()) + ": " + e.what());
    } catch (const std::exception& e) {
        // Catch-all for standard exceptions
        throw AppError(std::string("unexpected error: ") + e.what());
    }
}

// Nested try-catch
void processFiles(const std::vector<std::string>& paths) {
    for (const auto& path : paths) {
        try {
            auto result = processFile(path);
            // use result...
        } catch (const AppError& e) {
            std::cerr << "Skipping " << path << ": " << e.what() << std::endl;
        }
    }
}
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
[
  {
    "type": "Class",
    "kind": "class",
    "name": "AppError",
    "base_classes": [{"name": "std::runtime_error", "access": "public"}],
    "constructors": [{
      "params": [{"name": "msg", "type": {"name": "std::string", "const": true, "reference": true}}],
      "init_list": [{"member": "std::runtime_error", "value": "msg"}],
      "access": "public"
    }]
  },
  {
    "type": "Class",
    "kind": "class",
    "name": "FileNotFoundError",
    "base_classes": [{"name": "AppError", "access": "public"}],
    "fields": [
      {"name": "path_", "type": {"name": "std::string"}, "access": "private"}
    ],
    "constructors": [{
      "params": [{"name": "path", "type": {"name": "std::string", "const": true, "reference": true}}],
      "init_list": [
        {"member": "AppError", "value": "\"file not found: \" + path"},
        {"member": "path_", "value": "path"}
      ],
      "access": "public"
    }],
    "methods": [{
      "name": "path",
      "return_type": {"name": "std::string", "const": true, "reference": true},
      "params": [],
      "access": "public",
      "const": true
    }]
  },
  {
    "type": "Class",
    "kind": "class",
    "name": "ParseError",
    "base_classes": [{"name": "AppError", "access": "public"}],
    "fields": [
      {"name": "line_", "type": {"name": "int"}, "access": "private"}
    ],
    "constructors": [{
      "params": [
        {"name": "msg", "type": {"name": "std::string", "const": true, "reference": true}},
        {"name": "line", "type": {"name": "int"}}
      ],
      "init_list": [
        {"member": "AppError", "value": "msg"},
        {"member": "line_", "value": "line"}
      ],
      "access": "public"
    }]
  },
  {
    "type": "Function",
    "name": "readFile",
    "return_type": {"name": "std::string"},
    "params": [{"name": "path", "type": {"name": "std::string", "const": true, "reference": true}}],
    "body": [
      {
        "type": "Variable",
        "name": "file",
        "type": {"name": "std::ifstream"},
        "init": {"type": "CallExpr", "args": ["path"]}
      },
      {
        "type": "IfStmt",
        "condition": {"type": "UnaryExpr", "operator": "!", "operand": "file.is_open()"},
        "then": [
          {
            "type": "ThrowExpr",
            "value": {"type": "CallExpr", "func": "FileNotFoundError", "args": ["path"]}
          }
        ]
      },
      {"type": "ReturnStmt", "value": "content"}
    ]
  },
  {
    "type": "Function",
    "name": "processFile",
    "return_type": {"name": "std::vector", "template_args": [{"name": "std::string"}]},
    "params": [{"name": "path", "type": {"name": "std::string", "const": true, "reference": true}}],
    "body": [
      {
        "type": "TryBlock",
        "body": [
          {
            "type": "Variable",
            "name": "content",
            "init": {"type": "CallExpr", "func": "readFile", "args": ["path"]}
          },
          {
            "type": "IfStmt",
            "condition": "lines.empty()",
            "then": [
              {
                "type": "ThrowExpr",
                "value": {"type": "CallExpr", "func": "ParseError", "args": ["\"empty file\"", "0"]}
              }
            ]
          },
          {"type": "ReturnStmt", "value": "lines"}
        ],
        "catches": [
          {
            "param_name": "e",
            "param_type": {"name": "FileNotFoundError", "const": true, "reference": true},
            "body": [{"type": "ReturnStmt", "value": "{}"}]
          },
          {
            "param_name": "e",
            "param_type": {"name": "ParseError", "const": true, "reference": true},
            "body": [
              {
                "type": "ThrowExpr",
                "value": {"type": "CallExpr", "func": "AppError", "args": ["..."]}
              }
            ]
          },
          {
            "param_name": "e",
            "param_type": {"name": "std::exception", "const": true, "reference": true},
            "body": [
              {
                "type": "ThrowExpr",
                "value": {"type": "CallExpr", "func": "AppError", "args": ["..."]}
              }
            ]
          }
        ]
      }
    ]
  }
]
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
[
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "AppError",
    "fields": [
      {"name": "Msg", "type": {"kind": "primitive", "name": "string"}}
    ],
    "comment": "Base application error (from C++ AppError : std::runtime_error)"
  },
  {
    "type": "FuncDecl",
    "name": "Error",
    "receiver": {"name": "e", "type": {"kind": "pointer", "name": "*AppError"}},
    "returns": [{"type": {"kind": "primitive", "name": "string"}}],
    "body": [
      {"type": "ReturnStmt", "values": ["e.Msg"]}
    ]
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "FileNotFoundError",
    "fields": [
      {"name": "Path", "type": {"kind": "primitive", "name": "string"}}
    ],
    "comment": "From C++ FileNotFoundError : AppError"
  },
  {
    "type": "FuncDecl",
    "name": "Error",
    "receiver": {"name": "e", "type": {"kind": "pointer", "name": "*FileNotFoundError"}},
    "returns": [{"type": {"kind": "primitive", "name": "string"}}],
    "body": [
      {"type": "ReturnStmt", "values": ["\"file not found: \" + e.Path"]}
    ]
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "ParseError",
    "fields": [
      {"name": "Msg", "type": {"kind": "primitive", "name": "string"}},
      {"name": "Line", "type": {"kind": "primitive", "name": "int"}}
    ],
    "comment": "From C++ ParseError : AppError"
  },
  {
    "type": "FuncDecl",
    "name": "ReadFile",
    "params": [{"name": "path", "type": {"kind": "primitive", "name": "string"}}],
    "returns": [
      {"type": {"kind": "primitive", "name": "string"}},
      {"type": {"kind": "primitive", "name": "error"}}
    ],
    "body": [
      {
        "type": "ErrorHandling",
        "call": {"type": "CallExpr", "func": "os.ReadFile", "args": ["path"]},
        "err_var": "err",
        "body": [
          {"type": "ReturnStmt", "values": ["\"\"", "&FileNotFoundError{Path: path}"]}
        ]
      },
      {"type": "ReturnStmt", "values": ["string(data)", "nil"]}
    ]
  },
  {
    "type": "FuncDecl",
    "name": "ProcessFile",
    "params": [{"name": "path", "type": {"kind": "primitive", "name": "string"}}],
    "returns": [
      {"type": {"kind": "slice", "elem_type": {"kind": "primitive", "name": "string"}}},
      {"type": {"kind": "primitive", "name": "error"}}
    ],
    "body": [
      {
        "type": "ErrorHandling",
        "call": {"type": "CallExpr", "func": "ReadFile", "args": ["path"]},
        "err_var": "err",
        "body": [
          {
            "type": "IfStmt",
            "cond": {"type": "CallExpr", "func": "errors.As", "args": ["err", "&FileNotFoundError{}"]},
            "then": [
              {"type": "ExprStmt", "expr": {"type": "CallExpr", "func": "log.Printf", "args": ["\"Warning: %v\"", "err"]}},
              {"type": "ReturnStmt", "values": ["nil", "nil"]}
            ]
          },
          {"type": "ReturnStmt", "values": ["nil", "fmt.Errorf(\"processing failed: %w\", err)"]}
        ]
      },
      {
        "type": "IfStmt",
        "cond": {"type": "BinaryExpr", "op": "==", "left": "len(lines)", "right": "0"},
        "then": [
          {"type": "ReturnStmt", "values": ["nil", "&ParseError{Msg: \"empty file\", Line: 0}"]}
        ]
      },
      {"type": "ReturnStmt", "values": ["lines", "nil"]}
    ]
  }
]
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `throw` + "`" + ` → ` + "`" + `return ..., error` + "`" + `** every function that can throw gains an ` + "`" + `error` + "`" + ` return value; ` + "`" + `throw X` + "`" + ` becomes ` + "`" + `return zero, &XError{...}` + "`" + `
2. **` + "`" + `catch(const Type& e)` + "`" + ` → ` + "`" + `errors.As(err, &target)` + "`" + `** specific catch types map to ` + "`" + `errors.As` + "`" + ` for unwrapping typed errors
3. **` + "`" + `catch(const std::exception& e)` + "`" + ` → ` + "`" + `if err != nil` + "`" + `** the broadest catch becomes a general ` + "`" + `err != nil` + "`" + ` check
4. **` + "`" + `catch(...)` + "`" + ` → ` + "`" + `if err != nil` + "`" + `** catch-all maps to the same general error check with no type assertion
5. **Exception class hierarchy → custom error types** each C++ exception class becomes a Go struct implementing the ` + "`" + `error` + "`" + ` interface via an ` + "`" + `Error() string` + "`" + ` method
6. **Inheritance in exceptions → composition or flat types** Go does not have inheritance; each error type independently implements ` + "`" + `error` + "`" + `; use ` + "`" + `errors.Is` + "`" + ` / ` + "`" + `errors.As` + "`" + ` for matching
7. **Rethrow (` + "`" + `throw;` + "`" + `) → ` + "`" + `return err` + "`" + `** bare throw in a catch block becomes ` + "`" + `return ..., err` + "`" + ` to propagate the original error
8. **Rethrow with context → ` + "`" + `fmt.Errorf("context: %w", err)` + "`" + `** wrapping preserves the error chain for ` + "`" + `errors.Is` + "`" + ` / ` + "`" + `errors.As` + "`" + `
9. **Nested try/catch → sequential ` + "`" + `if err != nil` + "`" + ` blocks** each try body statement that can fail produces its own error check
10. **Constructor throw → ` + "`" + `return nil, err` + "`" + ` in factory** the ` + "`" + `NewX()` + "`" + ` factory function returns ` + "`" + `(*T, error)` + "`" + ` and the constructor body's throw becomes an early error return

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package fileproc

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

// AppError is the base application error.
type AppError struct {
	Msg string
}

// Error implements the error interface.
func (e *AppError) Error() string {
	return e.Msg
}

// FileNotFoundError indicates a file was not found.
type FileNotFoundError struct {
	Path string
}

// Error implements the error interface.
func (e *FileNotFoundError) Error() string {
	return "file not found: " + e.Path
}

// ParseError indicates a parse failure at a specific line.
type ParseError struct {
	Msg  string
	Line int
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	return fmt.Sprintf("parse error at line %d: %s", e.Line, e.Msg)
}

// ReadFile reads the entire file at path.
func ReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", &FileNotFoundError{Path: path}
	}
	return string(data), nil
}

// ProcessFile reads and parses a file into lines.
func ProcessFile(path string) ([]string, error) {
	content, err := ReadFile(path)
	if err != nil {
		var fnf *FileNotFoundError
		if errors.As(err, &fnf) {
			log.Printf("Warning: %v", err)
			return nil, nil
		}
		return nil, fmt.Errorf("processing failed: %w", err)
	}

	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return nil, &ParseError{Msg: "empty file", Line: 0}
	}

	return lines, nil
}

// ProcessFiles processes each file, logging and skipping failures.
func ProcessFiles(paths []string) error {
	for _, path := range paths {
		result, err := ProcessFile(path)
		if err != nil {
			var appErr *AppError
			if errors.As(err, &appErr) {
				log.Printf("Skipping %s: %v", path, err)
				continue
			}
			return fmt.Errorf("unexpected error processing %s: %w", path, err)
		}
		_ = result // use result...
	}
	return nil
}
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| ` + "`" + `throw FileNotFoundError(path)` + "`" + ` | ` + "`" + `return "", &FileNotFoundError{Path: path}` + "`" + ` | ` + "`" + `ThrowExpr{Value: CallExpr}` + "`" + ` | ` + "`" + `ReturnStmt{Values: [zero, error]}` + "`" + ` |
| ` + "`" + `throw;` + "`" + ` (rethrow) | ` + "`" + `return ..., err` + "`" + ` | ` + "`" + `ThrowExpr{Value: nil}` + "`" + ` | ` + "`" + `ReturnStmt{Values: [IdentExpr "err"]}` + "`" + ` |
| ` + "`" + `catch (const FileNotFoundError& e)` + "`" + ` | ` + "`" + `errors.As(err, &fnf)` + "`" + ` | ` + "`" + `CatchClause{ParamType: "FileNotFoundError"}` + "`" + ` | ` + "`" + `IfStmt` + "`" + ` with ` + "`" + `CallExpr{Func: "errors.As"}` + "`" + ` |
| ` + "`" + `catch (const std::exception& e)` + "`" + ` | ` + "`" + `if err != nil` + "`" + ` | ` + "`" + `CatchClause{ParamType: "std::exception"}` + "`" + ` | ` + "`" + `ErrorHandling{ErrVar: "err"}` + "`" + ` |
| ` + "`" + `catch (...)` + "`" + ` | ` + "`" + `if err != nil` + "`" + ` | ` + "`" + `CatchClause{ParamType: nil}` + "`" + ` | ` + "`" + `ErrorHandling{ErrVar: "err"}` + "`" + ` |
| Exception class with ` + "`" + `what()` + "`" + ` | Struct with ` + "`" + `Error() string` + "`" + ` | ` + "`" + `Class` + "`" + ` with base ` + "`" + `std::exception` + "`" + ` | ` + "`" + `TypeDecl` + "`" + ` + ` + "`" + `FuncDecl{Name: "Error"}` + "`" + ` |
| Exception inheritance hierarchy | Flat error types, each implements ` + "`" + `error` + "`" + ` | ` + "`" + `Class.BaseClasses` + "`" + ` | Independent ` + "`" + `TypeDecl` + "`" + ` nodes |
| ` + "`" + `try { ... } catch { ... }` + "`" + ` | ` + "`" + `if err != nil { ... }` + "`" + ` per call | ` + "`" + `TryBlock{Body, Catches}` + "`" + ` | ` + "`" + `ErrorHandling{Call, ErrVar, Body}` + "`" + ` |
| ` + "`" + `e.what()` + "`" + ` in catch | ` + "`" + `err.Error()` + "`" + ` | ` + "`" + `MemberExpr{Member: "what"}` + "`" + ` | ` + "`" + `MethodCallExpr{Method: "Error"}` + "`" + ` |
| Rethrow with context | ` + "`" + `fmt.Errorf("context: %w", err)` + "`" + ` | ` + "`" + `ThrowExpr` + "`" + ` with new message | ` + "`" + `ReturnStmt` + "`" + ` with ` + "`" + `CallExpr{Func: "fmt.Errorf"}` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/io/file_os.md",
			Body: `# File I/O to os / bufio / encoding/binary

> C++ file stream patterns mapped to Go's ` + "`" + `os` + "`" + `, ` + "`" + `bufio` + "`" + `, and ` + "`" + `encoding/binary` + "`" + ` packages.

---

## 1. Reading a File Line by Line: ` + "`" + `std::ifstream` + "`" + ` to ` + "`" + `os.Open` + "`" + ` + ` + "`" + `bufio.Scanner` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <fstream>
#include <iostream>
#include <string>

int main() {
    std::ifstream file("input.txt");
    if (!file.is_open()) {
        std::cerr << "Failed to open file" << std::endl;
        return 1;
    }

    std::string line;
    int lineNum = 0;
    while (std::getline(file, line)) {
        lineNum++;
        std::cout << lineNum << ": " << line << std::endl;
    }

    file.close();
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "FunctionDef",
      "name": "main",
      "returnType": "int",
      "body": [
        {
          "type": "VarDecl",
          "name": "file",
          "declType": "std::ifstream",
          "init": { "type": "StringLiteral", "value": "input.txt" }
        },
        {
          "type": "IfStmt",
          "condition": {
            "type": "UnaryOp", "op": "!",
            "operand": { "type": "CallExpr", "callee": "file.is_open" }
          },
          "then": [
            {
              "type": "ExprStmt",
              "expr": {
                "type": "BinaryOp", "op": "<<",
                "left": { "type": "NameExpr", "name": "std::cerr" },
                "right": { "type": "StringLiteral", "value": "Failed to open file" }
              }
            },
            { "type": "ReturnStmt", "value": { "type": "IntLiteral", "value": 1 } }
          ]
        },
        { "type": "VarDecl", "name": "line", "declType": "std::string" },
        { "type": "VarDecl", "name": "lineNum", "declType": "int", "init": { "type": "IntLiteral", "value": 0 } },
        {
          "type": "WhileStmt",
          "condition": {
            "type": "CallExpr",
            "callee": "std::getline",
            "args": [
              { "type": "NameExpr", "name": "file" },
              { "type": "NameExpr", "name": "line" }
            ]
          },
          "body": [
            { "type": "ExprStmt", "expr": { "type": "UnaryOp", "op": "++", "operand": { "type": "NameExpr", "name": "lineNum" } } },
            {
              "type": "ExprStmt",
              "expr": {
                "type": "BinaryOp", "op": "<<",
                "left": { "type": "NameExpr", "name": "std::cout" },
                "right": { "type": "NameExpr", "name": "lineNum" }
              }
            }
          ]
        },
        { "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "file.close" } }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["bufio", "fmt", "log", "os"],
  "functions": [
    {
      "type": "Func",
      "name": "main",
      "body": [
        {
          "type": "MultiAssign",
          "names": ["file", "err"],
          "value": { "type": "Call", "func": "os.Open", "args": [{ "type": "Literal", "value": "input.txt" }] }
        },
        {
          "type": "If",
          "condition": { "type": "BinaryOp", "op": "!=", "left": { "type": "Ref", "name": "err" }, "right": { "type": "Nil" } },
          "then": [
            { "type": "Call", "func": "log.Fatal", "args": [{ "type": "Literal", "value": "Failed to open file: " }, { "type": "Ref", "name": "err" }] }
          ]
        },
        {
          "type": "Defer",
          "call": { "type": "Call", "func": "file.Close" }
        },
        {
          "type": "VarDecl",
          "name": "scanner",
          "init": { "type": "Call", "func": "bufio.NewScanner", "args": [{ "type": "Ref", "name": "file" }] }
        },
        {
          "type": "VarDecl", "name": "lineNum", "varType": "int", "init": { "type": "Literal", "value": 0 }
        },
        {
          "type": "ForWhile",
          "condition": { "type": "Call", "func": "scanner.Scan" },
          "body": [
            { "type": "Increment", "name": "lineNum" },
            {
              "type": "Call",
              "func": "fmt.Printf",
              "args": [
                { "type": "Literal", "value": "%d: %s\\n" },
                { "type": "Ref", "name": "lineNum" },
                { "type": "Call", "func": "scanner.Text" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `std::ifstream` + "`" + ` constructor**: Maps to ` + "`" + `os.Open(path)` + "`" + ` which returns ` + "`" + `(*os.File, error)` + "`" + `.
2. **` + "`" + `!file.is_open()` + "`" + ` check**: Becomes ` + "`" + `if err != nil` + "`" + ` after the ` + "`" + `os.Open` + "`" + ` call.
3. **` + "`" + `file.close()` + "`" + `**: Converted to ` + "`" + `defer file.Close()` + "`" + ` placed immediately after the error check. Go's ` + "`" + `defer` + "`" + ` ensures cleanup even on early returns.
4. **` + "`" + `while (std::getline(file, line))` + "`" + `**: Maps to ` + "`" + `for scanner.Scan()` + "`" + ` with ` + "`" + `scanner.Text()` + "`" + ` inside the loop body.
5. **Error on ` + "`" + `cerr` + "`" + ` + return 1**: Collapses into ` + "`" + `log.Fatal` + "`" + ` for main functions, or ` + "`" + `return fmt.Errorf(...)` + "`" + ` for non-main functions.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

func main() {
	file, err := os.Open("input.txt")
	if err != nil {
		log.Fatal("Failed to open file: ", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		fmt.Printf("%d: %s\n", lineNum, scanner.Text())
	}
}
` + "`" + `` + "`" + `` + "`" + `

---

## 2. Writing to a File: ` + "`" + `std::ofstream` + "`" + ` to ` + "`" + `os.Create` + "`" + ` + ` + "`" + `bufio.Writer` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <fstream>
#include <string>
#include <vector>

void writeLines(const std::string& path, const std::vector<std::string>& lines) {
    std::ofstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + path);
    }

    for (const auto& line : lines) {
        file << line << "\n";
    }

    file.flush();
    file.close();
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "FunctionDef",
  "name": "writeLines",
  "params": [
    { "name": "path", "paramType": "const std::string&" },
    { "name": "lines", "paramType": "const std::vector<std::string>&" }
  ],
  "returnType": "void",
  "body": [
    {
      "type": "VarDecl",
      "name": "file",
      "declType": "std::ofstream",
      "init": { "type": "NameExpr", "name": "path" }
    },
    {
      "type": "IfStmt",
      "condition": {
        "type": "UnaryOp", "op": "!",
        "operand": { "type": "CallExpr", "callee": "file.is_open" }
      },
      "then": [
        {
          "type": "ThrowStmt",
          "expr": {
            "type": "ConstructExpr",
            "className": "std::runtime_error",
            "args": [{ "type": "BinaryOp", "op": "+", "left": { "type": "StringLiteral", "value": "Cannot open file: " }, "right": { "type": "NameExpr", "name": "path" } }]
          }
        }
      ]
    },
    {
      "type": "RangeForStmt",
      "varName": "line",
      "varType": "const auto&",
      "iterable": { "type": "NameExpr", "name": "lines" },
      "body": [
        {
          "type": "ExprStmt",
          "expr": {
            "type": "BinaryOp", "op": "<<",
            "left": {
              "type": "BinaryOp", "op": "<<",
              "left": { "type": "NameExpr", "name": "file" },
              "right": { "type": "NameExpr", "name": "line" }
            },
            "right": { "type": "StringLiteral", "value": "\n" }
          }
        }
      ]
    },
    { "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "file.flush" } },
    { "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "file.close" } }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Func",
  "name": "writeLines",
  "params": [
    { "name": "path", "paramType": "string" },
    { "name": "lines", "paramType": "[]string" }
  ],
  "returnType": "error",
  "body": [
    {
      "type": "MultiAssign",
      "names": ["file", "err"],
      "value": { "type": "Call", "func": "os.Create", "args": [{ "type": "Ref", "name": "path" }] }
    },
    {
      "type": "If",
      "condition": { "type": "BinaryOp", "op": "!=", "left": { "type": "Ref", "name": "err" }, "right": { "type": "Nil" } },
      "then": [
        { "type": "Return", "value": { "type": "Call", "func": "fmt.Errorf", "args": [{ "type": "Literal", "value": "cannot open file %s: %w" }, { "type": "Ref", "name": "path" }, { "type": "Ref", "name": "err" }] } }
      ]
    },
    { "type": "Defer", "call": { "type": "Call", "func": "file.Close" } },
    {
      "type": "VarDecl",
      "name": "w",
      "init": { "type": "Call", "func": "bufio.NewWriter", "args": [{ "type": "Ref", "name": "file" }] }
    },
    {
      "type": "RangeFor",
      "index": "_",
      "value": "line",
      "iterable": { "type": "Ref", "name": "lines" },
      "body": [
        { "type": "Call", "func": "fmt.Fprintln", "args": [{ "type": "Ref", "name": "w" }, { "type": "Ref", "name": "line" }] }
      ]
    },
    { "type": "Return", "value": { "type": "Call", "func": "w.Flush" } }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `std::ofstream` + "`" + ` constructor**: Maps to ` + "`" + `os.Create(path)` + "`" + ` for write-only (truncate). For append mode, use ` + "`" + `os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)` + "`" + `.
2. **` + "`" + `throw` + "`" + ` becomes ` + "`" + `return error` + "`" + `**: C++ exceptions translate to Go error returns. The function signature changes from ` + "`" + `void` + "`" + ` to ` + "`" + `error` + "`" + `.
3. **Buffered writes**: When multiple writes occur in a loop, wrap with ` + "`" + `bufio.NewWriter` + "`" + ` for performance. Call ` + "`" + `w.Flush()` + "`" + ` before close.
4. **` + "`" + `file.flush()` + "`" + ` + ` + "`" + `file.close()` + "`" + `**: In Go, ` + "`" + `defer file.Close()` + "`" + ` handles cleanup. Explicit ` + "`" + `w.Flush()` + "`" + ` is returned as the last expression to propagate any write errors.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"bufio"
	"fmt"
	"os"
)

func writeLines(path string, lines []string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot open file %s: %w", path, err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
` + "`" + `` + "`" + `` + "`" + `

---

## 3. Read/Write Mode: ` + "`" + `std::fstream` + "`" + ` to ` + "`" + `os.OpenFile` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <fstream>
#include <iostream>
#include <string>

void appendTimestamp(const std::string& path, const std::string& timestamp) {
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::app);
    if (!file) {
        std::cerr << "Cannot open file" << std::endl;
        return;
    }
    file << timestamp << "\n";
    file.close();
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "FunctionDef",
  "name": "appendTimestamp",
  "params": [
    { "name": "path", "paramType": "const std::string&" },
    { "name": "timestamp", "paramType": "const std::string&" }
  ],
  "returnType": "void",
  "body": [
    {
      "type": "VarDecl",
      "name": "file",
      "declType": "std::fstream",
      "init": {
        "type": "ConstructExpr",
        "args": [
          { "type": "NameExpr", "name": "path" },
          {
            "type": "BinaryOp", "op": "|",
            "left": {
              "type": "BinaryOp", "op": "|",
              "left": { "type": "NameExpr", "name": "std::ios::in" },
              "right": { "type": "NameExpr", "name": "std::ios::out" }
            },
            "right": { "type": "NameExpr", "name": "std::ios::app" }
          }
        ]
      }
    },
    {
      "type": "IfStmt",
      "condition": { "type": "UnaryOp", "op": "!", "operand": { "type": "NameExpr", "name": "file" } },
      "then": [
        { "type": "ExprStmt", "expr": { "type": "BinaryOp", "op": "<<", "left": { "type": "NameExpr", "name": "std::cerr" }, "right": { "type": "StringLiteral", "value": "Cannot open file" } } },
        { "type": "ReturnStmt" }
      ]
    },
    {
      "type": "ExprStmt",
      "expr": {
        "type": "BinaryOp", "op": "<<",
        "left": {
          "type": "BinaryOp", "op": "<<",
          "left": { "type": "NameExpr", "name": "file" },
          "right": { "type": "NameExpr", "name": "timestamp" }
        },
        "right": { "type": "StringLiteral", "value": "\n" }
      }
    },
    { "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "file.close" } }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Func",
  "name": "appendTimestamp",
  "params": [
    { "name": "path", "paramType": "string" },
    { "name": "timestamp", "paramType": "string" }
  ],
  "returnType": "error",
  "body": [
    {
      "type": "MultiAssign",
      "names": ["file", "err"],
      "value": {
        "type": "Call",
        "func": "os.OpenFile",
        "args": [
          { "type": "Ref", "name": "path" },
          { "type": "BinaryOp", "op": "|", "left": { "type": "Ref", "name": "os.O_APPEND" }, "right": { "type": "BinaryOp", "op": "|", "left": { "type": "Ref", "name": "os.O_WRONLY" }, "right": { "type": "Ref", "name": "os.O_CREATE" } } },
          { "type": "Literal", "value": "0644" }
        ]
      }
    },
    {
      "type": "If",
      "condition": { "type": "BinaryOp", "op": "!=", "left": { "type": "Ref", "name": "err" }, "right": { "type": "Nil" } },
      "then": [
        { "type": "Return", "value": { "type": "Call", "func": "fmt.Errorf", "args": [{ "type": "Literal", "value": "cannot open file: %w" }, { "type": "Ref", "name": "err" }] } }
      ]
    },
    { "type": "Defer", "call": { "type": "Call", "func": "file.Close" } },
    {
      "type": "MultiAssign",
      "names": ["_", "err"],
      "value": {
        "type": "Call",
        "func": "fmt.Fprintf",
        "args": [
          { "type": "Ref", "name": "file" },
          { "type": "Literal", "value": "%s\\n" },
          { "type": "Ref", "name": "timestamp" }
        ]
      }
    },
    { "type": "Return", "value": { "type": "Ref", "name": "err" } }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Map ` + "`" + `std::ios` + "`" + ` flags to ` + "`" + `os` + "`" + ` constants**:
   - ` + "`" + `std::ios::in` + "`" + ` maps to ` + "`" + `os.O_RDONLY` + "`" + `
   - ` + "`" + `std::ios::out` + "`" + ` maps to ` + "`" + `os.O_WRONLY` + "`" + `
   - ` + "`" + `std::ios::app` + "`" + ` maps to ` + "`" + `os.O_APPEND` + "`" + `
   - ` + "`" + `std::ios::trunc` + "`" + ` maps to ` + "`" + `os.O_TRUNC` + "`" + `
   - ` + "`" + `std::ios::in | std::ios::out` + "`" + ` maps to ` + "`" + `os.O_RDWR` + "`" + `
2. **` + "`" + `std::fstream` + "`" + ` with combined flags**: Translates to ` + "`" + `os.OpenFile(path, flags, perm)` + "`" + `.
3. **Error pattern**: ` + "`" + `!file` + "`" + ` becomes ` + "`" + `err != nil` + "`" + `. The ` + "`" + `return` + "`" + ` after error becomes ` + "`" + `return err` + "`" + `.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"os"
)

func appendTimestamp(path string, timestamp string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("cannot open file: %w", err)
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, "%s\n", timestamp)
	return err
}
` + "`" + `` + "`" + `` + "`" + `

---

## 4. File Read Loop: ` + "`" + `getline` + "`" + ` Loop to ` + "`" + `bufio.Scanner` + "`" + ` Loop

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

struct Record {
    std::string name;
    int age;
    double score;
};

std::vector<Record> loadCSV(const std::string& path) {
    std::vector<Record> records;
    std::ifstream file(path);
    std::string line;

    // Skip header
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        Record r;
        std::string token;

        std::getline(iss, r.name, ',');
        std::getline(iss, token, ',');
        r.age = std::stoi(token);
        std::getline(iss, token, ',');
        r.score = std::stod(token);

        records.push_back(r);
    }
    return records;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "StructDef",
      "name": "Record",
      "members": [
        { "type": "FieldDecl", "name": "name", "fieldType": "std::string" },
        { "type": "FieldDecl", "name": "age", "fieldType": "int" },
        { "type": "FieldDecl", "name": "score", "fieldType": "double" }
      ]
    },
    {
      "type": "FunctionDef",
      "name": "loadCSV",
      "params": [{ "name": "path", "paramType": "const std::string&" }],
      "returnType": "std::vector<Record>",
      "body": [
        { "type": "VarDecl", "name": "records", "declType": "std::vector<Record>" },
        { "type": "VarDecl", "name": "file", "declType": "std::ifstream", "init": { "type": "NameExpr", "name": "path" } },
        { "type": "VarDecl", "name": "line", "declType": "std::string" },
        {
          "type": "ExprStmt",
          "expr": { "type": "CallExpr", "callee": "std::getline", "args": [{ "type": "NameExpr", "name": "file" }, { "type": "NameExpr", "name": "line" }] }
        },
        {
          "type": "WhileStmt",
          "condition": { "type": "CallExpr", "callee": "std::getline", "args": [{ "type": "NameExpr", "name": "file" }, { "type": "NameExpr", "name": "line" }] },
          "body": [
            { "type": "VarDecl", "name": "iss", "declType": "std::istringstream", "init": { "type": "NameExpr", "name": "line" } },
            { "type": "VarDecl", "name": "r", "declType": "Record" },
            { "type": "VarDecl", "name": "token", "declType": "std::string" },
            {
              "type": "ExprStmt",
              "expr": { "type": "CallExpr", "callee": "std::getline", "args": [{ "type": "NameExpr", "name": "iss" }, { "type": "MemberExpr", "object": "r", "member": "name" }, { "type": "CharLiteral", "value": "," }] }
            },
            {
              "type": "ExprStmt",
              "expr": { "type": "CallExpr", "callee": "std::getline", "args": [{ "type": "NameExpr", "name": "iss" }, { "type": "NameExpr", "name": "token" }, { "type": "CharLiteral", "value": "," }] }
            },
            {
              "type": "ExprStmt",
              "expr": { "type": "AssignExpr", "left": { "type": "MemberExpr", "object": "r", "member": "age" }, "right": { "type": "CallExpr", "callee": "std::stoi", "args": [{ "type": "NameExpr", "name": "token" }] } }
            },
            {
              "type": "ExprStmt",
              "expr": { "type": "CallExpr", "callee": "std::getline", "args": [{ "type": "NameExpr", "name": "iss" }, { "type": "NameExpr", "name": "token" }, { "type": "CharLiteral", "value": "," }] }
            },
            {
              "type": "ExprStmt",
              "expr": { "type": "AssignExpr", "left": { "type": "MemberExpr", "object": "r", "member": "score" }, "right": { "type": "CallExpr", "callee": "std::stod", "args": [{ "type": "NameExpr", "name": "token" }] } }
            },
            {
              "type": "ExprStmt",
              "expr": { "type": "CallExpr", "callee": "records.push_back", "args": [{ "type": "NameExpr", "name": "r" }] }
            }
          ]
        },
        { "type": "ReturnStmt", "value": { "type": "NameExpr", "name": "records" } }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["bufio", "fmt", "os", "strconv", "strings"],
  "types": [
    {
      "type": "Struct",
      "name": "Record",
      "fields": [
        { "name": "Name", "fieldType": "string" },
        { "name": "Age", "fieldType": "int" },
        { "name": "Score", "fieldType": "float64" }
      ]
    }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "loadCSV",
      "params": [{ "name": "path", "paramType": "string" }],
      "returnType": "([]Record, error)",
      "body": [
        {
          "type": "MultiAssign",
          "names": ["file", "err"],
          "value": { "type": "Call", "func": "os.Open", "args": [{ "type": "Ref", "name": "path" }] }
        },
        {
          "type": "If",
          "condition": { "type": "BinaryOp", "op": "!=", "left": { "type": "Ref", "name": "err" }, "right": { "type": "Nil" } },
          "then": [
            { "type": "Return", "values": [{ "type": "Nil" }, { "type": "Ref", "name": "err" }] }
          ]
        },
        { "type": "Defer", "call": { "type": "Call", "func": "file.Close" } },
        { "type": "VarDecl", "name": "scanner", "init": { "type": "Call", "func": "bufio.NewScanner", "args": [{ "type": "Ref", "name": "file" }] } },
        { "type": "Call", "func": "scanner.Scan", "comment": "skip header" },
        { "type": "VarDecl", "name": "records", "varType": "[]Record" },
        {
          "type": "ForWhile",
          "condition": { "type": "Call", "func": "scanner.Scan" },
          "body": [
            { "type": "VarDecl", "name": "fields", "init": { "type": "Call", "func": "strings.Split", "args": [{ "type": "Call", "func": "scanner.Text" }, { "type": "Literal", "value": "," }] } },
            {
              "type": "MultiAssign",
              "names": ["age", "_"],
              "value": { "type": "Call", "func": "strconv.Atoi", "args": [{ "type": "Index", "base": { "type": "Ref", "name": "fields" }, "index": 1 }] }
            },
            {
              "type": "MultiAssign",
              "names": ["score", "_"],
              "value": { "type": "Call", "func": "strconv.ParseFloat", "args": [{ "type": "Index", "base": { "type": "Ref", "name": "fields" }, "index": 2 }, { "type": "Literal", "value": 64 }] }
            },
            {
              "type": "Assign",
              "name": "records",
              "value": {
                "type": "Append",
                "slice": { "type": "Ref", "name": "records" },
                "element": {
                  "type": "StructLiteral",
                  "structType": "Record",
                  "fields": {
                    "Name": { "type": "Index", "base": { "type": "Ref", "name": "fields" }, "index": 0 },
                    "Age": { "type": "Ref", "name": "age" },
                    "Score": { "type": "Ref", "name": "score" }
                  }
                }
              }
            }
          ]
        },
        { "type": "Return", "values": [{ "type": "Ref", "name": "records" }, { "type": "Nil" }] }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **CSV parsing pattern detection**: When ` + "`" + `std::getline` + "`" + ` is used with a delimiter character inside a ` + "`" + `while(getline)` + "`" + ` loop, recognize this as CSV/delimited parsing. Map to ` + "`" + `strings.Split` + "`" + ` for simple cases, or ` + "`" + `encoding/csv` + "`" + ` for RFC 4180 compliant parsing.
2. **` + "`" + `std::istringstream` + "`" + ` with delimiter ` + "`" + `getline` + "`" + `**: Maps to ` + "`" + `strings.Split(line, ",")` + "`" + ` with index access.
3. **` + "`" + `std::stoi` + "`" + ` / ` + "`" + `std::stod` + "`" + `**: Map to ` + "`" + `strconv.Atoi` + "`" + ` and ` + "`" + `strconv.ParseFloat(..., 64)` + "`" + `.
4. **` + "`" + `push_back` + "`" + `**: Maps to ` + "`" + `append(slice, element)` + "`" + `.
5. **Skip header**: The standalone ` + "`" + `std::getline` + "`" + ` before the loop becomes ` + "`" + `scanner.Scan()` + "`" + ` with a comment.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type Record struct {
	Name  string
	Age   int
	Score float64
}

func loadCSV(path string) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header

	var records []Record
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ",")
		age, _ := strconv.Atoi(fields[1])
		score, _ := strconv.ParseFloat(fields[2], 64)

		records = append(records, Record{
			Name:  fields[0],
			Age:   age,
			Score: score,
		})
	}
	return records, nil
}
` + "`" + `` + "`" + `` + "`" + `

---

## 5. Binary I/O: ` + "`" + `read()` + "`" + ` / ` + "`" + `write()` + "`" + ` to ` + "`" + `encoding/binary` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <fstream>
#include <cstdint>
#include <vector>

struct Header {
    uint32_t magic;
    uint16_t version;
    uint32_t count;
};

struct Entry {
    int32_t id;
    float value;
};

std::vector<Entry> readBinaryFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);

    Header hdr;
    file.read(reinterpret_cast<char*>(&hdr), sizeof(Header));

    std::vector<Entry> entries(hdr.count);
    file.read(reinterpret_cast<char*>(entries.data()), hdr.count * sizeof(Entry));

    file.close();
    return entries;
}

void writeBinaryFile(const std::string& path, const Header& hdr, const std::vector<Entry>& entries) {
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(&hdr), sizeof(Header));
    file.write(reinterpret_cast<const char*>(entries.data()), entries.size() * sizeof(Entry));
    file.close();
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "StructDef",
      "name": "Header",
      "members": [
        { "type": "FieldDecl", "name": "magic", "fieldType": "uint32_t" },
        { "type": "FieldDecl", "name": "version", "fieldType": "uint16_t" },
        { "type": "FieldDecl", "name": "count", "fieldType": "uint32_t" }
      ]
    },
    {
      "type": "StructDef",
      "name": "Entry",
      "members": [
        { "type": "FieldDecl", "name": "id", "fieldType": "int32_t" },
        { "type": "FieldDecl", "name": "value", "fieldType": "float" }
      ]
    },
    {
      "type": "FunctionDef",
      "name": "readBinaryFile",
      "params": [{ "name": "path", "paramType": "const std::string&" }],
      "returnType": "std::vector<Entry>",
      "body": [
        { "type": "VarDecl", "name": "file", "declType": "std::ifstream", "init": { "type": "ConstructExpr", "args": [{ "type": "NameExpr", "name": "path" }, { "type": "NameExpr", "name": "std::ios::binary" }] } },
        { "type": "VarDecl", "name": "hdr", "declType": "Header" },
        { "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "file.read", "args": [{ "type": "CastExpr", "castType": "char*", "operand": { "type": "UnaryOp", "op": "&", "operand": { "type": "NameExpr", "name": "hdr" } } }, { "type": "SizeofExpr", "operand": "Header" }] } },
        { "type": "VarDecl", "name": "entries", "declType": "std::vector<Entry>", "init": { "type": "ConstructExpr", "args": [{ "type": "MemberExpr", "object": "hdr", "member": "count" }] } },
        { "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "file.read", "args": [{ "type": "CastExpr", "castType": "char*", "operand": { "type": "CallExpr", "callee": "entries.data" } }, { "type": "BinaryOp", "op": "*", "left": { "type": "MemberExpr", "object": "hdr", "member": "count" }, "right": { "type": "SizeofExpr", "operand": "Entry" } }] } },
        { "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "file.close" } },
        { "type": "ReturnStmt", "value": { "type": "NameExpr", "name": "entries" } }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["encoding/binary", "fmt", "os"],
  "types": [
    {
      "type": "Struct",
      "name": "Header",
      "fields": [
        { "name": "Magic", "fieldType": "uint32" },
        { "name": "Version", "fieldType": "uint16" },
        { "name": "Count", "fieldType": "uint32" }
      ]
    },
    {
      "type": "Struct",
      "name": "Entry",
      "fields": [
        { "name": "ID", "fieldType": "int32" },
        { "name": "Value", "fieldType": "float32" }
      ]
    }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "readBinaryFile",
      "params": [{ "name": "path", "paramType": "string" }],
      "returnType": "([]Entry, error)",
      "body": [
        { "type": "MultiAssign", "names": ["file", "err"], "value": { "type": "Call", "func": "os.Open", "args": [{ "type": "Ref", "name": "path" }] } },
        { "type": "If", "condition": { "type": "BinaryOp", "op": "!=", "left": { "type": "Ref", "name": "err" }, "right": { "type": "Nil" } }, "then": [{ "type": "Return", "values": [{ "type": "Nil" }, { "type": "Ref", "name": "err" }] }] },
        { "type": "Defer", "call": { "type": "Call", "func": "file.Close" } },
        { "type": "VarDecl", "name": "hdr", "varType": "Header" },
        { "type": "Call", "func": "binary.Read", "args": [{ "type": "Ref", "name": "file" }, { "type": "Ref", "name": "binary.LittleEndian" }, { "type": "AddressOf", "operand": { "type": "Ref", "name": "hdr" } }] },
        { "type": "VarDecl", "name": "entries", "init": { "type": "Make", "makeType": "[]Entry", "length": { "type": "FieldAccess", "object": "hdr", "field": "Count" } } },
        { "type": "Call", "func": "binary.Read", "args": [{ "type": "Ref", "name": "file" }, { "type": "Ref", "name": "binary.LittleEndian" }, { "type": "Ref", "name": "entries" }] },
        { "type": "Return", "values": [{ "type": "Ref", "name": "entries" }, { "type": "Nil" }] }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `std::ios::binary` + "`" + ` flag**: In Go, files are always binary. There is no text/binary mode distinction. The flag is dropped.
2. **` + "`" + `file.read(reinterpret_cast<char*>(&var), sizeof(T))` + "`" + `**: Maps to ` + "`" + `binary.Read(reader, byteOrder, &var)` + "`" + `. The ` + "`" + `encoding/binary` + "`" + ` package handles struct layout.
3. **` + "`" + `sizeof(T)` + "`" + `**: Not needed in Go; ` + "`" + `binary.Read` + "`" + ` and ` + "`" + `binary.Write` + "`" + ` calculate size from the struct fields automatically.
4. **Byte order**: C++ typically uses platform-native byte order. The adapter defaults to ` + "`" + `binary.LittleEndian` + "`" + ` on x86-like platforms. This may need manual review.
5. **` + "`" + `reinterpret_cast` + "`" + `**: Eliminated entirely; Go's ` + "`" + `encoding/binary` + "`" + ` provides safe serialization.
6. **Bulk read into vector**: ` + "`" + `std::vector<Entry>(count)` + "`" + ` + ` + "`" + `file.read(data, count*sizeof)` + "`" + ` becomes ` + "`" + `make([]Entry, count)` + "`" + ` + ` + "`" + `binary.Read(file, order, entries)` + "`" + `.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"encoding/binary"
	"os"
)

type Header struct {
	Magic   uint32
	Version uint16
	Count   uint32
}

type Entry struct {
	ID    int32
	Value float32
}

func readBinaryFile(path string) ([]Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hdr Header
	if err := binary.Read(file, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}

	entries := make([]Entry, hdr.Count)
	if err := binary.Read(file, binary.LittleEndian, entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func writeBinaryFile(path string, hdr Header, entries []Entry) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := binary.Write(file, binary.LittleEndian, &hdr); err != nil {
		return err
	}
	return binary.Write(file, binary.LittleEndian, entries)
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Equivalent | Package | Notes |
|---|---|---|---|
| ` + "`" + `std::ifstream file(path)` + "`" + ` | ` + "`" + `file, err := os.Open(path)` + "`" + ` | ` + "`" + `os` + "`" + ` | Read-only open |
| ` + "`" + `std::ofstream file(path)` + "`" + ` | ` + "`" + `file, err := os.Create(path)` + "`" + ` | ` + "`" + `os` + "`" + ` | Write-only, truncate |
| ` + "`" + `std::fstream file(path, flags)` + "`" + ` | ` + "`" + `file, err := os.OpenFile(path, flags, perm)` + "`" + ` | ` + "`" + `os` + "`" + ` | Custom flags |
| ` + "`" + `std::ios::app` + "`" + ` | ` + "`" + `os.O_APPEND` + "`" + ` | ` + "`" + `os` + "`" + ` | Append mode |
| ` + "`" + `std::ios::binary` + "`" + ` | (default in Go) | -- | No binary/text distinction |
| ` + "`" + `!file.is_open()` + "`" + ` / ` + "`" + `!file` + "`" + ` | ` + "`" + `if err != nil` + "`" + ` | -- | Error check after open |
| ` + "`" + `file.close()` + "`" + ` | ` + "`" + `defer file.Close()` + "`" + ` | -- | Deferred cleanup |
| ` + "`" + `while (getline(file, line))` + "`" + ` | ` + "`" + `for scanner.Scan()` + "`" + ` | ` + "`" + `bufio` + "`" + ` | Line-by-line reading |
| ` + "`" + `getline(stream, tok, ',')` + "`" + ` | ` + "`" + `strings.Split(line, ",")` + "`" + ` | ` + "`" + `strings` + "`" + ` | Delimited parsing |
| ` + "`" + `file << data` + "`" + ` | ` + "`" + `fmt.Fprintln(w, data)` + "`" + ` | ` + "`" + `fmt` + "`" + `, ` + "`" + `bufio` + "`" + ` | Buffered writes |
| ` + "`" + `file.flush()` + "`" + ` | ` + "`" + `w.Flush()` + "`" + ` | ` + "`" + `bufio` + "`" + ` | Flush buffered writer |
| ` + "`" + `file.read(&var, sizeof)` + "`" + ` | ` + "`" + `binary.Read(f, order, &var)` + "`" + ` | ` + "`" + `encoding/binary` + "`" + ` | Binary deserialization |
| ` + "`" + `file.write(&var, sizeof)` + "`" + ` | ` + "`" + `binary.Write(f, order, &var)` + "`" + ` | ` + "`" + `encoding/binary` + "`" + ` | Binary serialization |
| ` + "`" + `reinterpret_cast<char*>` + "`" + ` | (eliminated) | -- | ` + "`" + `encoding/binary` + "`" + ` handles casting |
| ` + "`" + `std::stoi(s)` + "`" + ` | ` + "`" + `strconv.Atoi(s)` + "`" + ` | ` + "`" + `strconv` + "`" + ` | String to int |
| ` + "`" + `std::stod(s)` + "`" + ` | ` + "`" + `strconv.ParseFloat(s, 64)` + "`" + ` | ` + "`" + `strconv` + "`" + ` | String to float64 |
| ` + "`" + `push_back(elem)` + "`" + ` | ` + "`" + `append(slice, elem)` + "`" + ` | builtin | Grow slice |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/io/streams_fmt.md",
			Body: `# I/O Streams to fmt / strings / bufio

> C++ iostream and stringstream patterns mapped to Go's ` + "`" + `fmt` + "`" + `, ` + "`" + `strings` + "`" + `, ` + "`" + `bufio` + "`" + `, and ` + "`" + `os` + "`" + ` packages.

---

## 1. Standard Output: ` + "`" + `std::cout` + "`" + ` to ` + "`" + `fmt.Println` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>

int main() {
    int x = 42;
    std::string name = "Alice";
    std::cout << "Hello, " << name << "! Value: " << x << std::endl;
    std::cout << "No newline" << std::flush;
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "FunctionDef",
      "name": "main",
      "returnType": "int",
      "body": [
        {
          "type": "VarDecl",
          "name": "x",
          "declType": "int",
          "init": { "type": "IntLiteral", "value": 42 }
        },
        {
          "type": "VarDecl",
          "name": "name",
          "declType": "std::string",
          "init": { "type": "StringLiteral", "value": "Alice" }
        },
        {
          "type": "ExprStmt",
          "expr": {
            "type": "BinaryOp",
            "op": "<<",
            "left": {
              "type": "BinaryOp",
              "op": "<<",
              "left": {
                "type": "BinaryOp",
                "op": "<<",
                "left": {
                  "type": "BinaryOp",
                  "op": "<<",
                  "left": { "type": "NameExpr", "name": "std::cout" },
                  "right": { "type": "StringLiteral", "value": "Hello, " }
                },
                "right": { "type": "NameExpr", "name": "name" }
              },
              "right": { "type": "StringLiteral", "value": "! Value: " }
            },
            "right": { "type": "NameExpr", "name": "x" }
          }
        },
        {
          "type": "ExprStmt",
          "expr": {
            "type": "BinaryOp",
            "op": "<<",
            "left": {
              "type": "BinaryOp",
              "op": "<<",
              "left": { "type": "NameExpr", "name": "std::cout" },
              "right": { "type": "StringLiteral", "value": "No newline" }
            },
            "right": { "type": "NameExpr", "name": "std::flush" }
          }
        },
        {
          "type": "ReturnStmt",
          "value": { "type": "IntLiteral", "value": 0 }
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "functions": [
    {
      "type": "Func",
      "name": "main",
      "returnType": "void",
      "body": [
        {
          "type": "VarDecl",
          "name": "x",
          "varType": "int",
          "init": { "type": "Literal", "value": 42 }
        },
        {
          "type": "VarDecl",
          "name": "name",
          "varType": "string",
          "init": { "type": "Literal", "value": "Alice" }
        },
        {
          "type": "Call",
          "func": "fmt.Printf",
          "args": [
            { "type": "Literal", "value": "Hello, %s! Value: %d\\n" },
            { "type": "Ref", "name": "name" },
            { "type": "Ref", "name": "x" }
          ]
        },
        {
          "type": "Call",
          "func": "fmt.Print",
          "args": [
            { "type": "Literal", "value": "No newline" }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Flatten ` + "`" + `<<` + "`" + ` chains**: The AST contains nested left-associative ` + "`" + `BinaryOp(<<)` + "`" + ` nodes. The adapter walks the chain, collects all operands, and identifies the stream target (` + "`" + `std::cout` + "`" + `, ` + "`" + `std::cerr` + "`" + `).
2. **Detect endl / flush**: ` + "`" + `std::endl` + "`" + ` becomes a ` + "`" + `\n` + "`" + ` suffix; ` + "`" + `std::flush` + "`" + ` is dropped (Go flushes on newline by default for ` + "`" + `fmt` + "`" + `).
3. **Choose fmt function**: If the chain ends with ` + "`" + `std::endl` + "`" + ` and has a single value, use ` + "`" + `fmt.Println` + "`" + `. For mixed types with a format, use ` + "`" + `fmt.Printf` + "`" + `. For no trailing newline, use ` + "`" + `fmt.Print` + "`" + `.
4. **Type-infer format verbs**: ` + "`" + `int` + "`" + ` maps to ` + "`" + `%d` + "`" + `, ` + "`" + `string` + "`" + ` maps to ` + "`" + `%s` + "`" + `, ` + "`" + `float` + "`" + `/` + "`" + `double` + "`" + ` maps to ` + "`" + `%f` + "`" + `.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

func main() {
	x := 42
	name := "Alice"
	fmt.Printf("Hello, %s! Value: %d\n", name, x)
	fmt.Print("No newline")
}
` + "`" + `` + "`" + `` + "`" + `

---

## 2. Standard Error: ` + "`" + `std::cerr` + "`" + ` to ` + "`" + `fmt.Fprintln(os.Stderr, ...)` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>

void reportError(const std::string& msg) {
    std::cerr << "Error: " << msg << std::endl;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "FunctionDef",
  "name": "reportError",
  "params": [
    {
      "name": "msg",
      "paramType": "const std::string&"
    }
  ],
  "returnType": "void",
  "body": [
    {
      "type": "ExprStmt",
      "expr": {
        "type": "BinaryOp",
        "op": "<<",
        "left": {
          "type": "BinaryOp",
          "op": "<<",
          "left": {
            "type": "BinaryOp",
            "op": "<<",
            "left": { "type": "NameExpr", "name": "std::cerr" },
            "right": { "type": "StringLiteral", "value": "Error: " }
          },
          "right": { "type": "NameExpr", "name": "msg" }
        },
        "right": { "type": "NameExpr", "name": "std::endl" }
      }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Func",
  "name": "reportError",
  "params": [
    { "name": "msg", "paramType": "string" }
  ],
  "returnType": "void",
  "body": [
    {
      "type": "Call",
      "func": "fmt.Fprintf",
      "args": [
        { "type": "Ref", "name": "os.Stderr" },
        { "type": "Literal", "value": "Error: %s\\n" },
        { "type": "Ref", "name": "msg" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Identify stream target**: ` + "`" + `std::cerr` + "`" + ` maps to ` + "`" + `os.Stderr` + "`" + `.
2. **Use ` + "`" + `fmt.Fprintln` + "`" + ` or ` + "`" + `fmt.Fprintf` + "`" + `**: When a single string concatenation is detected, prefer ` + "`" + `fmt.Fprintln(os.Stderr, ...)` + "`" + `. When format verbs are needed, use ` + "`" + `fmt.Fprintf` + "`" + `.
3. **Drop const ref**: ` + "`" + `const std::string&` + "`" + ` becomes plain ` + "`" + `string` + "`" + ` (Go strings are immutable and passed by value with pointer-backed storage).

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"os"
)

func reportError(msg string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
}
` + "`" + `` + "`" + `` + "`" + `

---

## 3. Standard Input: ` + "`" + `std::cin` + "`" + ` to ` + "`" + `fmt.Scan` + "`" + ` / ` + "`" + `bufio.Scanner` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <string>

int main() {
    int age;
    std::string name;

    std::cout << "Enter name: ";
    std::getline(std::cin, name);

    std::cout << "Enter age: ";
    std::cin >> age;

    std::cout << "Hello " << name << ", age " << age << std::endl;
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "FunctionDef",
  "name": "main",
  "returnType": "int",
  "body": [
    { "type": "VarDecl", "name": "age", "declType": "int" },
    { "type": "VarDecl", "name": "name", "declType": "std::string" },
    {
      "type": "ExprStmt",
      "expr": {
        "type": "BinaryOp", "op": "<<",
        "left": { "type": "NameExpr", "name": "std::cout" },
        "right": { "type": "StringLiteral", "value": "Enter name: " }
      }
    },
    {
      "type": "ExprStmt",
      "expr": {
        "type": "CallExpr",
        "callee": "std::getline",
        "args": [
          { "type": "NameExpr", "name": "std::cin" },
          { "type": "NameExpr", "name": "name" }
        ]
      }
    },
    {
      "type": "ExprStmt",
      "expr": {
        "type": "BinaryOp", "op": "<<",
        "left": { "type": "NameExpr", "name": "std::cout" },
        "right": { "type": "StringLiteral", "value": "Enter age: " }
      }
    },
    {
      "type": "ExprStmt",
      "expr": {
        "type": "BinaryOp", "op": ">>",
        "left": { "type": "NameExpr", "name": "std::cin" },
        "right": { "type": "NameExpr", "name": "age" }
      }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["bufio", "fmt", "os"],
  "functions": [
    {
      "type": "Func",
      "name": "main",
      "body": [
        {
          "type": "VarDecl",
          "name": "scanner",
          "varType": "*bufio.Scanner",
          "init": { "type": "Call", "func": "bufio.NewScanner", "args": [{ "type": "Ref", "name": "os.Stdin" }] }
        },
        { "type": "Call", "func": "fmt.Print", "args": [{ "type": "Literal", "value": "Enter name: " }] },
        { "type": "Call", "func": "scanner.Scan" },
        { "type": "VarDecl", "name": "name", "varType": "string", "init": { "type": "Call", "func": "scanner.Text" } },
        { "type": "Call", "func": "fmt.Print", "args": [{ "type": "Literal", "value": "Enter age: " }] },
        {
          "type": "VarDecl",
          "name": "age",
          "varType": "int"
        },
        {
          "type": "Call",
          "func": "fmt.Scan",
          "args": [{ "type": "AddressOf", "operand": { "type": "Ref", "name": "age" } }]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `std::getline` + "`" + ` maps to ` + "`" + `bufio.Scanner` + "`" + `**: Line-oriented input uses ` + "`" + `bufio.NewScanner(os.Stdin)` + "`" + ` with ` + "`" + `scanner.Scan()` + "`" + ` and ` + "`" + `scanner.Text()` + "`" + `.
2. **` + "`" + `std::cin >> var` + "`" + ` maps to ` + "`" + `fmt.Scan(&var)` + "`" + `**: Token-based input uses ` + "`" + `fmt.Scan` + "`" + ` with a pointer argument.
3. **Mixed input**: When both ` + "`" + `getline` + "`" + ` and ` + "`" + `>>` + "`" + ` are used, introduce a scanner for line reads and ` + "`" + `fmt.Scan` + "`" + ` for typed reads. Note that mixing these in Go requires care (same as in C++).

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Enter name: ")
	scanner.Scan()
	name := scanner.Text()

	var age int
	fmt.Print("Enter age: ")
	fmt.Scan(&age)

	fmt.Printf("Hello %s, age %d\n", name, age)
}
` + "`" + `` + "`" + `` + "`" + `

---

## 4. String Streams: ` + "`" + `std::stringstream` + "`" + ` to ` + "`" + `strings.Builder` + "`" + ` / ` + "`" + `fmt.Sprintf` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <sstream>
#include <string>
#include <vector>

std::string joinWithComma(const std::vector<std::string>& items) {
    std::ostringstream oss;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << items[i];
    }
    return oss.str();
}

int parseAge(const std::string& input) {
    std::istringstream iss(input);
    int age;
    iss >> age;
    return age;
}

std::string formatRecord(const std::string& name, int id) {
    std::stringstream ss;
    ss << "ID=" << id << " Name=" << name;
    return ss.str();
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "FunctionDef",
      "name": "joinWithComma",
      "params": [{ "name": "items", "paramType": "const std::vector<std::string>&" }],
      "returnType": "std::string",
      "body": [
        {
          "type": "VarDecl",
          "name": "oss",
          "declType": "std::ostringstream"
        },
        {
          "type": "ForStmt",
          "init": { "type": "VarDecl", "name": "i", "declType": "size_t", "init": { "type": "IntLiteral", "value": 0 } },
          "condition": { "type": "BinaryOp", "op": "<", "left": { "type": "NameExpr", "name": "i" }, "right": { "type": "CallExpr", "callee": "items.size" } },
          "increment": { "type": "UnaryOp", "op": "++", "operand": { "type": "NameExpr", "name": "i" } },
          "body": [
            {
              "type": "IfStmt",
              "condition": { "type": "BinaryOp", "op": ">", "left": { "type": "NameExpr", "name": "i" }, "right": { "type": "IntLiteral", "value": 0 } },
              "then": [
                { "type": "ExprStmt", "expr": { "type": "BinaryOp", "op": "<<", "left": { "type": "NameExpr", "name": "oss" }, "right": { "type": "StringLiteral", "value": ", " } } }
              ]
            },
            { "type": "ExprStmt", "expr": { "type": "BinaryOp", "op": "<<", "left": { "type": "NameExpr", "name": "oss" }, "right": { "type": "IndexExpr", "base": { "type": "NameExpr", "name": "items" }, "index": { "type": "NameExpr", "name": "i" } } } }
          ]
        },
        { "type": "ReturnStmt", "value": { "type": "CallExpr", "callee": "oss.str" } }
      ]
    },
    {
      "type": "FunctionDef",
      "name": "parseAge",
      "params": [{ "name": "input", "paramType": "const std::string&" }],
      "returnType": "int",
      "body": [
        { "type": "VarDecl", "name": "iss", "declType": "std::istringstream", "init": { "type": "NameExpr", "name": "input" } },
        { "type": "VarDecl", "name": "age", "declType": "int" },
        { "type": "ExprStmt", "expr": { "type": "BinaryOp", "op": ">>", "left": { "type": "NameExpr", "name": "iss" }, "right": { "type": "NameExpr", "name": "age" } } },
        { "type": "ReturnStmt", "value": { "type": "NameExpr", "name": "age" } }
      ]
    },
    {
      "type": "FunctionDef",
      "name": "formatRecord",
      "params": [
        { "name": "name", "paramType": "const std::string&" },
        { "name": "id", "paramType": "int" }
      ],
      "returnType": "std::string",
      "body": [
        { "type": "VarDecl", "name": "ss", "declType": "std::stringstream" },
        { "type": "ExprStmt", "expr": { "type": "BinaryOp", "op": "<<", "left": { "type": "BinaryOp", "op": "<<", "left": { "type": "BinaryOp", "op": "<<", "left": { "type": "BinaryOp", "op": "<<", "left": { "type": "NameExpr", "name": "ss" }, "right": { "type": "StringLiteral", "value": "ID=" } }, "right": { "type": "NameExpr", "name": "id" } }, "right": { "type": "StringLiteral", "value": " Name=" } }, "right": { "type": "NameExpr", "name": "name" } } },
        { "type": "ReturnStmt", "value": { "type": "CallExpr", "callee": "ss.str" } }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["fmt", "strconv", "strings"],
  "functions": [
    {
      "type": "Func",
      "name": "joinWithComma",
      "params": [{ "name": "items", "paramType": "[]string" }],
      "returnType": "string",
      "body": [
        {
          "type": "VarDecl",
          "name": "b",
          "varType": "strings.Builder"
        },
        {
          "type": "RangeFor",
          "index": "i",
          "value": "item",
          "iterable": { "type": "Ref", "name": "items" },
          "body": [
            {
              "type": "If",
              "condition": { "type": "BinaryOp", "op": ">", "left": { "type": "Ref", "name": "i" }, "right": { "type": "Literal", "value": 0 } },
              "then": [
                { "type": "Call", "func": "b.WriteString", "args": [{ "type": "Literal", "value": ", " }] }
              ]
            },
            { "type": "Call", "func": "b.WriteString", "args": [{ "type": "Ref", "name": "item" }] }
          ]
        },
        { "type": "Return", "value": { "type": "Call", "func": "b.String" } }
      ]
    },
    {
      "type": "Func",
      "name": "parseAge",
      "params": [{ "name": "input", "paramType": "string" }],
      "returnType": "int",
      "body": [
        {
          "type": "MultiAssign",
          "names": ["age", "_"],
          "value": { "type": "Call", "func": "strconv.Atoi", "args": [{ "type": "Ref", "name": "input" }] }
        },
        { "type": "Return", "value": { "type": "Ref", "name": "age" } }
      ]
    },
    {
      "type": "Func",
      "name": "formatRecord",
      "params": [
        { "name": "name", "paramType": "string" },
        { "name": "id", "paramType": "int" }
      ],
      "returnType": "string",
      "body": [
        {
          "type": "Return",
          "value": {
            "type": "Call",
            "func": "fmt.Sprintf",
            "args": [
              { "type": "Literal", "value": "ID=%d Name=%s" },
              { "type": "Ref", "name": "id" },
              { "type": "Ref", "name": "name" }
            ]
          }
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `std::ostringstream` + "`" + ` used for accumulation**: When the pattern is "write many, read once via ` + "`" + `.str()` + "`" + `", map to ` + "`" + `strings.Builder` + "`" + `. The ` + "`" + `<<` + "`" + ` calls become ` + "`" + `WriteString` + "`" + ` / ` + "`" + `fmt.Fprintf(&b, ...)` + "`" + `.
2. **` + "`" + `std::istringstream` + "`" + ` used for parsing**: Map to ` + "`" + `strconv` + "`" + ` functions (` + "`" + `Atoi` + "`" + `, ` + "`" + `ParseFloat` + "`" + `, etc.) when extracting typed values. For complex parsing, use ` + "`" + `fmt.Sscanf` + "`" + ` or ` + "`" + `strings.NewReader` + "`" + ` + ` + "`" + `fmt.Fscan` + "`" + `.
3. **` + "`" + `std::stringstream` + "`" + ` used for formatting**: When the pattern is a single format expression, collapse to ` + "`" + `fmt.Sprintf` + "`" + `.
4. **` + "`" + `strings.Join` + "`" + ` optimization**: When the loop pattern is "join with separator", the adapter may recognize this idiom and emit ` + "`" + `strings.Join(items, ", ")` + "`" + ` instead of the manual loop.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"strconv"
	"strings"
)

func joinWithComma(items []string) string {
	var b strings.Builder
	for i, item := range items {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(item)
	}
	return b.String()
}

func parseAge(input string) int {
	age, _ := strconv.Atoi(input)
	return age
}

func formatRecord(name string, id int) string {
	return fmt.Sprintf("ID=%d Name=%s", id, name)
}
` + "`" + `` + "`" + `` + "`" + `

---

## 5. Operator<< Overloading to ` + "`" + `String()` + "`" + ` Method (Stringer Interface)

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <sstream>
#include <string>

class Point {
public:
    int x, y;
    Point(int x, int y) : x(x), y(y) {}

    friend std::ostream& operator<<(std::ostream& os, const Point& p) {
        os << "(" << p.x << ", " << p.y << ")";
        return os;
    }
};

int main() {
    Point p(3, 7);
    std::cout << "Point: " << p << std::endl;
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "ClassDef",
      "name": "Point",
      "access": "public",
      "members": [
        { "type": "FieldDecl", "name": "x", "fieldType": "int" },
        { "type": "FieldDecl", "name": "y", "fieldType": "int" },
        {
          "type": "Constructor",
          "params": [
            { "name": "x", "paramType": "int" },
            { "name": "y", "paramType": "int" }
          ],
          "initList": [
            { "member": "x", "value": { "type": "NameExpr", "name": "x" } },
            { "member": "y", "value": { "type": "NameExpr", "name": "y" } }
          ]
        },
        {
          "type": "FriendFunctionDef",
          "name": "operator<<",
          "params": [
            { "name": "os", "paramType": "std::ostream&" },
            { "name": "p", "paramType": "const Point&" }
          ],
          "returnType": "std::ostream&",
          "body": [
            {
              "type": "ExprStmt",
              "expr": {
                "type": "BinaryOp", "op": "<<",
                "left": { "type": "NameExpr", "name": "os" },
                "right": { "type": "StringLiteral", "value": "(" }
              }
            },
            { "type": "ReturnStmt", "value": { "type": "NameExpr", "name": "os" } }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["fmt"],
  "types": [
    {
      "type": "Struct",
      "name": "Point",
      "fields": [
        { "name": "X", "fieldType": "int" },
        { "name": "Y", "fieldType": "int" }
      ]
    }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "NewPoint",
      "params": [
        { "name": "x", "paramType": "int" },
        { "name": "y", "paramType": "int" }
      ],
      "returnType": "Point",
      "body": [
        { "type": "Return", "value": { "type": "StructLiteral", "structType": "Point", "fields": { "X": { "type": "Ref", "name": "x" }, "Y": { "type": "Ref", "name": "y" } } } }
      ]
    },
    {
      "type": "Method",
      "receiver": { "name": "p", "receiverType": "Point" },
      "name": "String",
      "returnType": "string",
      "body": [
        {
          "type": "Return",
          "value": {
            "type": "Call",
            "func": "fmt.Sprintf",
            "args": [
              { "type": "Literal", "value": "(%d, %d)" },
              { "type": "FieldAccess", "object": "p", "field": "X" },
              { "type": "FieldAccess", "object": "p", "field": "Y" }
            ]
          }
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Detect ` + "`" + `operator<<` + "`" + ` overload**: When the AST contains a friend function ` + "`" + `operator<<` + "`" + ` taking ` + "`" + `std::ostream&` + "`" + ` and a class reference, generate a ` + "`" + `String() string` + "`" + ` method on the struct.
2. **Flatten the stream writes**: Collect all ` + "`" + `<<` + "`" + ` operands inside the function body and build a ` + "`" + `fmt.Sprintf` + "`" + ` format string.
3. **Stringer interface**: The generated ` + "`" + `String()` + "`" + ` method satisfies ` + "`" + `fmt.Stringer` + "`" + `, so ` + "`" + `fmt.Println(p)` + "`" + ` will automatically call it.
4. **Constructor to factory**: The C++ constructor becomes a ` + "`" + `NewPoint` + "`" + ` factory function.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

type Point struct {
	X int
	Y int
}

func NewPoint(x, y int) Point {
	return Point{X: x, Y: y}
}

func (p Point) String() string {
	return fmt.Sprintf("(%d, %d)", p.X, p.Y)
}

func main() {
	p := NewPoint(3, 7)
	fmt.Println("Point:", p)
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Equivalent | Package | Notes |
|---|---|---|---|
| ` + "`" + `std::cout << x << std::endl` + "`" + ` | ` + "`" + `fmt.Println(x)` + "`" + ` | ` + "`" + `fmt` + "`" + ` | Single value with newline |
| ` + "`" + `std::cout << a << b << c` + "`" + ` | ` + "`" + `fmt.Printf(format, a, b, c)` + "`" + ` | ` + "`" + `fmt` + "`" + ` | Multiple values, infer format verbs |
| ` + "`" + `std::cerr << msg` + "`" + ` | ` + "`" + `fmt.Fprintln(os.Stderr, msg)` + "`" + ` | ` + "`" + `fmt` + "`" + `, ` + "`" + `os` + "`" + ` | Write to stderr |
| ` + "`" + `std::cin >> x` + "`" + ` | ` + "`" + `fmt.Scan(&x)` + "`" + ` | ` + "`" + `fmt` + "`" + ` | Token-based input, pass pointer |
| ` + "`" + `std::getline(std::cin, line)` + "`" + ` | ` + "`" + `scanner.Scan(); line = scanner.Text()` + "`" + ` | ` + "`" + `bufio` + "`" + ` | Line-based input |
| ` + "`" + `std::ostringstream` + "`" + ` + ` + "`" + `<<` + "`" + ` + ` + "`" + `.str()` + "`" + ` | ` + "`" + `strings.Builder` + "`" + ` + ` + "`" + `WriteString` + "`" + ` + ` + "`" + `.String()` + "`" + ` | ` + "`" + `strings` + "`" + ` | Accumulate output |
| ` + "`" + `std::istringstream` + "`" + ` + ` + "`" + `>>` + "`" + ` | ` + "`" + `strconv.Atoi` + "`" + ` / ` + "`" + `fmt.Sscanf` + "`" + ` | ` + "`" + `strconv` + "`" + `, ` + "`" + `fmt` + "`" + ` | Parse typed values from string |
| ` + "`" + `std::stringstream` + "`" + ` for format | ` + "`" + `fmt.Sprintf(format, args...)` + "`" + ` | ` + "`" + `fmt` + "`" + ` | Single-shot formatting |
| ` + "`" + `operator<<` + "`" + ` overload (friend) | ` + "`" + `String() string` + "`" + ` method | ` + "`" + `fmt` + "`" + ` | Satisfies ` + "`" + `fmt.Stringer` + "`" + ` |
| ` + "`" + `std::endl` + "`" + ` | ` + "`" + `\n` + "`" + ` in format string | -- | Go ` + "`" + `Println` + "`" + ` adds newline automatically |
| ` + "`" + `std::flush` + "`" + ` | (usually unnecessary) | -- | Go flushes on newlines for stdout |
| ` + "`" + `std::setprecision(n)` + "`" + ` | ` + "`" + `fmt.Sprintf("%.nf", v)` + "`" + ` | ` + "`" + `fmt` + "`" + ` | Precision in format verb |
| ` + "`" + `std::setw(n)` + "`" + ` | ` + "`" + `fmt.Sprintf("%nd", v)` + "`" + ` | ` + "`" + `fmt` + "`" + ` | Width in format verb |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/memory/new_delete.md",
			Body: `# new/delete to Go Allocation

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
class Buffer {
public:
    Buffer(size_t size) : data_(new char[size]), size_(size) {}

    ~Buffer() {
        delete[] data_;
    }

    Buffer(const Buffer& other) : data_(new char[other.size_]), size_(other.size_) {
        std::memcpy(data_, other.data_, size_);
    }

    Buffer& operator=(const Buffer& other) {
        if (this != &other) {
            delete[] data_;
            data_ = new char[other.size_];
            size_ = other.size_;
            std::memcpy(data_, other.data_, size_);
        }
        return *this;
    }

    char* data() { return data_; }
    size_t size() const { return size_; }

private:
    char* data_;
    size_t size_;
};

// Heap allocation
Node* node = new Node(42);
// ... use node ...
delete node;

// Array allocation
int* arr = new int[100];
// ... use arr ...
delete[] arr;
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Class",
  "name": "Buffer",
  "fields": [
    {"name": "data_", "type": {"name": "char", "pointer": true}, "access": "private"},
    {"name": "size_", "type": {"name": "size_t"}, "access": "private"}
  ],
  "constructors": [
    {"params": [{"name": "size", "type": {"name": "size_t"}}], "access": "public"},
    {"params": [{"name": "other", "type": {"name": "Buffer", "const": true, "reference": true}}], "access": "public"}
  ],
  "destructor": {"body": ["delete[] data_"], "access": "public"},
  "operators": [
    {"operator": "=", "params": [{"name": "other", "type": {"name": "Buffer", "const": true, "reference": true}}]}
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TypeDecl",
  "kind": "struct",
  "name": "Buffer",
  "fields": [
    {"name": "data", "type": {"kind": "slice", "elem_type": {"kind": "primitive", "name": "byte"}}}
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `new T(args)` + "`" + ` → ` + "`" + `&T{args}` + "`" + `** — heap allocation with GC
2. **` + "`" + `new T[n]` + "`" + ` → ` + "`" + `make([]T, n)` + "`" + `** — array allocation becomes slice
3. **` + "`" + `delete ptr` + "`" + ` → remove** — GC handles deallocation
4. **` + "`" + `delete[] arr` + "`" + ` → remove** — GC handles deallocation
5. **` + "`" + `char*` + "`" + ` buffer → ` + "`" + `[]byte` + "`" + `** — Go slice replaces raw pointer + size
6. **Copy constructor → ` + "`" + `Clone()` + "`" + ` method** or just assign (Go copies values)
7. **` + "`" + `operator=` + "`" + ` → remove** — Go assignment copies values, or ` + "`" + `Clone()` + "`" + ` for deep copy
8. **` + "`" + `std::memcpy` + "`" + ` → ` + "`" + `copy(dst, src)` + "`" + `** — built-in slice copy
9. **` + "`" + `size_t` + "`" + ` → ` + "`" + `int` + "`" + `** — Go convention uses ` + "`" + `int` + "`" + ` for lengths

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
type Buffer struct {
	data []byte
}

func NewBuffer(size int) *Buffer {
	return &Buffer{data: make([]byte, size)}
}

func (b *Buffer) Clone() *Buffer {
	clone := &Buffer{data: make([]byte, len(b.data))}
	copy(clone.data, b.data)
	return clone
}

func (b *Buffer) Data() []byte { return b.data }
func (b *Buffer) Size() int    { return len(b.data) }

// Heap allocation — GC handles lifetime
node := NewNode(42)
// no delete needed

// Array allocation — slice handles size tracking
arr := make([]int, 100)
// no delete[] needed
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| ` + "`" + `new T(args)` + "`" + ` | ` + "`" + `&T{args}` + "`" + ` | ` + "`" + `NewExpr` + "`" + ` | ` + "`" + `AddressExpr` + "`" + ` + ` + "`" + `CompositeLitExpr` + "`" + ` |
| ` + "`" + `new T[n]` + "`" + ` | ` + "`" + `make([]T, n)` + "`" + ` | ` + "`" + `NewExpr{array:true}` + "`" + ` | ` + "`" + `MakeExpr` + "`" + ` |
| ` + "`" + `delete ptr` + "`" + ` | (removed — GC) | ` + "`" + `DeleteExpr` + "`" + ` | (none) |
| ` + "`" + `delete[] arr` + "`" + ` | (removed — GC) | ` + "`" + `DeleteExpr{array:true}` + "`" + ` | (none) |
| Copy constructor | ` + "`" + `Clone()` + "`" + ` method | ` + "`" + `Constructor` + "`" + ` (copy) | ` + "`" + `FuncDecl` + "`" + ` |
| ` + "`" + `operator=` + "`" + ` | (removed or ` + "`" + `Clone()` + "`" + `) | ` + "`" + `OperatorOverload{op:"="}` + "`" + ` | (none or ` + "`" + `FuncDecl` + "`" + `) |
| ` + "`" + `std::memcpy(d,s,n)` + "`" + ` | ` + "`" + `copy(d, s)` + "`" + ` | ` + "`" + `CallExpr` + "`" + ` | ` + "`" + `CallExpr{func:"copy"}` + "`" + ` |
| ` + "`" + `size_t` + "`" + ` | ` + "`" + `int` + "`" + ` | ` + "`" + `TypeRef{name:"size_t"}` + "`" + ` | ` + "`" + `TypeRef{kind:"primitive", name:"int"}` + "`" + ` |
| ` + "`" + `char*` + "`" + ` + ` + "`" + `size_t` + "`" + ` | ` + "`" + `[]byte` + "`" + ` | ` + "`" + `Field{pointer:true}` + "`" + ` + ` + "`" + `Field` + "`" + ` | ` + "`" + `FieldDecl{type:slice}` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/memory/raii_defer.md",
			Body: `# RAII to defer Pattern

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <fstream>
#include <mutex>

class FileWriter {
public:
    FileWriter(const std::string& path) : file_(path) {
        if (!file_.is_open()) {
            throw std::runtime_error("cannot open file");
        }
    }

    ~FileWriter() {
        if (file_.is_open()) {
            file_.close();
        }
    }

    void write(const std::string& data) {
        std::lock_guard<std::mutex> lock(mutex_);
        file_ << data;
    }

private:
    std::ofstream file_;
    std::mutex mutex_;
};

// Usage
void processFile(const std::string& path) {
    FileWriter writer(path);  // RAII: resource acquired
    writer.write("hello");
    // ~FileWriter() called automatically at scope exit
}
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Class",
  "name": "FileWriter",
  "fields": [
    {"name": "file_", "type": {"name": "std::ofstream"}, "access": "private"},
    {"name": "mutex_", "type": {"name": "std::mutex"}, "access": "private"}
  ],
  "constructors": [{
    "params": [{"name": "path", "type": {"name": "std::string", "const": true, "reference": true}}],
    "init_list": [{"member": "file_", "value": "path"}],
    "access": "public"
  }],
  "destructor": {"body": ["file_.close()"], "virtual": false, "access": "public"},
  "methods": [{
    "name": "write",
    "params": [{"name": "data", "type": {"name": "std::string", "const": true, "reference": true}}],
    "return_type": {"name": "void"},
    "access": "public"
  }]
}
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TypeDecl",
  "kind": "struct",
  "name": "FileWriter",
  "fields": [
    {"name": "file", "type": {"kind": "pointer", "name": "os.File"}},
    {"name": "mu", "type": {"kind": "struct", "name": "sync.Mutex"}}
  ],
  "methods": [
    {
      "name": "Close",
      "receiver": {"name": "w", "type": {"kind": "pointer", "name": "FileWriter"}},
      "returns": [{"type": {"kind": "primitive", "name": "error"}}],
      "body": [{"type": "ReturnStmt", "values": ["w.file.Close()"]}]
    },
    {
      "name": "Write",
      "receiver": {"name": "w", "type": {"kind": "pointer", "name": "FileWriter"}},
      "params": [{"name": "data", "type": {"kind": "primitive", "name": "string"}}],
      "returns": [{"type": {"kind": "primitive", "name": "error"}}]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Destructor → ` + "`" + `Close()` + "`" + ` method** returning ` + "`" + `error` + "`" + `
2. **Constructor → ` + "`" + `NewX()` + "`" + ` factory** returning ` + "`" + `(*T, error)` + "`" + `
3. **RAII scope → ` + "`" + `defer obj.Close()` + "`" + `** immediately after construction
4. **` + "`" + `std::lock_guard` + "`" + ` → ` + "`" + `mu.Lock()` + "`" + ` + ` + "`" + `defer mu.Unlock()` + "`" + `**
5. **` + "`" + `std::ofstream` + "`" + ` → ` + "`" + `*os.File` + "`" + `** with explicit error returns
6. **Exception in constructor → return ` + "`" + `nil, err` + "`" + `**

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package filewriter

import (
	"os"
	"sync"
)

// FileWriter writes data to a file with mutex protection.
type FileWriter struct {
	file *os.File
	mu   sync.Mutex
}

// NewFileWriter opens a file for writing.
func NewFileWriter(path string) (*FileWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &FileWriter{file: f}, nil
}

// Close releases the file resource.
func (w *FileWriter) Close() error {
	return w.file.Close()
}

// Write writes data to the file with mutex protection.
func (w *FileWriter) Write(data string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.file.WriteString(data)
	return err
}

// Usage
func processFile(path string) error {
	writer, err := NewFileWriter(path)
	if err != nil {
		return err
	}
	defer writer.Close() // replaces RAII destructor
	return writer.Write("hello")
}
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| Destructor body | ` + "`" + `Close() error` + "`" + ` method | ` + "`" + `Destructor` + "`" + ` | ` + "`" + `FuncDecl` + "`" + ` with receiver |
| ` + "`" + `std::lock_guard<std::mutex>` + "`" + ` | ` + "`" + `mu.Lock(); defer mu.Unlock()` + "`" + ` | ` + "`" + `Variable` + "`" + ` + ` + "`" + `TypeRef` + "`" + ` | ` + "`" + `DeferStmt` + "`" + ` |
| Stack-allocated RAII object | ` + "`" + `defer obj.Close()` + "`" + ` after ` + "`" + `NewX()` + "`" + ` | ` + "`" + `Variable` + "`" + ` (auto) | ` + "`" + `DeferStmt` + "`" + ` |
| Constructor exception | ` + "`" + `return nil, err` + "`" + ` | ` + "`" + `Constructor` + "`" + ` throw | ` + "`" + `ErrorHandling` + "`" + ` |
| ` + "`" + `std::ofstream` + "`" + ` open check | ` + "`" + `os.Create()` + "`" + ` + ` + "`" + `if err != nil` + "`" + ` | ` + "`" + `CallExpr` + "`" + ` | ` + "`" + `ErrorHandling` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/memory/smart_pointers.md",
			Body: `# Smart Pointers to Go Pointers

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <memory>
#include <vector>

class Node {
public:
    explicit Node(int val) : value_(val) {}
    int getValue() const { return value_; }

private:
    int value_;
};

class Tree {
public:
    void addChild(std::unique_ptr<Node> node) {
        children_.push_back(std::move(node));
    }

    std::shared_ptr<Node> findNode(int val) const {
        for (const auto& child : children_) {
            if (child->getValue() == val) {
                return std::shared_ptr<Node>(child.get(), [](Node*){});
            }
        }
        return nullptr;
    }

    void setRoot(std::unique_ptr<Node> root) {
        root_ = std::move(root);
    }

private:
    std::unique_ptr<Node> root_;
    std::vector<std::unique_ptr<Node>> children_;
};

// Usage
auto node = std::make_unique<Node>(42);
tree.addChild(std::move(node));
auto shared = std::make_shared<Node>(10);
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Class",
  "name": "Tree",
  "fields": [
    {
      "name": "root_",
      "type": {"name": "std::unique_ptr", "template_args": [{"name": "Node"}]},
      "access": "private"
    },
    {
      "name": "children_",
      "type": {
        "name": "std::vector",
        "template_args": [{"name": "std::unique_ptr", "template_args": [{"name": "Node"}]}]
      },
      "access": "private"
    }
  ],
  "methods": [
    {
      "name": "addChild",
      "params": [{"name": "node", "type": {"name": "std::unique_ptr", "template_args": [{"name": "Node"}]}}]
    },
    {
      "name": "findNode",
      "return_type": {"name": "std::shared_ptr", "template_args": [{"name": "Node"}]},
      "const": true
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TypeDecl",
  "kind": "struct",
  "name": "Tree",
  "fields": [
    {"name": "root", "type": {"kind": "pointer", "elem_type": {"name": "Node"}}},
    {"name": "children", "type": {"kind": "slice", "elem_type": {"kind": "pointer", "name": "Node"}}}
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `std::unique_ptr<T>` + "`" + ` → ` + "`" + `*T` + "`" + `** — Go GC handles ownership
2. **` + "`" + `std::shared_ptr<T>` + "`" + ` → ` + "`" + `*T` + "`" + `** — Go GC is reference-counted implicitly
3. **` + "`" + `std::weak_ptr<T>` + "`" + ` → ` + "`" + `*T` + "`" + `** — no weak references needed with GC
4. **` + "`" + `std::make_unique<T>(args)` + "`" + ` → ` + "`" + `&T{args}` + "`" + `** or ` + "`" + `NewT(args)` + "`" + `
5. **` + "`" + `std::make_shared<T>(args)` + "`" + ` → ` + "`" + `&T{args}` + "`" + `** or ` + "`" + `NewT(args)` + "`" + `
6. **` + "`" + `std::move(x)` + "`" + ` → just ` + "`" + `x` + "`" + `** — no move semantics in Go
7. **` + "`" + `std::vector<std::unique_ptr<T>>` + "`" + ` → ` + "`" + `[]*T` + "`" + `**
8. **` + "`" + `ptr.get()` + "`" + ` → just ` + "`" + `ptr` + "`" + `** — already a raw pointer
9. **` + "`" + `ptr.reset()` + "`" + ` → ` + "`" + `ptr = nil` + "`" + `**
10. **` + "`" + `ptr == nullptr` + "`" + ` → ` + "`" + `ptr == nil` + "`" + `**

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
type Node struct {
	value int
}

func NewNode(val int) *Node {
	return &Node{value: val}
}

func (n *Node) GetValue() int {
	return n.value
}

type Tree struct {
	root     *Node
	children []*Node
}

func (t *Tree) AddChild(node *Node) {
	t.children = append(t.children, node)
}

func (t *Tree) FindNode(val int) *Node {
	for _, child := range t.children {
		if child.GetValue() == val {
			return child
		}
	}
	return nil
}

func (t *Tree) SetRoot(root *Node) {
	t.root = root
}

// Usage
node := NewNode(42)
tree.AddChild(node) // no std::move needed
shared := NewNode(10)
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| ` + "`" + `std::unique_ptr<T>` + "`" + ` | ` + "`" + `*T` + "`" + ` | ` + "`" + `TypeRef{name:"std::unique_ptr"}` + "`" + ` | ` + "`" + `TypeRef{kind:"pointer"}` + "`" + ` |
| ` + "`" + `std::shared_ptr<T>` + "`" + ` | ` + "`" + `*T` + "`" + ` | ` + "`" + `TypeRef{name:"std::shared_ptr"}` + "`" + ` | ` + "`" + `TypeRef{kind:"pointer"}` + "`" + ` |
| ` + "`" + `std::make_unique<T>(args)` + "`" + ` | ` + "`" + `&T{args}` + "`" + ` or ` + "`" + `NewT(args)` + "`" + ` | ` + "`" + `CallExpr` + "`" + ` | ` + "`" + `AddressExpr` + "`" + ` + ` + "`" + `CompositeLitExpr` + "`" + ` |
| ` + "`" + `std::move(x)` + "`" + ` | ` + "`" + `x` + "`" + ` (no-op) | ` + "`" + `CallExpr{func:"std::move"}` + "`" + ` | ` + "`" + `IdentExpr` + "`" + ` |
| ` + "`" + `ptr.get()` + "`" + ` | ` + "`" + `ptr` + "`" + ` (no-op) | ` + "`" + `MethodCallExpr{method:"get"}` + "`" + ` | ` + "`" + `IdentExpr` + "`" + ` |
| ` + "`" + `ptr.reset()` + "`" + ` | ` + "`" + `ptr = nil` + "`" + ` | ` + "`" + `MethodCallExpr{method:"reset"}` + "`" + ` | ` + "`" + `AssignStmt` + "`" + ` |
| ` + "`" + `ptr == nullptr` + "`" + ` | ` + "`" + `ptr == nil` + "`" + ` | ` + "`" + `BinaryExpr{op:"=="}` + "`" + ` | ` + "`" + `BinaryExpr{op:"=="}` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/oop/classes_structs.md",
			Body: `# Classes to Structs

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <cmath>
#include <string>

class Point {
public:
    Point(double x, double y) : x_(x), y_(y) {}

    double getX() const { return x_; }
    double getY() const { return y_; }

    void setX(double x) { x_ = x; }
    void setY(double y) { y_ = y; }

    double distanceTo(const Point& other) const {
        double dx = x_ - other.x_;
        double dy = y_ - other.y_;
        return std::sqrt(dx * dx + dy * dy);
    }

    Point operator+(const Point& other) const {
        return Point(x_ + other.x_, y_ + other.y_);
    }

    std::string toString() const {
        return "(" + std::to_string(x_) + ", " + std::to_string(y_) + ")";
    }

private:
    double x_;
    double y_;
};

// Usage
Point a(3.0, 4.0);
Point b(6.0, 8.0);
double dist = a.distanceTo(b);
Point c = a + b;
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Class",
  "kind": "class",
  "name": "Point",
  "base_classes": [],
  "template_params": [],
  "fields": [
    {"name": "x_", "type": {"name": "double"}, "access": "private"},
    {"name": "y_", "type": {"name": "double"}, "access": "private"}
  ],
  "constructors": [
    {
      "params": [
        {"name": "x", "type": {"name": "double"}},
        {"name": "y", "type": {"name": "double"}}
      ],
      "init_list": [
        {"member": "x_", "value": "x"},
        {"member": "y_", "value": "y"}
      ],
      "access": "public"
    }
  ],
  "destructor": null,
  "methods": [
    {
      "name": "getX",
      "return_type": {"name": "double"},
      "params": [],
      "const": true,
      "virtual": false,
      "pure": false,
      "override": false,
      "access": "public"
    },
    {
      "name": "getY",
      "return_type": {"name": "double"},
      "params": [],
      "const": true,
      "virtual": false,
      "pure": false,
      "override": false,
      "access": "public"
    },
    {
      "name": "setX",
      "return_type": {"name": "void"},
      "params": [{"name": "x", "type": {"name": "double"}}],
      "const": false,
      "virtual": false,
      "pure": false,
      "override": false,
      "access": "public"
    },
    {
      "name": "setY",
      "return_type": {"name": "void"},
      "params": [{"name": "y", "type": {"name": "double"}}],
      "const": false,
      "virtual": false,
      "pure": false,
      "override": false,
      "access": "public"
    },
    {
      "name": "distanceTo",
      "return_type": {"name": "double"},
      "params": [{"name": "other", "type": {"name": "Point", "const": true, "reference": true}}],
      "const": true,
      "virtual": false,
      "pure": false,
      "override": false,
      "access": "public"
    },
    {
      "name": "toString",
      "return_type": {"name": "std::string"},
      "params": [],
      "const": true,
      "virtual": false,
      "pure": false,
      "override": false,
      "access": "public"
    }
  ],
  "operators": [
    {
      "operator": "+",
      "return_type": {"name": "Point"},
      "params": [{"name": "other", "type": {"name": "Point", "const": true, "reference": true}}],
      "const": true,
      "access": "public"
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TypeDecl",
  "kind": "struct",
  "name": "Point",
  "embedded": [],
  "fields": [
    {"name": "X", "type": {"kind": "primitive", "name": "float64"}},
    {"name": "Y", "type": {"kind": "primitive", "name": "float64"}}
  ],
  "methods": [
    {
      "type": "FuncDecl",
      "name": "DistanceTo",
      "receiver": {"name": "p", "type": {"kind": "struct", "name": "Point"}},
      "params": [{"name": "other", "type": {"kind": "struct", "name": "Point"}}],
      "returns": [{"type": {"kind": "primitive", "name": "float64"}}]
    },
    {
      "type": "FuncDecl",
      "name": "Add",
      "receiver": {"name": "p", "type": {"kind": "struct", "name": "Point"}},
      "params": [{"name": "other", "type": {"kind": "struct", "name": "Point"}}],
      "returns": [{"type": {"kind": "struct", "name": "Point"}}]
    },
    {
      "type": "FuncDecl",
      "name": "String",
      "receiver": {"name": "p", "type": {"kind": "struct", "name": "Point"}},
      "params": [],
      "returns": [{"type": {"kind": "primitive", "name": "string"}}]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `class` + "`" + ` → ` + "`" + `struct` + "`" + `** -- Go has no class keyword; structs carry both data and methods
2. **Private fields → unexported (lowercase)** or **promoted to exported (uppercase)** when getters/setters are trivial pass-through
3. **Trivial getters/setters → remove** -- promote the field to exported and access directly
4. **Non-trivial getters/setters → keep** as methods when they contain validation or side effects
5. **Constructor → ` + "`" + `NewX()` + "`" + ` factory function** returning the struct (value or pointer)
6. **` + "`" + `const` + "`" + ` methods → value receiver** -- method does not mutate the receiver
7. **Non-` + "`" + `const` + "`" + ` methods → pointer receiver** -- method mutates the receiver
8. **` + "`" + `operator+` + "`" + ` → ` + "`" + `Add()` + "`" + ` method** -- Go has no operator overloading; use named methods
9. **` + "`" + `toString()` + "`" + ` → ` + "`" + `String()` + "`" + `** -- satisfies ` + "`" + `fmt.Stringer` + "`" + ` interface
10. **` + "`" + `double` + "`" + ` → ` + "`" + `float64` + "`" + `**, **` + "`" + `std::string` + "`" + ` → ` + "`" + `string` + "`" + `** -- standard type mappings
11. **` + "`" + `const T&` + "`" + ` parameter → value ` + "`" + `T` + "`" + `** -- Go copies small structs efficiently

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package point

import (
	"fmt"
	"math"
)

// Point represents a 2D coordinate.
type Point struct {
	X float64
	Y float64
}

// NewPoint creates a Point with the given coordinates.
func NewPoint(x, y float64) Point {
	return Point{X: x, Y: y}
}

// DistanceTo returns the Euclidean distance to another point.
func (p Point) DistanceTo(other Point) float64 {
	dx := p.X - other.X
	dy := p.Y - other.Y
	return math.Sqrt(dx*dx + dy*dy)
}

// Add returns a new point that is the vector sum of p and other.
func (p Point) Add(other Point) Point {
	return Point{X: p.X + other.X, Y: p.Y + other.Y}
}

// String returns a formatted string representation.
func (p Point) String() string {
	return fmt.Sprintf("(%g, %g)", p.X, p.Y)
}

// Usage
a := NewPoint(3.0, 4.0)
b := NewPoint(6.0, 8.0)
dist := a.DistanceTo(b)
c := a.Add(b)
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| ` + "`" + `class Point { ... }` + "`" + ` | ` + "`" + `type Point struct { ... }` + "`" + ` | ` + "`" + `Class{kind:"class"}` + "`" + ` | ` + "`" + `TypeDecl{kind:"struct"}` + "`" + ` |
| Private field ` + "`" + `x_` + "`" + ` with getter ` + "`" + `getX()` + "`" + ` | Exported field ` + "`" + `X` + "`" + ` | ` + "`" + `Field{access:"private"}` + "`" + ` + ` + "`" + `Method{name:"getX"}` + "`" + ` | ` + "`" + `FieldDecl{name:"X"}` + "`" + ` |
| Constructor with init list | ` + "`" + `NewPoint()` + "`" + ` factory | ` + "`" + `Constructor{init_list:[...]}` + "`" + ` | ` + "`" + `FuncDecl{name:"NewPoint"}` + "`" + ` |
| ` + "`" + `const` + "`" + ` method | Value receiver ` + "`" + `(p Point)` + "`" + ` | ` + "`" + `Method{const:true}` + "`" + ` | ` + "`" + `FuncDecl{receiver:{name:"p"}}` + "`" + ` |
| Non-` + "`" + `const` + "`" + ` method | Pointer receiver ` + "`" + `(p *Point)` + "`" + ` | ` + "`" + `Method{const:false}` + "`" + ` | ` + "`" + `FuncDecl{receiver:{type:pointer}}` + "`" + ` |
| ` + "`" + `operator+` + "`" + ` | ` + "`" + `Add()` + "`" + ` method | ` + "`" + `Operator{op:"+"}` + "`" + ` | ` + "`" + `FuncDecl{name:"Add"}` + "`" + ` |
| ` + "`" + `toString()` + "`" + ` | ` + "`" + `String()` + "`" + ` (` + "`" + `fmt.Stringer` + "`" + `) | ` + "`" + `Method{name:"toString"}` + "`" + ` | ` + "`" + `FuncDecl{name:"String"}` + "`" + ` |
| ` + "`" + `double` + "`" + ` | ` + "`" + `float64` + "`" + ` | ` + "`" + `TypeRef{name:"double"}` + "`" + ` | ` + "`" + `TypeRef{kind:"primitive", name:"float64"}` + "`" + ` |
| ` + "`" + `const Point&` + "`" + ` param | ` + "`" + `Point` + "`" + ` (value) | ` + "`" + `Param{const:true, reference:true}` + "`" + ` | ` + "`" + `Param{type:{kind:"struct"}}` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/oop/constructors_destructors.md",
			Body: `# Constructors and Destructors to Factory Functions

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <string>
#include <stdexcept>
#include <iostream>

class Database {
public:
    // Primary constructor
    Database(const std::string& host, int port, const std::string& dbname)
        : host_(host), port_(port), dbname_(dbname), connected_(false) {
        connect();
    }

    // Overloaded constructor (defaults)
    explicit Database(const std::string& connectionString)
        : host_(""), port_(0), dbname_(""), connected_(false) {
        parseConnectionString(connectionString);
        connect();
    }

    // Copy constructor
    Database(const Database& other)
        : host_(other.host_), port_(other.port_), dbname_(other.dbname_),
          connected_(false) {
        // New connection, not sharing the original
        connect();
    }

    // Move constructor
    Database(Database&& other) noexcept
        : host_(std::move(other.host_)),
          port_(other.port_),
          dbname_(std::move(other.dbname_)),
          connected_(other.connected_) {
        other.connected_ = false;
        other.port_ = 0;
    }

    // Copy assignment
    Database& operator=(const Database& other) {
        if (this != &other) {
            disconnect();
            host_ = other.host_;
            port_ = other.port_;
            dbname_ = other.dbname_;
            connect();
        }
        return *this;
    }

    // Move assignment
    Database& operator=(Database&& other) noexcept {
        if (this != &other) {
            disconnect();
            host_ = std::move(other.host_);
            port_ = other.port_;
            dbname_ = std::move(other.dbname_);
            connected_ = other.connected_;
            other.connected_ = false;
            other.port_ = 0;
        }
        return *this;
    }

    // Destructor
    ~Database() {
        if (connected_) {
            disconnect();
        }
    }

    bool isConnected() const { return connected_; }
    std::string getHost() const { return host_; }

    void execute(const std::string& query) {
        if (!connected_) {
            throw std::runtime_error("not connected");
        }
        // execute query...
    }

private:
    void connect() {
        // establish connection
        connected_ = true;
    }

    void disconnect() {
        // close connection
        connected_ = false;
    }

    void parseConnectionString(const std::string& cs) {
        // parse "host:port/dbname" format
    }

    std::string host_;
    int port_;
    std::string dbname_;
    bool connected_;
};

// Usage with RAII
void doWork() {
    Database db("localhost", 5432, "mydb");
    db.execute("SELECT 1");
    // ~Database() called at scope exit
}
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Class",
  "kind": "class",
  "name": "Database",
  "base_classes": [],
  "template_params": [],
  "fields": [
    {"name": "host_", "type": {"name": "std::string"}, "access": "private"},
    {"name": "port_", "type": {"name": "int"}, "access": "private"},
    {"name": "dbname_", "type": {"name": "std::string"}, "access": "private"},
    {"name": "connected_", "type": {"name": "bool"}, "access": "private"}
  ],
  "constructors": [
    {
      "params": [
        {"name": "host", "type": {"name": "std::string", "const": true, "reference": true}},
        {"name": "port", "type": {"name": "int"}},
        {"name": "dbname", "type": {"name": "std::string", "const": true, "reference": true}}
      ],
      "init_list": [
        {"member": "host_", "value": "host"},
        {"member": "port_", "value": "port"},
        {"member": "dbname_", "value": "dbname"},
        {"member": "connected_", "value": "false"}
      ],
      "explicit": false,
      "access": "public"
    },
    {
      "params": [
        {"name": "connectionString", "type": {"name": "std::string", "const": true, "reference": true}}
      ],
      "init_list": [
        {"member": "host_", "value": "\"\""},
        {"member": "port_", "value": "0"},
        {"member": "dbname_", "value": "\"\""},
        {"member": "connected_", "value": "false"}
      ],
      "explicit": true,
      "access": "public"
    },
    {
      "params": [
        {"name": "other", "type": {"name": "Database", "const": true, "reference": true}}
      ],
      "init_list": [
        {"member": "host_", "value": "other.host_"},
        {"member": "port_", "value": "other.port_"},
        {"member": "dbname_", "value": "other.dbname_"},
        {"member": "connected_", "value": "false"}
      ],
      "copy": true,
      "access": "public"
    },
    {
      "params": [
        {"name": "other", "type": {"name": "Database", "rvalue_reference": true}}
      ],
      "init_list": [
        {"member": "host_", "value": "std::move(other.host_)"},
        {"member": "port_", "value": "other.port_"},
        {"member": "dbname_", "value": "std::move(other.dbname_)"},
        {"member": "connected_", "value": "other.connected_"}
      ],
      "move": true,
      "noexcept": true,
      "access": "public"
    }
  ],
  "destructor": {
    "virtual": false,
    "body": ["if (connected_) { disconnect(); }"],
    "access": "public"
  },
  "methods": [
    {"name": "isConnected", "return_type": {"name": "bool"}, "params": [], "const": true, "virtual": false, "pure": false, "override": false, "access": "public"},
    {"name": "getHost", "return_type": {"name": "std::string"}, "params": [], "const": true, "virtual": false, "pure": false, "override": false, "access": "public"},
    {"name": "execute", "return_type": {"name": "void"}, "params": [{"name": "query", "type": {"name": "std::string", "const": true, "reference": true}}], "const": false, "virtual": false, "pure": false, "override": false, "access": "public"},
    {"name": "connect", "return_type": {"name": "void"}, "params": [], "const": false, "virtual": false, "pure": false, "override": false, "access": "private"},
    {"name": "disconnect", "return_type": {"name": "void"}, "params": [], "const": false, "virtual": false, "pure": false, "override": false, "access": "private"},
    {"name": "parseConnectionString", "return_type": {"name": "void"}, "params": [{"name": "cs", "type": {"name": "std::string", "const": true, "reference": true}}], "const": false, "virtual": false, "pure": false, "override": false, "access": "private"}
  ],
  "operators": [
    {
      "operator": "=",
      "params": [{"name": "other", "type": {"name": "Database", "const": true, "reference": true}}],
      "return_type": {"name": "Database", "reference": true},
      "copy": true,
      "access": "public"
    },
    {
      "operator": "=",
      "params": [{"name": "other", "type": {"name": "Database", "rvalue_reference": true}}],
      "return_type": {"name": "Database", "reference": true},
      "move": true,
      "noexcept": true,
      "access": "public"
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Package",
  "declarations": [
    {
      "type": "TypeDecl",
      "kind": "struct",
      "name": "Database",
      "embedded": [],
      "fields": [
        {"name": "host", "type": {"kind": "primitive", "name": "string"}},
        {"name": "port", "type": {"kind": "primitive", "name": "int"}},
        {"name": "dbname", "type": {"kind": "primitive", "name": "string"}},
        {"name": "connected", "type": {"kind": "primitive", "name": "bool"}}
      ],
      "methods": [
        {
          "type": "FuncDecl",
          "name": "Close",
          "receiver": {"name": "db", "type": {"kind": "pointer", "name": "Database"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "error"}}]
        },
        {
          "type": "FuncDecl",
          "name": "Clone",
          "receiver": {"name": "db", "type": {"kind": "pointer", "name": "Database"}},
          "params": [],
          "returns": [
            {"type": {"kind": "pointer", "name": "Database"}},
            {"type": {"kind": "primitive", "name": "error"}}
          ]
        },
        {
          "type": "FuncDecl",
          "name": "Execute",
          "receiver": {"name": "db", "type": {"kind": "pointer", "name": "Database"}},
          "params": [{"name": "query", "type": {"kind": "primitive", "name": "string"}}],
          "returns": [{"type": {"kind": "primitive", "name": "error"}}]
        }
      ]
    },
    {
      "type": "FuncDecl",
      "name": "NewDatabase",
      "receiver": null,
      "params": [
        {"name": "host", "type": {"kind": "primitive", "name": "string"}},
        {"name": "port", "type": {"kind": "primitive", "name": "int"}},
        {"name": "dbname", "type": {"kind": "primitive", "name": "string"}}
      ],
      "returns": [
        {"type": {"kind": "pointer", "name": "Database"}},
        {"type": {"kind": "primitive", "name": "error"}}
      ]
    },
    {
      "type": "FuncDecl",
      "name": "NewDatabaseFromConnString",
      "receiver": null,
      "params": [
        {"name": "connectionString", "type": {"kind": "primitive", "name": "string"}}
      ],
      "returns": [
        {"type": {"kind": "pointer", "name": "Database"}},
        {"type": {"kind": "primitive", "name": "error"}}
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Primary constructor → ` + "`" + `NewX()` + "`" + ` factory function** returning ` + "`" + `(*T, error)` + "`" + ` -- the factory initializes the struct and performs any setup that could fail
2. **Overloaded constructors → multiple ` + "`" + `NewX` + "`" + ` variants** with descriptive suffixes (e.g., ` + "`" + `NewDatabaseFromConnString` + "`" + `) -- Go has no function overloading, so each variant needs a unique name
3. **Copy constructor → ` + "`" + `Clone()` + "`" + ` method** returning ` + "`" + `(*T, error)` + "`" + ` -- creates a deep copy with its own independent resources (e.g., a new database connection)
4. **Move constructor → remove** -- Go copies values by default; there is no move semantics. The GC handles memory, so there is no ownership transfer concern
5. **Copy assignment ` + "`" + `operator=` + "`" + ` → remove** -- Go's assignment copies values. For deep copy semantics, callers use ` + "`" + `Clone()` + "`" + ` explicitly
6. **Move assignment ` + "`" + `operator=` + "`" + ` → remove** -- same reasoning as move constructor; Go does not have move semantics
7. **Destructor with cleanup logic → ` + "`" + `Close() error` + "`" + ` method** -- implement ` + "`" + `io.Closer` + "`" + ` for interoperability with ` + "`" + `defer` + "`" + ` and standard library patterns
8. **` + "`" + `throw` + "`" + ` in methods → return ` + "`" + `error` + "`" + `** -- exceptions become explicit error returns
9. **Initializer list → struct field assignment** in the factory function body
10. **Private helper methods → unexported methods** -- ` + "`" + `connect()` + "`" + ` and ` + "`" + `disconnect()` + "`" + ` remain as unexported helpers
11. **RAII usage → ` + "`" + `defer db.Close()` + "`" + `** -- acquire in factory, defer close immediately after

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package database

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// Verify Database implements io.Closer at compile time.
var _ io.Closer = (*Database)(nil)

// Database manages a connection to a database server.
type Database struct {
	host      string
	port      int
	dbname    string
	connected bool
}

// NewDatabase creates a Database and connects to the given host.
func NewDatabase(host string, port int, dbname string) (*Database, error) {
	db := &Database{
		host:   host,
		port:   port,
		dbname: dbname,
	}
	if err := db.connect(); err != nil {
		return nil, fmt.Errorf("connect to %s:%d/%s: %w", host, port, dbname, err)
	}
	return db, nil
}

// NewDatabaseFromConnString creates a Database from a "host:port/dbname" string.
func NewDatabaseFromConnString(connectionString string) (*Database, error) {
	host, port, dbname, err := parseConnectionString(connectionString)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}
	return NewDatabase(host, port, dbname)
}

// Clone creates a new Database with its own connection using the same parameters.
func (db *Database) Clone() (*Database, error) {
	return NewDatabase(db.host, db.port, db.dbname)
}

// Close disconnects from the database and releases resources.
func (db *Database) Close() error {
	if !db.connected {
		return nil
	}
	return db.disconnect()
}

// IsConnected reports whether the database connection is active.
func (db *Database) IsConnected() bool {
	return db.connected
}

// Host returns the database host.
func (db *Database) Host() string {
	return db.host
}

// Execute runs a query against the database.
func (db *Database) Execute(query string) error {
	if !db.connected {
		return errors.New("not connected")
	}
	// execute query...
	return nil
}

func (db *Database) connect() error {
	// establish connection
	db.connected = true
	return nil
}

func (db *Database) disconnect() error {
	// close connection
	db.connected = false
	return nil
}

func parseConnectionString(cs string) (host string, port int, dbname string, err error) {
	// parse "host:port/dbname" format
	parts := strings.SplitN(cs, "/", 2)
	if len(parts) != 2 {
		return "", 0, "", errors.New("invalid connection string format")
	}
	dbname = parts[1]

	hostPort := strings.SplitN(parts[0], ":", 2)
	if len(hostPort) != 2 {
		return "", 0, "", errors.New("missing port in connection string")
	}
	host = hostPort[0]

	_, err = fmt.Sscanf(hostPort[1], "%d", &port)
	if err != nil {
		return "", 0, "", fmt.Errorf("invalid port: %w", err)
	}
	return host, port, dbname, nil
}

// Usage with defer (replaces RAII)
func doWork() error {
	db, err := NewDatabase("localhost", 5432, "mydb")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	return db.Execute("SELECT 1")
}
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| Primary constructor | ` + "`" + `NewX()` + "`" + ` factory returning ` + "`" + `(*T, error)` + "`" + ` | ` + "`" + `Constructor{params:[...]}` + "`" + ` | ` + "`" + `FuncDecl{name:"NewX"}` + "`" + ` |
| Overloaded constructor | ` + "`" + `NewXFromY()` + "`" + ` named variant | ` + "`" + `Constructor` + "`" + ` (additional) | ` + "`" + `FuncDecl{name:"NewXFromY"}` + "`" + ` |
| Copy constructor | ` + "`" + `Clone() (*T, error)` + "`" + ` method | ` + "`" + `Constructor{copy:true}` + "`" + ` | ` + "`" + `FuncDecl{name:"Clone"}` + "`" + ` |
| Move constructor | (removed -- Go copies values) | ` + "`" + `Constructor{move:true}` + "`" + ` | (none) |
| Copy assignment ` + "`" + `operator=` + "`" + ` | (removed or ` + "`" + `Clone()` + "`" + `) | ` + "`" + `Operator{op:"=", copy:true}` + "`" + ` | (none) |
| Move assignment ` + "`" + `operator=` + "`" + ` | (removed -- no move semantics) | ` + "`" + `Operator{op:"=", move:true}` + "`" + ` | (none) |
| Destructor with body | ` + "`" + `Close() error` + "`" + ` (` + "`" + `io.Closer` + "`" + `) | ` + "`" + `Destructor{body:[...]}` + "`" + ` | ` + "`" + `FuncDecl{name:"Close"}` + "`" + ` |
| ` + "`" + `throw` + "`" + ` in constructor | ` + "`" + `return nil, err` + "`" + ` | ` + "`" + `Constructor` + "`" + ` + throw | ` + "`" + `FuncDecl` + "`" + ` + ` + "`" + `ErrorHandling` + "`" + ` |
| Initializer list | Struct literal fields | ` + "`" + `Constructor{init_list:[...]}` + "`" + ` | ` + "`" + `CompositeLitExpr` + "`" + ` |
| RAII scope cleanup | ` + "`" + `defer db.Close()` + "`" + ` | ` + "`" + `Variable` + "`" + ` (auto storage) | ` + "`" + `DeferStmt` + "`" + ` |
| ` + "`" + `explicit` + "`" + ` keyword | (not applicable -- factories are always explicit) | ` + "`" + `Constructor{explicit:true}` + "`" + ` | (none) |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/oop/inheritance_composition.md",
			Body: `# Inheritance to Composition

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <cmath>
#include <string>

// Base class
class Shape {
public:
    Shape(const std::string& color) : color_(color) {}
    virtual ~Shape() = default;

    std::string getColor() const { return color_; }
    void setColor(const std::string& color) { color_ = color; }

    virtual double area() const = 0;
    virtual double perimeter() const = 0;
    virtual std::string describe() const {
        return "Shape(color=" + color_ + ")";
    }

private:
    std::string color_;
};

// Single inheritance
class Circle : public Shape {
public:
    Circle(const std::string& color, double radius)
        : Shape(color), radius_(radius) {}

    double area() const override {
        return M_PI * radius_ * radius_;
    }

    double perimeter() const override {
        return 2 * M_PI * radius_;
    }

    std::string describe() const override {
        return "Circle(color=" + getColor() + ", radius=" + std::to_string(radius_) + ")";
    }

private:
    double radius_;
};

// Single inheritance
class Rectangle : public Shape {
public:
    Rectangle(const std::string& color, double width, double height)
        : Shape(color), width_(width), height_(height) {}

    double area() const override {
        return width_ * height_;
    }

    double perimeter() const override {
        return 2 * (width_ + height_);
    }

    std::string describe() const override {
        return "Rectangle(color=" + getColor() + ", w=" + std::to_string(width_)
            + ", h=" + std::to_string(height_) + ")";
    }

private:
    double width_;
    double height_;
};

// Multiple inheritance
class Printable {
public:
    virtual ~Printable() = default;
    virtual void print() const = 0;
};

class PrintableCircle : public Circle, public Printable {
public:
    PrintableCircle(const std::string& color, double radius)
        : Circle(color, radius) {}

    void print() const override {
        std::cout << describe() << std::endl;
    }
};

// Usage with polymorphism
void printArea(const Shape& shape) {
    std::cout << shape.describe() << " area=" << shape.area() << std::endl;
}
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "Class",
      "kind": "class",
      "name": "Shape",
      "base_classes": [],
      "template_params": [],
      "fields": [
        {"name": "color_", "type": {"name": "std::string"}, "access": "private"}
      ],
      "constructors": [
        {
          "params": [{"name": "color", "type": {"name": "std::string", "const": true, "reference": true}}],
          "init_list": [{"member": "color_", "value": "color"}],
          "access": "public"
        }
      ],
      "destructor": {"virtual": true, "default": true, "access": "public"},
      "methods": [
        {"name": "getColor", "return_type": {"name": "std::string"}, "const": true, "virtual": false, "pure": false, "override": false, "access": "public"},
        {"name": "setColor", "params": [{"name": "color", "type": {"name": "std::string", "const": true, "reference": true}}], "return_type": {"name": "void"}, "const": false, "virtual": false, "pure": false, "override": false, "access": "public"},
        {"name": "area", "return_type": {"name": "double"}, "const": true, "virtual": true, "pure": true, "override": false, "access": "public"},
        {"name": "perimeter", "return_type": {"name": "double"}, "const": true, "virtual": true, "pure": true, "override": false, "access": "public"},
        {"name": "describe", "return_type": {"name": "std::string"}, "const": true, "virtual": true, "pure": false, "override": false, "access": "public"}
      ],
      "operators": []
    },
    {
      "type": "Class",
      "kind": "class",
      "name": "Circle",
      "base_classes": [
        {"name": "Shape", "access": "public"}
      ],
      "template_params": [],
      "fields": [
        {"name": "radius_", "type": {"name": "double"}, "access": "private"}
      ],
      "constructors": [
        {
          "params": [
            {"name": "color", "type": {"name": "std::string", "const": true, "reference": true}},
            {"name": "radius", "type": {"name": "double"}}
          ],
          "init_list": [
            {"member": "Shape", "value": "color"},
            {"member": "radius_", "value": "radius"}
          ],
          "access": "public"
        }
      ],
      "destructor": null,
      "methods": [
        {"name": "area", "return_type": {"name": "double"}, "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "perimeter", "return_type": {"name": "double"}, "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "describe", "return_type": {"name": "std::string"}, "const": true, "virtual": true, "pure": false, "override": true, "access": "public"}
      ],
      "operators": []
    },
    {
      "type": "Class",
      "kind": "class",
      "name": "Rectangle",
      "base_classes": [
        {"name": "Shape", "access": "public"}
      ],
      "template_params": [],
      "fields": [
        {"name": "width_", "type": {"name": "double"}, "access": "private"},
        {"name": "height_", "type": {"name": "double"}, "access": "private"}
      ],
      "constructors": [
        {
          "params": [
            {"name": "color", "type": {"name": "std::string", "const": true, "reference": true}},
            {"name": "width", "type": {"name": "double"}},
            {"name": "height", "type": {"name": "double"}}
          ],
          "init_list": [
            {"member": "Shape", "value": "color"},
            {"member": "width_", "value": "width"},
            {"member": "height_", "value": "height"}
          ],
          "access": "public"
        }
      ],
      "destructor": null,
      "methods": [
        {"name": "area", "return_type": {"name": "double"}, "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "perimeter", "return_type": {"name": "double"}, "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "describe", "return_type": {"name": "std::string"}, "const": true, "virtual": true, "pure": false, "override": true, "access": "public"}
      ],
      "operators": []
    },
    {
      "type": "Class",
      "kind": "class",
      "name": "Printable",
      "base_classes": [],
      "template_params": [],
      "fields": [],
      "constructors": [],
      "destructor": {"virtual": true, "default": true, "access": "public"},
      "methods": [
        {"name": "print", "return_type": {"name": "void"}, "const": true, "virtual": true, "pure": true, "override": false, "access": "public"}
      ],
      "operators": []
    },
    {
      "type": "Class",
      "kind": "class",
      "name": "PrintableCircle",
      "base_classes": [
        {"name": "Circle", "access": "public"},
        {"name": "Printable", "access": "public"}
      ],
      "template_params": [],
      "fields": [],
      "constructors": [
        {
          "params": [
            {"name": "color", "type": {"name": "std::string", "const": true, "reference": true}},
            {"name": "radius", "type": {"name": "double"}}
          ],
          "init_list": [{"member": "Circle", "value": "color, radius"}],
          "access": "public"
        }
      ],
      "destructor": null,
      "methods": [
        {"name": "print", "return_type": {"name": "void"}, "const": true, "virtual": true, "pure": false, "override": true, "access": "public"}
      ],
      "operators": []
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Package",
  "declarations": [
    {
      "type": "TypeDecl",
      "kind": "interface",
      "name": "ShapeInterface",
      "methods": [
        {"name": "Area", "params": [], "returns": [{"type": {"kind": "primitive", "name": "float64"}}]},
        {"name": "Perimeter", "params": [], "returns": [{"type": {"kind": "primitive", "name": "float64"}}]},
        {"name": "Describe", "params": [], "returns": [{"type": {"kind": "primitive", "name": "string"}}]}
      ]
    },
    {
      "type": "TypeDecl",
      "kind": "struct",
      "name": "Shape",
      "embedded": [],
      "fields": [
        {"name": "Color", "type": {"kind": "primitive", "name": "string"}}
      ],
      "methods": [
        {
          "type": "FuncDecl",
          "name": "Describe",
          "receiver": {"name": "s", "type": {"kind": "struct", "name": "Shape"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "string"}}]
        }
      ]
    },
    {
      "type": "TypeDecl",
      "kind": "struct",
      "name": "Circle",
      "embedded": [
        {"type": {"kind": "struct", "name": "Shape"}}
      ],
      "fields": [
        {"name": "Radius", "type": {"kind": "primitive", "name": "float64"}}
      ],
      "methods": [
        {
          "type": "FuncDecl",
          "name": "Area",
          "receiver": {"name": "c", "type": {"kind": "struct", "name": "Circle"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "float64"}}]
        },
        {
          "type": "FuncDecl",
          "name": "Perimeter",
          "receiver": {"name": "c", "type": {"kind": "struct", "name": "Circle"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "float64"}}]
        },
        {
          "type": "FuncDecl",
          "name": "Describe",
          "receiver": {"name": "c", "type": {"kind": "struct", "name": "Circle"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "string"}}]
        }
      ]
    },
    {
      "type": "TypeDecl",
      "kind": "struct",
      "name": "Rectangle",
      "embedded": [
        {"type": {"kind": "struct", "name": "Shape"}}
      ],
      "fields": [
        {"name": "Width", "type": {"kind": "primitive", "name": "float64"}},
        {"name": "Height", "type": {"kind": "primitive", "name": "float64"}}
      ],
      "methods": [
        {
          "type": "FuncDecl",
          "name": "Area",
          "receiver": {"name": "r", "type": {"kind": "struct", "name": "Rectangle"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "float64"}}]
        },
        {
          "type": "FuncDecl",
          "name": "Perimeter",
          "receiver": {"name": "r", "type": {"kind": "struct", "name": "Rectangle"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "float64"}}]
        },
        {
          "type": "FuncDecl",
          "name": "Describe",
          "receiver": {"name": "r", "type": {"kind": "struct", "name": "Rectangle"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "string"}}]
        }
      ]
    },
    {
      "type": "TypeDecl",
      "kind": "interface",
      "name": "Printer",
      "methods": [
        {"name": "Print", "params": [], "returns": []}
      ]
    },
    {
      "type": "TypeDecl",
      "kind": "struct",
      "name": "PrintableCircle",
      "embedded": [
        {"type": {"kind": "struct", "name": "Circle"}}
      ],
      "fields": [],
      "methods": [
        {
          "type": "FuncDecl",
          "name": "Print",
          "receiver": {"name": "pc", "type": {"kind": "struct", "name": "PrintableCircle"}},
          "params": [],
          "returns": []
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Single inheritance → struct embedding** -- embed the base struct as an anonymous field to inherit its fields and methods
2. **Multiple inheritance → multiple embeddings** -- embed each base as a separate anonymous field; pure-virtual bases become interface fields instead
3. **Abstract base class (has pure virtual methods) → interface + base struct** -- extract the pure virtual methods into a Go interface; keep data and default methods on a concrete base struct
4. **Virtual method override → method on child struct** -- Go method dispatch uses the concrete receiver type; the child method shadows the embedded method
5. **Base class constructor call → explicit field initialization** -- ` + "`" + `Shape(color)` + "`" + ` in init list becomes ` + "`" + `Shape: Shape{Color: color}` + "`" + ` in the composite literal
6. **` + "`" + `virtual` + "`" + ` destructor → no action** -- Go GC handles cleanup; if the destructor has logic, add a ` + "`" + `Close()` + "`" + ` method
7. **Diamond inheritance → flatten** -- embed each distinct ancestor once; resolve ambiguity by promoting only the needed fields
8. **Polymorphic function parameter ` + "`" + `const Shape&` + "`" + ` → interface parameter** -- accept the interface type to enable polymorphic dispatch
9. **` + "`" + `dynamic_cast<Derived*>(base)` + "`" + ` → type assertion ` + "`" + `base.(Derived)` + "`" + `** -- Go type assertions replace C++ RTTI casts
10. **Protected fields → unexported fields** on the embedded struct, accessible within the same package

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package shapes

import (
	"fmt"
	"math"
)

// ShapeInterface defines the contract for all shapes.
type ShapeInterface interface {
	Area() float64
	Perimeter() float64
	Describe() string
}

// Shape holds shared data for all shapes.
type Shape struct {
	Color string
}

// Describe returns a base description of the shape.
func (s Shape) Describe() string {
	return fmt.Sprintf("Shape(color=%s)", s.Color)
}

// Circle is a shape defined by a radius.
type Circle struct {
	Shape
	Radius float64
}

// NewCircle creates a Circle with the given color and radius.
func NewCircle(color string, radius float64) *Circle {
	return &Circle{
		Shape:  Shape{Color: color},
		Radius: radius,
	}
}

// Area returns the area of the circle.
func (c Circle) Area() float64 {
	return math.Pi * c.Radius * c.Radius
}

// Perimeter returns the circumference of the circle.
func (c Circle) Perimeter() float64 {
	return 2 * math.Pi * c.Radius
}

// Describe returns a formatted description of the circle.
func (c Circle) Describe() string {
	return fmt.Sprintf("Circle(color=%s, radius=%g)", c.Color, c.Radius)
}

// Rectangle is a shape defined by width and height.
type Rectangle struct {
	Shape
	Width  float64
	Height float64
}

// NewRectangle creates a Rectangle with the given dimensions.
func NewRectangle(color string, width, height float64) *Rectangle {
	return &Rectangle{
		Shape:  Shape{Color: color},
		Width:  width,
		Height: height,
	}
}

// Area returns the area of the rectangle.
func (r Rectangle) Area() float64 {
	return r.Width * r.Height
}

// Perimeter returns the perimeter of the rectangle.
func (r Rectangle) Perimeter() float64 {
	return 2 * (r.Width + r.Height)
}

// Describe returns a formatted description of the rectangle.
func (r Rectangle) Describe() string {
	return fmt.Sprintf("Rectangle(color=%s, w=%g, h=%g)", r.Color, r.Width, r.Height)
}

// Printer defines types that can print themselves.
type Printer interface {
	Print()
}

// PrintableCircle is a Circle that can print itself.
type PrintableCircle struct {
	Circle
}

// NewPrintableCircle creates a PrintableCircle.
func NewPrintableCircle(color string, radius float64) *PrintableCircle {
	return &PrintableCircle{
		Circle: *NewCircle(color, radius),
	}
}

// Print writes the circle's description to stdout.
func (pc PrintableCircle) Print() {
	fmt.Println(pc.Describe())
}

// Usage with polymorphism
func printArea(shape ShapeInterface) {
	fmt.Printf("%s area=%g\n", shape.Describe(), shape.Area())
}
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| ` + "`" + `class Dog : public Animal` + "`" + ` | ` + "`" + `type Dog struct { Animal }` + "`" + ` | ` + "`" + `Class{base_classes:[{name:"Animal", access:"public"}]}` + "`" + ` | ` + "`" + `TypeDecl{embedded:[{name:"Animal"}]}` + "`" + ` |
| Multiple inheritance | Multiple embedded structs | ` + "`" + `Class{base_classes:[...]}` + "`" + ` | ` + "`" + `TypeDecl{embedded:[...]}` + "`" + ` |
| Pure virtual base as second parent | Interface satisfaction | ` + "`" + `BaseClass` + "`" + ` + ` + "`" + `Method{pure:true}` + "`" + ` | ` + "`" + `TypeDecl{kind:"interface"}` + "`" + ` |
| Base constructor call in init list | Composite literal field | ` + "`" + `Constructor{init_list:[{member:"Shape"}]}` + "`" + ` | ` + "`" + `CompositeLitExpr` + "`" + ` |
| ` + "`" + `virtual ~Shape() = default` + "`" + ` | (removed -- GC) | ` + "`" + `Destructor{virtual:true, default:true}` + "`" + ` | (none) |
| ` + "`" + `override` + "`" + ` keyword | Method shadows embedded method | ` + "`" + `Method{override:true}` + "`" + ` | ` + "`" + `FuncDecl` + "`" + ` with same name as embedded |
| ` + "`" + `const Shape&` + "`" + ` parameter | ` + "`" + `ShapeInterface` + "`" + ` parameter | ` + "`" + `Param{type:{name:"Shape"}, reference:true}` + "`" + ` | ` + "`" + `Param{type:{kind:"interface"}}` + "`" + ` |
| ` + "`" + `dynamic_cast<Circle*>(shape)` + "`" + ` | ` + "`" + `shape.(*Circle)` + "`" + ` type assertion | ` + "`" + `CastExpr{kind:"dynamic"}` + "`" + ` | ` + "`" + `TypeAssertExpr` + "`" + ` |
| Diamond inheritance | Flatten, embed once | Multiple ` + "`" + `BaseClass` + "`" + ` paths | Single ` + "`" + `Embedded` + "`" + ` entry |
| Protected member | Unexported (same package) | ` + "`" + `Field{access:"protected"}` + "`" + ` | ` + "`" + `FieldDecl{name:"lowercase"}` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/oop/virtual_interfaces.md",
			Body: `# Virtual Methods to Interfaces

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <string>
#include <vector>
#include <memory>

// Pure virtual base class (abstract)
class Serializable {
public:
    virtual ~Serializable() = default;
    virtual std::string serialize() const = 0;
    virtual void deserialize(const std::string& data) = 0;
};

// Abstract event handler
class EventHandler {
public:
    virtual ~EventHandler() = default;
    virtual void onEvent(const std::string& event) = 0;
    virtual bool canHandle(const std::string& event) const = 0;

    // Default implementation (non-pure virtual)
    virtual std::string handlerName() const {
        return "unnamed";
    }
};

// Concrete implementation: ClickHandler
class ClickHandler : public EventHandler {
public:
    void onEvent(const std::string& event) override {
        lastEvent_ = event;
        clickCount_++;
    }

    bool canHandle(const std::string& event) const override {
        return event == "click" || event == "doubleclick";
    }

    std::string handlerName() const override {
        return "ClickHandler";
    }

    int getClickCount() const { return clickCount_; }

private:
    std::string lastEvent_;
    int clickCount_ = 0;
};

// Concrete implementation: KeyHandler
class KeyHandler : public EventHandler {
public:
    explicit KeyHandler(const std::string& targetKey)
        : targetKey_(targetKey) {}

    void onEvent(const std::string& event) override {
        if (event == targetKey_) {
            pressed_ = true;
        }
    }

    bool canHandle(const std::string& event) const override {
        return event == targetKey_;
    }

    std::string handlerName() const override {
        return "KeyHandler(" + targetKey_ + ")";
    }

    bool isPressed() const { return pressed_; }

private:
    std::string targetKey_;
    bool pressed_ = false;
};

// Mixed class: implements Serializable AND extends EventHandler
class LoggingHandler : public EventHandler, public Serializable {
public:
    void onEvent(const std::string& event) override {
        log_.push_back(event);
    }

    bool canHandle(const std::string& event) const override {
        return true; // handles all events
    }

    std::string handlerName() const override {
        return "LoggingHandler";
    }

    std::string serialize() const override {
        std::string result;
        for (const auto& entry : log_) {
            result += entry + "\n";
        }
        return result;
    }

    void deserialize(const std::string& data) override {
        log_.clear();
        // parse newline-separated entries back into log
        size_t pos = 0;
        size_t found;
        while ((found = data.find('\n', pos)) != std::string::npos) {
            log_.push_back(data.substr(pos, found - pos));
            pos = found + 1;
        }
    }

private:
    std::vector<std::string> log_;
};

// Polymorphic dispatch
void dispatchEvent(const std::vector<std::unique_ptr<EventHandler>>& handlers,
                   const std::string& event) {
    for (const auto& handler : handlers) {
        if (handler->canHandle(event)) {
            handler->onEvent(event);
        }
    }
}

// dynamic_cast for runtime type check
void trySerialize(EventHandler* handler) {
    if (auto* s = dynamic_cast<Serializable*>(handler)) {
        std::cout << s->serialize() << std::endl;
    }
}
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "Class",
      "kind": "class",
      "name": "Serializable",
      "base_classes": [],
      "template_params": [],
      "fields": [],
      "constructors": [],
      "destructor": {"virtual": true, "default": true, "access": "public"},
      "methods": [
        {
          "name": "serialize",
          "return_type": {"name": "std::string"},
          "params": [],
          "const": true,
          "virtual": true,
          "pure": true,
          "override": false,
          "access": "public"
        },
        {
          "name": "deserialize",
          "return_type": {"name": "void"},
          "params": [{"name": "data", "type": {"name": "std::string", "const": true, "reference": true}}],
          "const": false,
          "virtual": true,
          "pure": true,
          "override": false,
          "access": "public"
        }
      ],
      "operators": []
    },
    {
      "type": "Class",
      "kind": "class",
      "name": "EventHandler",
      "base_classes": [],
      "template_params": [],
      "fields": [],
      "constructors": [],
      "destructor": {"virtual": true, "default": true, "access": "public"},
      "methods": [
        {
          "name": "onEvent",
          "return_type": {"name": "void"},
          "params": [{"name": "event", "type": {"name": "std::string", "const": true, "reference": true}}],
          "const": false,
          "virtual": true,
          "pure": true,
          "override": false,
          "access": "public"
        },
        {
          "name": "canHandle",
          "return_type": {"name": "bool"},
          "params": [{"name": "event", "type": {"name": "std::string", "const": true, "reference": true}}],
          "const": true,
          "virtual": true,
          "pure": true,
          "override": false,
          "access": "public"
        },
        {
          "name": "handlerName",
          "return_type": {"name": "std::string"},
          "params": [],
          "const": true,
          "virtual": true,
          "pure": false,
          "override": false,
          "access": "public"
        }
      ],
      "operators": []
    },
    {
      "type": "Class",
      "kind": "class",
      "name": "ClickHandler",
      "base_classes": [
        {"name": "EventHandler", "access": "public"}
      ],
      "template_params": [],
      "fields": [
        {"name": "lastEvent_", "type": {"name": "std::string"}, "access": "private"},
        {"name": "clickCount_", "type": {"name": "int"}, "access": "private"}
      ],
      "constructors": [],
      "destructor": null,
      "methods": [
        {"name": "onEvent", "return_type": {"name": "void"}, "params": [{"name": "event", "type": {"name": "std::string", "const": true, "reference": true}}], "const": false, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "canHandle", "return_type": {"name": "bool"}, "params": [{"name": "event", "type": {"name": "std::string", "const": true, "reference": true}}], "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "handlerName", "return_type": {"name": "std::string"}, "params": [], "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "getClickCount", "return_type": {"name": "int"}, "params": [], "const": true, "virtual": false, "pure": false, "override": false, "access": "public"}
      ],
      "operators": []
    },
    {
      "type": "Class",
      "kind": "class",
      "name": "KeyHandler",
      "base_classes": [
        {"name": "EventHandler", "access": "public"}
      ],
      "template_params": [],
      "fields": [
        {"name": "targetKey_", "type": {"name": "std::string"}, "access": "private"},
        {"name": "pressed_", "type": {"name": "bool"}, "access": "private"}
      ],
      "constructors": [
        {
          "params": [{"name": "targetKey", "type": {"name": "std::string", "const": true, "reference": true}}],
          "init_list": [{"member": "targetKey_", "value": "targetKey"}],
          "explicit": true,
          "access": "public"
        }
      ],
      "destructor": null,
      "methods": [
        {"name": "onEvent", "return_type": {"name": "void"}, "params": [{"name": "event", "type": {"name": "std::string", "const": true, "reference": true}}], "const": false, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "canHandle", "return_type": {"name": "bool"}, "params": [{"name": "event", "type": {"name": "std::string", "const": true, "reference": true}}], "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "handlerName", "return_type": {"name": "std::string"}, "params": [], "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "isPressed", "return_type": {"name": "bool"}, "params": [], "const": true, "virtual": false, "pure": false, "override": false, "access": "public"}
      ],
      "operators": []
    },
    {
      "type": "Class",
      "kind": "class",
      "name": "LoggingHandler",
      "base_classes": [
        {"name": "EventHandler", "access": "public"},
        {"name": "Serializable", "access": "public"}
      ],
      "template_params": [],
      "fields": [
        {"name": "log_", "type": {"name": "std::vector", "template_args": [{"name": "std::string"}]}, "access": "private"}
      ],
      "constructors": [],
      "destructor": null,
      "methods": [
        {"name": "onEvent", "return_type": {"name": "void"}, "params": [{"name": "event", "type": {"name": "std::string", "const": true, "reference": true}}], "const": false, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "canHandle", "return_type": {"name": "bool"}, "params": [{"name": "event", "type": {"name": "std::string", "const": true, "reference": true}}], "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "handlerName", "return_type": {"name": "std::string"}, "params": [], "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "serialize", "return_type": {"name": "std::string"}, "params": [], "const": true, "virtual": true, "pure": false, "override": true, "access": "public"},
        {"name": "deserialize", "return_type": {"name": "void"}, "params": [{"name": "data", "type": {"name": "std::string", "const": true, "reference": true}}], "const": false, "virtual": true, "pure": false, "override": true, "access": "public"}
      ],
      "operators": []
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Package",
  "declarations": [
    {
      "type": "TypeDecl",
      "kind": "interface",
      "name": "Serializable",
      "methods": [
        {
          "name": "Serialize",
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "string"}}]
        },
        {
          "name": "Deserialize",
          "params": [{"name": "data", "type": {"kind": "primitive", "name": "string"}}],
          "returns": [{"type": {"kind": "primitive", "name": "error"}}]
        }
      ]
    },
    {
      "type": "TypeDecl",
      "kind": "interface",
      "name": "EventHandler",
      "methods": [
        {
          "name": "OnEvent",
          "params": [{"name": "event", "type": {"kind": "primitive", "name": "string"}}],
          "returns": []
        },
        {
          "name": "CanHandle",
          "params": [{"name": "event", "type": {"kind": "primitive", "name": "string"}}],
          "returns": [{"type": {"kind": "primitive", "name": "bool"}}]
        },
        {
          "name": "HandlerName",
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "string"}}]
        }
      ]
    },
    {
      "type": "TypeDecl",
      "kind": "struct",
      "name": "ClickHandler",
      "embedded": [],
      "fields": [
        {"name": "lastEvent", "type": {"kind": "primitive", "name": "string"}},
        {"name": "clickCount", "type": {"kind": "primitive", "name": "int"}}
      ],
      "methods": [
        {
          "type": "FuncDecl",
          "name": "OnEvent",
          "receiver": {"name": "h", "type": {"kind": "pointer", "name": "ClickHandler"}},
          "params": [{"name": "event", "type": {"kind": "primitive", "name": "string"}}],
          "returns": []
        },
        {
          "type": "FuncDecl",
          "name": "CanHandle",
          "receiver": {"name": "h", "type": {"kind": "struct", "name": "ClickHandler"}},
          "params": [{"name": "event", "type": {"kind": "primitive", "name": "string"}}],
          "returns": [{"type": {"kind": "primitive", "name": "bool"}}]
        },
        {
          "type": "FuncDecl",
          "name": "HandlerName",
          "receiver": {"name": "h", "type": {"kind": "struct", "name": "ClickHandler"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "string"}}]
        },
        {
          "type": "FuncDecl",
          "name": "ClickCount",
          "receiver": {"name": "h", "type": {"kind": "struct", "name": "ClickHandler"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "int"}}]
        }
      ]
    },
    {
      "type": "TypeDecl",
      "kind": "struct",
      "name": "KeyHandler",
      "embedded": [],
      "fields": [
        {"name": "targetKey", "type": {"kind": "primitive", "name": "string"}},
        {"name": "pressed", "type": {"kind": "primitive", "name": "bool"}}
      ],
      "methods": [
        {
          "type": "FuncDecl",
          "name": "OnEvent",
          "receiver": {"name": "h", "type": {"kind": "pointer", "name": "KeyHandler"}},
          "params": [{"name": "event", "type": {"kind": "primitive", "name": "string"}}],
          "returns": []
        },
        {
          "type": "FuncDecl",
          "name": "CanHandle",
          "receiver": {"name": "h", "type": {"kind": "struct", "name": "KeyHandler"}},
          "params": [{"name": "event", "type": {"kind": "primitive", "name": "string"}}],
          "returns": [{"type": {"kind": "primitive", "name": "bool"}}]
        },
        {
          "type": "FuncDecl",
          "name": "HandlerName",
          "receiver": {"name": "h", "type": {"kind": "struct", "name": "KeyHandler"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "string"}}]
        },
        {
          "type": "FuncDecl",
          "name": "IsPressed",
          "receiver": {"name": "h", "type": {"kind": "struct", "name": "KeyHandler"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "bool"}}]
        }
      ]
    },
    {
      "type": "TypeDecl",
      "kind": "struct",
      "name": "LoggingHandler",
      "embedded": [],
      "fields": [
        {"name": "log", "type": {"kind": "slice", "elem_type": {"kind": "primitive", "name": "string"}}}
      ],
      "methods": [
        {
          "type": "FuncDecl",
          "name": "OnEvent",
          "receiver": {"name": "h", "type": {"kind": "pointer", "name": "LoggingHandler"}},
          "params": [{"name": "event", "type": {"kind": "primitive", "name": "string"}}],
          "returns": []
        },
        {
          "type": "FuncDecl",
          "name": "CanHandle",
          "receiver": {"name": "h", "type": {"kind": "struct", "name": "LoggingHandler"}},
          "params": [{"name": "event", "type": {"kind": "primitive", "name": "string"}}],
          "returns": [{"type": {"kind": "primitive", "name": "bool"}}]
        },
        {
          "type": "FuncDecl",
          "name": "HandlerName",
          "receiver": {"name": "h", "type": {"kind": "struct", "name": "LoggingHandler"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "string"}}]
        },
        {
          "type": "FuncDecl",
          "name": "Serialize",
          "receiver": {"name": "h", "type": {"kind": "struct", "name": "LoggingHandler"}},
          "params": [],
          "returns": [{"type": {"kind": "primitive", "name": "string"}}]
        },
        {
          "type": "FuncDecl",
          "name": "Deserialize",
          "receiver": {"name": "h", "type": {"kind": "pointer", "name": "LoggingHandler"}},
          "params": [{"name": "data", "type": {"kind": "primitive", "name": "string"}}],
          "returns": [{"type": {"kind": "primitive", "name": "error"}}]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Pure virtual class (all methods ` + "`" + `= 0` + "`" + `, no data) → Go ` + "`" + `interface` + "`" + `** -- a class with only pure virtual methods and no fields maps directly to an interface
2. **Mixed virtual class (pure + non-pure virtual, or has data) → interface + base struct** -- extract the pure virtual contract into an interface; keep default implementations and data fields on a concrete struct that can be embedded
3. **` + "`" + `virtual` + "`" + ` method with default body → method on base struct** -- provides a default implementation that embedded structs inherit unless they define their own
4. **` + "`" + `override` + "`" + ` method → method on concrete struct** -- the concrete struct defines its own method with the same name, satisfying the interface
5. **Virtual destructor → remove** -- Go has no destructors; the virtual destructor exists only to enable safe polymorphic deletion in C++
6. **` + "`" + `dynamic_cast<T*>(ptr)` + "`" + ` → type assertion ` + "`" + `ptr.(T)` + "`" + `** -- returns ` + "`" + `(value, ok)` + "`" + ` for safe checked casts
7. **` + "`" + `static_cast<T*>(ptr)` + "`" + ` on known types → direct type assertion ` + "`" + `ptr.(T)` + "`" + `** -- same mechanism, but the safety guarantee comes from the programmer
8. **` + "`" + `typeid(obj)` + "`" + ` → type switch** -- ` + "`" + `switch v := obj.(type) { case T: ... }` + "`" + ` replaces runtime type identification
9. **Class implementing multiple abstract bases → struct satisfying multiple interfaces** -- Go's implicit interface satisfaction means the struct just needs to define all required methods
10. **` + "`" + `void` + "`" + ` return on ` + "`" + `deserialize` + "`" + ` with exceptions → ` + "`" + `error` + "`" + ` return** -- replace throw-based error signaling with explicit error returns

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package events

import (
	"fmt"
	"strings"
)

// Serializable defines types that can marshal/unmarshal themselves.
type Serializable interface {
	Serialize() string
	Deserialize(data string) error
}

// EventHandler defines the contract for handling events.
type EventHandler interface {
	OnEvent(event string)
	CanHandle(event string) bool
	HandlerName() string
}

// ClickHandler tracks click events.
type ClickHandler struct {
	lastEvent  string
	clickCount int
}

// OnEvent records the click event.
func (h *ClickHandler) OnEvent(event string) {
	h.lastEvent = event
	h.clickCount++
}

// CanHandle returns true for click and doubleclick events.
func (h ClickHandler) CanHandle(event string) bool {
	return event == "click" || event == "doubleclick"
}

// HandlerName returns the handler's identifier.
func (h ClickHandler) HandlerName() string {
	return "ClickHandler"
}

// ClickCount returns the total number of click events received.
func (h ClickHandler) ClickCount() int {
	return h.clickCount
}

// KeyHandler tracks a specific key event.
type KeyHandler struct {
	targetKey string
	pressed   bool
}

// NewKeyHandler creates a KeyHandler for the given key.
func NewKeyHandler(targetKey string) *KeyHandler {
	return &KeyHandler{targetKey: targetKey}
}

// OnEvent marks the key as pressed if it matches the target.
func (h *KeyHandler) OnEvent(event string) {
	if event == h.targetKey {
		h.pressed = true
	}
}

// CanHandle returns true if the event matches the target key.
func (h KeyHandler) CanHandle(event string) bool {
	return event == h.targetKey
}

// HandlerName returns the handler's identifier with its target key.
func (h KeyHandler) HandlerName() string {
	return fmt.Sprintf("KeyHandler(%s)", h.targetKey)
}

// IsPressed returns whether the target key has been pressed.
func (h KeyHandler) IsPressed() bool {
	return h.pressed
}

// LoggingHandler records all events and supports serialization.
// Satisfies both EventHandler and Serializable interfaces.
type LoggingHandler struct {
	log []string
}

// OnEvent appends the event to the log.
func (h *LoggingHandler) OnEvent(event string) {
	h.log = append(h.log, event)
}

// CanHandle returns true for all events.
func (h LoggingHandler) CanHandle(event string) bool {
	return true
}

// HandlerName returns the handler's identifier.
func (h LoggingHandler) HandlerName() string {
	return "LoggingHandler"
}

// Serialize returns the log as newline-separated entries.
func (h LoggingHandler) Serialize() string {
	return strings.Join(h.log, "\n") + "\n"
}

// Deserialize parses newline-separated entries back into the log.
func (h *LoggingHandler) Deserialize(data string) error {
	h.log = nil
	for _, line := range strings.Split(strings.TrimRight(data, "\n"), "\n") {
		if line != "" {
			h.log = append(h.log, line)
		}
	}
	return nil
}

// DispatchEvent sends the event to all handlers that can handle it.
func DispatchEvent(handlers []EventHandler, event string) {
	for _, handler := range handlers {
		if handler.CanHandle(event) {
			handler.OnEvent(event)
		}
	}
}

// TrySerialize prints serialized output if the handler supports it.
func TrySerialize(handler EventHandler) {
	if s, ok := handler.(Serializable); ok {
		fmt.Println(s.Serialize())
	}
}
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| Pure virtual class (no fields) | ` + "`" + `interface` + "`" + ` | ` + "`" + `Class{methods:[{pure:true}], fields:[]}` + "`" + ` | ` + "`" + `TypeDecl{kind:"interface"}` + "`" + ` |
| Virtual method ` + "`" + `= 0` + "`" + ` | Interface method | ` + "`" + `Method{virtual:true, pure:true}` + "`" + ` | Method in ` + "`" + `TypeDecl{kind:"interface"}` + "`" + ` |
| Non-pure virtual with body | Method on base struct | ` + "`" + `Method{virtual:true, pure:false}` + "`" + ` | ` + "`" + `FuncDecl` + "`" + ` with receiver |
| ` + "`" + `override` + "`" + ` on concrete class | Method satisfying interface | ` + "`" + `Method{override:true}` + "`" + ` | ` + "`" + `FuncDecl` + "`" + ` with receiver |
| ` + "`" + `virtual ~Destructor() = default` + "`" + ` | (removed -- GC) | ` + "`" + `Destructor{virtual:true}` + "`" + ` | (none) |
| ` + "`" + `dynamic_cast<T*>(ptr)` + "`" + ` | ` + "`" + `ptr.(T)` + "`" + ` type assertion | ` + "`" + `CastExpr{kind:"dynamic"}` + "`" + ` | ` + "`" + `TypeAssertExpr` + "`" + ` |
| ` + "`" + `typeid(obj)` + "`" + ` | ` + "`" + `switch v := obj.(type)` + "`" + ` | ` + "`" + `TypeIdExpr` + "`" + ` | ` + "`" + `TypeSwitchStmt` + "`" + ` |
| Class with multiple virtual bases | Struct satisfying multiple interfaces | ` + "`" + `Class{base_classes:[...]}` + "`" + ` (all pure) | ` + "`" + `TypeDecl{kind:"struct"}` + "`" + ` with methods |
| ` + "`" + `void` + "`" + ` return + exception | ` + "`" + `error` + "`" + ` return | ` + "`" + `Method{return_type:"void"}` + "`" + ` + throw | ` + "`" + `FuncDecl{returns:["error"]}` + "`" + ` |
| ` + "`" + `std::vector<unique_ptr<Base>>` + "`" + ` | ` + "`" + `[]Interface` + "`" + ` | ` + "`" + `TypeRef{vector<unique_ptr>}` + "`" + ` | ` + "`" + `TypeRef{kind:"slice", elem:"interface"}` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/patterns/factory.md",
			Body: `# Factory Pattern to Interfaces and Constructor Functions

> C++ factory method and abstract factory patterns mapped to Go interfaces with constructor functions and registration maps.

---

## 1. Factory Method: Virtual ` + "`" + `create()` + "`" + ` to Interface Return

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <string>
#include <cmath>
#include <memory>
#include <stdexcept>

class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual double perimeter() const = 0;
    virtual std::string name() const = 0;
};

class Circle : public Shape {
    double radius;
public:
    explicit Circle(double r) : radius(r) {}
    double area() const override { return M_PI * radius * radius; }
    double perimeter() const override { return 2 * M_PI * radius; }
    std::string name() const override { return "Circle"; }
};

class Rectangle : public Shape {
    double width, height;
public:
    Rectangle(double w, double h) : width(w), height(h) {}
    double area() const override { return width * height; }
    double perimeter() const override { return 2 * (width + height); }
    std::string name() const override { return "Rectangle"; }
};

class Triangle : public Shape {
    double a, b, c;
public:
    Triangle(double a, double b, double c) : a(a), b(b), c(c) {}
    double area() const override {
        double s = (a + b + c) / 2;
        return std::sqrt(s * (s-a) * (s-b) * (s-c));
    }
    double perimeter() const override { return a + b + c; }
    std::string name() const override { return "Triangle"; }
};

std::unique_ptr<Shape> createShape(const std::string& type, double p1, double p2 = 0, double p3 = 0) {
    if (type == "circle") {
        return std::make_unique<Circle>(p1);
    } else if (type == "rectangle") {
        return std::make_unique<Rectangle>(p1, p2);
    } else if (type == "triangle") {
        return std::make_unique<Triangle>(p1, p2, p3);
    }
    throw std::invalid_argument("Unknown shape: " + type);
}

int main() {
    auto c = createShape("circle", 5.0);
    auto r = createShape("rectangle", 4.0, 6.0);
    auto t = createShape("triangle", 3.0, 4.0, 5.0);

    std::cout << c->name() << " area: " << c->area() << std::endl;
    std::cout << r->name() << " area: " << r->area() << std::endl;
    std::cout << t->name() << " perimeter: " << t->perimeter() << std::endl;
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "ClassDef",
      "name": "Shape",
      "isAbstract": true,
      "members": {
        "public": [
          { "type": "Destructor", "isVirtual": true, "defaulted": true },
          { "type": "PureVirtualMethod", "name": "area", "returnType": "double", "isConst": true },
          { "type": "PureVirtualMethod", "name": "perimeter", "returnType": "double", "isConst": true },
          { "type": "PureVirtualMethod", "name": "name", "returnType": "std::string", "isConst": true }
        ]
      }
    },
    {
      "type": "ClassDef",
      "name": "Circle",
      "bases": [{ "name": "Shape", "access": "public" }],
      "members": {
        "private": [
          { "type": "FieldDecl", "name": "radius", "fieldType": "double" }
        ],
        "public": [
          { "type": "Constructor", "isExplicit": true, "params": [{ "name": "r", "paramType": "double" }], "initList": [{ "member": "radius", "value": { "type": "NameExpr", "name": "r" } }] },
          { "type": "MethodDef", "name": "area", "isOverride": true, "isConst": true, "returnType": "double" },
          { "type": "MethodDef", "name": "perimeter", "isOverride": true, "isConst": true, "returnType": "double" },
          { "type": "MethodDef", "name": "name", "isOverride": true, "isConst": true, "returnType": "std::string" }
        ]
      }
    },
    {
      "type": "ClassDef",
      "name": "Rectangle",
      "bases": [{ "name": "Shape", "access": "public" }],
      "members": {
        "private": [
          { "type": "FieldDecl", "name": "width", "fieldType": "double" },
          { "type": "FieldDecl", "name": "height", "fieldType": "double" }
        ],
        "public": [
          { "type": "Constructor", "params": [{ "name": "w", "paramType": "double" }, { "name": "h", "paramType": "double" }] },
          { "type": "MethodDef", "name": "area", "isOverride": true, "isConst": true, "returnType": "double" },
          { "type": "MethodDef", "name": "perimeter", "isOverride": true, "isConst": true, "returnType": "double" },
          { "type": "MethodDef", "name": "name", "isOverride": true, "isConst": true, "returnType": "std::string" }
        ]
      }
    },
    {
      "type": "ClassDef",
      "name": "Triangle",
      "bases": [{ "name": "Shape", "access": "public" }],
      "members": {
        "private": [
          { "type": "FieldDecl", "name": "a", "fieldType": "double" },
          { "type": "FieldDecl", "name": "b", "fieldType": "double" },
          { "type": "FieldDecl", "name": "c", "fieldType": "double" }
        ],
        "public": [
          { "type": "Constructor", "params": [{ "name": "a", "paramType": "double" }, { "name": "b", "paramType": "double" }, { "name": "c", "paramType": "double" }] },
          { "type": "MethodDef", "name": "area", "isOverride": true, "isConst": true, "returnType": "double" },
          { "type": "MethodDef", "name": "perimeter", "isOverride": true, "isConst": true, "returnType": "double" },
          { "type": "MethodDef", "name": "name", "isOverride": true, "isConst": true, "returnType": "std::string" }
        ]
      }
    },
    {
      "type": "FunctionDef",
      "name": "createShape",
      "params": [
        { "name": "type", "paramType": "const std::string&" },
        { "name": "p1", "paramType": "double" },
        { "name": "p2", "paramType": "double", "default": { "type": "FloatLiteral", "value": 0 } },
        { "name": "p3", "paramType": "double", "default": { "type": "FloatLiteral", "value": 0 } }
      ],
      "returnType": "std::unique_ptr<Shape>",
      "body": [
        {
          "type": "IfChain",
          "branches": [
            { "condition": { "type": "BinaryOp", "op": "==", "left": { "type": "NameExpr", "name": "type" }, "right": { "type": "StringLiteral", "value": "circle" } }, "body": [{ "type": "ReturnStmt", "value": { "type": "CallExpr", "callee": "std::make_unique<Circle>", "args": [{ "type": "NameExpr", "name": "p1" }] } }] },
            { "condition": { "type": "BinaryOp", "op": "==", "left": { "type": "NameExpr", "name": "type" }, "right": { "type": "StringLiteral", "value": "rectangle" } }, "body": [{ "type": "ReturnStmt", "value": { "type": "CallExpr", "callee": "std::make_unique<Rectangle>", "args": [{ "type": "NameExpr", "name": "p1" }, { "type": "NameExpr", "name": "p2" }] } }] },
            { "condition": { "type": "BinaryOp", "op": "==", "left": { "type": "NameExpr", "name": "type" }, "right": { "type": "StringLiteral", "value": "triangle" } }, "body": [{ "type": "ReturnStmt", "value": { "type": "CallExpr", "callee": "std::make_unique<Triangle>", "args": [{ "type": "NameExpr", "name": "p1" }, { "type": "NameExpr", "name": "p2" }, { "type": "NameExpr", "name": "p3" }] } }] }
          ]
        },
        { "type": "ThrowStmt", "expr": { "type": "ConstructExpr", "className": "std::invalid_argument" } }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["fmt", "math"],
  "interfaces": [
    {
      "type": "Interface",
      "name": "Shape",
      "methods": [
        { "name": "Area", "returnType": "float64" },
        { "name": "Perimeter", "returnType": "float64" },
        { "name": "Name", "returnType": "string" }
      ]
    }
  ],
  "types": [
    {
      "type": "Struct",
      "name": "Circle",
      "fields": [{ "name": "Radius", "fieldType": "float64" }],
      "implements": "Shape"
    },
    {
      "type": "Struct",
      "name": "Rectangle",
      "fields": [
        { "name": "Width", "fieldType": "float64" },
        { "name": "Height", "fieldType": "float64" }
      ],
      "implements": "Shape"
    },
    {
      "type": "Struct",
      "name": "Triangle",
      "fields": [
        { "name": "A", "fieldType": "float64" },
        { "name": "B", "fieldType": "float64" },
        { "name": "C", "fieldType": "float64" }
      ],
      "implements": "Shape"
    }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "NewCircle",
      "params": [{ "name": "radius", "paramType": "float64" }],
      "returnType": "Shape",
      "body": [{ "type": "Return", "value": { "type": "AddressOf", "operand": { "type": "StructLiteral", "structType": "Circle", "fields": { "Radius": { "type": "Ref", "name": "radius" } } } } }]
    },
    {
      "type": "Func",
      "name": "NewRectangle",
      "params": [
        { "name": "width", "paramType": "float64" },
        { "name": "height", "paramType": "float64" }
      ],
      "returnType": "Shape",
      "body": [{ "type": "Return", "value": { "type": "AddressOf", "operand": { "type": "StructLiteral", "structType": "Rectangle" } } }]
    },
    {
      "type": "Func",
      "name": "NewTriangle",
      "params": [
        { "name": "a", "paramType": "float64" },
        { "name": "b", "paramType": "float64" },
        { "name": "c", "paramType": "float64" }
      ],
      "returnType": "Shape",
      "body": [{ "type": "Return", "value": { "type": "AddressOf", "operand": { "type": "StructLiteral", "structType": "Triangle" } } }]
    },
    {
      "type": "Func",
      "name": "CreateShape",
      "params": [
        { "name": "shapeType", "paramType": "string" },
        { "name": "params", "paramType": "...float64" }
      ],
      "returnType": "(Shape, error)",
      "body": [
        {
          "type": "Switch",
          "expr": { "type": "Ref", "name": "shapeType" },
          "cases": [
            { "value": { "type": "Literal", "value": "circle" }, "body": [{ "type": "Return", "values": [{ "type": "Call", "func": "NewCircle", "args": [{ "type": "Index", "base": "params", "index": 0 }] }, { "type": "Nil" }] }] },
            { "value": { "type": "Literal", "value": "rectangle" }, "body": [{ "type": "Return", "values": [{ "type": "Call", "func": "NewRectangle", "args": [{ "type": "Index", "base": "params", "index": 0 }, { "type": "Index", "base": "params", "index": 1 }] }, { "type": "Nil" }] }] },
            { "value": { "type": "Literal", "value": "triangle" }, "body": [{ "type": "Return", "values": [{ "type": "Call", "func": "NewTriangle", "args": [{ "type": "Index", "base": "params", "index": 0 }, { "type": "Index", "base": "params", "index": 1 }, { "type": "Index", "base": "params", "index": 2 }] }, { "type": "Nil" }] }] }
          ],
          "default": [{ "type": "Return", "values": [{ "type": "Nil" }, { "type": "Call", "func": "fmt.Errorf", "args": [{ "type": "Literal", "value": "unknown shape: %s" }, { "type": "Ref", "name": "shapeType" }] }] }]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Abstract class with pure virtuals**: Maps to a Go ` + "`" + `interface` + "`" + `. Each pure virtual method becomes an interface method.
2. **Concrete classes**: Map to structs that implement the interface through methods.
3. **Virtual destructor**: Dropped. Go's garbage collector handles memory. If resources need cleanup, add a ` + "`" + `Close() error` + "`" + ` method to the interface.
4. **` + "`" + `override` + "`" + ` keyword**: Dropped. Go's implicit interface satisfaction replaces explicit override declarations.
5. **Constructors**: Each class gets a ` + "`" + `NewXxx` + "`" + ` factory function returning the interface type.
6. **` + "`" + `std::unique_ptr<Base>` + "`" + `**: Maps to the interface type directly. Go interfaces are already reference-like (they hold a pointer internally for pointer receivers).
7. **Factory function**: ` + "`" + `createShape` + "`" + ` becomes ` + "`" + `CreateShape` + "`" + ` with a ` + "`" + `switch` + "`" + ` statement. The ` + "`" + `throw` + "`" + ` becomes an error return.
8. **Default parameters**: Handled via variadic ` + "`" + `...float64` + "`" + ` or separate factory functions per shape.
9. **` + "`" + `explicit` + "`" + ` keyword**: Dropped. Go constructors are always explicit (named functions).

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"math"
)

type Shape interface {
	Area() float64
	Perimeter() float64
	Name() string
}

type Circle struct {
	Radius float64
}

func NewCircle(radius float64) Shape {
	return &Circle{Radius: radius}
}

func (c *Circle) Area() float64 {
	return math.Pi * c.Radius * c.Radius
}

func (c *Circle) Perimeter() float64 {
	return 2 * math.Pi * c.Radius
}

func (c *Circle) Name() string {
	return "Circle"
}

type Rectangle struct {
	Width  float64
	Height float64
}

func NewRectangle(width, height float64) Shape {
	return &Rectangle{Width: width, Height: height}
}

func (r *Rectangle) Area() float64 {
	return r.Width * r.Height
}

func (r *Rectangle) Perimeter() float64 {
	return 2 * (r.Width + r.Height)
}

func (r *Rectangle) Name() string {
	return "Rectangle"
}

type Triangle struct {
	A float64
	B float64
	C float64
}

func NewTriangle(a, b, c float64) Shape {
	return &Triangle{A: a, B: b, C: c}
}

func (t *Triangle) Area() float64 {
	s := (t.A + t.B + t.C) / 2
	return math.Sqrt(s * (s - t.A) * (s - t.B) * (s - t.C))
}

func (t *Triangle) Perimeter() float64 {
	return t.A + t.B + t.C
}

func (t *Triangle) Name() string {
	return "Triangle"
}

func CreateShape(shapeType string, params ...float64) (Shape, error) {
	switch shapeType {
	case "circle":
		return NewCircle(params[0]), nil
	case "rectangle":
		return NewRectangle(params[0], params[1]), nil
	case "triangle":
		return NewTriangle(params[0], params[1], params[2]), nil
	default:
		return nil, fmt.Errorf("unknown shape: %s", shapeType)
	}
}

func main() {
	c, _ := CreateShape("circle", 5.0)
	r, _ := CreateShape("rectangle", 4.0, 6.0)
	t, _ := CreateShape("triangle", 3.0, 4.0, 5.0)

	fmt.Printf("%s area: %.2f\n", c.Name(), c.Area())
	fmt.Printf("%s area: %.2f\n", r.Name(), r.Area())
	fmt.Printf("%s perimeter: %.2f\n", t.Name(), t.Perimeter())
}
` + "`" + `` + "`" + `` + "`" + `

---

## 2. Registration Pattern: Map of Factory Functions

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <string>
#include <map>
#include <memory>
#include <functional>

class Plugin {
public:
    virtual ~Plugin() = default;
    virtual std::string name() const = 0;
    virtual void execute() = 0;
};

class PluginRegistry {
public:
    using FactoryFunc = std::function<std::unique_ptr<Plugin>()>;

    static PluginRegistry& instance() {
        static PluginRegistry registry;
        return registry;
    }

    void registerPlugin(const std::string& name, FactoryFunc factory) {
        factories[name] = std::move(factory);
    }

    std::unique_ptr<Plugin> create(const std::string& name) {
        auto it = factories.find(name);
        if (it != factories.end()) {
            return it->second();
        }
        return nullptr;
    }

    std::vector<std::string> listPlugins() const {
        std::vector<std::string> names;
        for (const auto& [name, _] : factories) {
            names.push_back(name);
        }
        return names;
    }

private:
    PluginRegistry() = default;
    std::map<std::string, FactoryFunc> factories;
};

// Concrete plugins
class LogPlugin : public Plugin {
public:
    std::string name() const override { return "log"; }
    void execute() override { std::cout << "Logging..." << std::endl; }
};

class MetricsPlugin : public Plugin {
public:
    std::string name() const override { return "metrics"; }
    void execute() override { std::cout << "Collecting metrics..." << std::endl; }
};

// Auto-registration helper
template<typename T>
struct PluginRegistrar {
    explicit PluginRegistrar(const std::string& name) {
        PluginRegistry::instance().registerPlugin(name, []() {
            return std::make_unique<T>();
        });
    }
};

static PluginRegistrar<LogPlugin> regLog("log");
static PluginRegistrar<MetricsPlugin> regMetrics("metrics");

int main() {
    auto& registry = PluginRegistry::instance();

    for (const auto& name : registry.listPlugins()) {
        auto plugin = registry.create(name);
        if (plugin) {
            plugin->execute();
        }
    }
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "ClassDef",
      "name": "Plugin",
      "isAbstract": true,
      "members": {
        "public": [
          { "type": "Destructor", "isVirtual": true, "defaulted": true },
          { "type": "PureVirtualMethod", "name": "name", "returnType": "std::string", "isConst": true },
          { "type": "PureVirtualMethod", "name": "execute", "returnType": "void" }
        ]
      }
    },
    {
      "type": "ClassDef",
      "name": "PluginRegistry",
      "isSingleton": true,
      "members": {
        "public": [
          { "type": "TypeAlias", "name": "FactoryFunc", "underlying": "std::function<std::unique_ptr<Plugin>()>" },
          { "type": "StaticMethod", "name": "instance", "returnType": "PluginRegistry&" },
          {
            "type": "MethodDef", "name": "registerPlugin",
            "params": [
              { "name": "name", "paramType": "const std::string&" },
              { "name": "factory", "paramType": "FactoryFunc" }
            ]
          },
          {
            "type": "MethodDef", "name": "create",
            "params": [{ "name": "name", "paramType": "const std::string&" }],
            "returnType": "std::unique_ptr<Plugin>"
          },
          {
            "type": "MethodDef", "name": "listPlugins", "isConst": true,
            "returnType": "std::vector<std::string>"
          }
        ],
        "private": [
          { "type": "Constructor", "defaulted": true },
          { "type": "FieldDecl", "name": "factories", "fieldType": "std::map<std::string, FactoryFunc>" }
        ]
      }
    },
    {
      "type": "ClassDef", "name": "LogPlugin", "bases": [{ "name": "Plugin" }]
    },
    {
      "type": "ClassDef", "name": "MetricsPlugin", "bases": [{ "name": "Plugin" }]
    },
    {
      "type": "TemplateClassDef",
      "name": "PluginRegistrar",
      "typeParams": ["T"],
      "comment": "Auto-registration via static constructor"
    },
    {
      "type": "StaticVarDecl", "name": "regLog", "declType": "PluginRegistrar<LogPlugin>",
      "init": { "type": "StringLiteral", "value": "log" }
    },
    {
      "type": "StaticVarDecl", "name": "regMetrics", "declType": "PluginRegistrar<MetricsPlugin>",
      "init": { "type": "StringLiteral", "value": "metrics" }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["fmt", "sort", "sync"],
  "interfaces": [
    {
      "type": "Interface",
      "name": "Plugin",
      "methods": [
        { "name": "Name", "returnType": "string" },
        { "name": "Execute" }
      ]
    }
  ],
  "types": [
    {
      "type": "Struct",
      "name": "PluginRegistry",
      "fields": [
        { "name": "mu", "fieldType": "sync.RWMutex" },
        { "name": "factories", "fieldType": "map[string]func() Plugin" }
      ]
    }
  ],
  "packageVars": [
    { "name": "registry", "varType": "*PluginRegistry" },
    { "name": "registryOnce", "varType": "sync.Once" }
  ],
  "initFunctions": [
    {
      "type": "Init",
      "body": [
        { "type": "Call", "func": "Register", "args": [{ "type": "Literal", "value": "log" }, { "type": "FuncRef", "name": "NewLogPlugin" }] },
        { "type": "Call", "func": "Register", "args": [{ "type": "Literal", "value": "metrics" }, { "type": "FuncRef", "name": "NewMetricsPlugin" }] }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Abstract factory interface**: The ` + "`" + `Plugin` + "`" + ` abstract class becomes a Go ` + "`" + `interface` + "`" + `.
2. **Registry singleton**: The ` + "`" + `PluginRegistry` + "`" + ` singleton maps to ` + "`" + `sync.Once` + "`" + ` + package-level variable pattern (same as singleton strategy).
3. **` + "`" + `std::function<unique_ptr<Plugin>()>` + "`" + `**: Maps to ` + "`" + `func() Plugin` + "`" + `. Go's first-class functions replace ` + "`" + `std::function` + "`" + `.
4. **Factory map**: ` + "`" + `std::map<string, FactoryFunc>` + "`" + ` becomes ` + "`" + `map[string]func() Plugin` + "`" + `.
5. **Template auto-registrar with static init**: C++ uses static variable constructors to auto-register at startup. In Go, use ` + "`" + `init()` + "`" + ` functions which run automatically before ` + "`" + `main()` + "`" + `.
6. **` + "`" + `std::move` + "`" + `**: Dropped. Go does not have move semantics.
7. **` + "`" + `nullptr` + "`" + ` return**: Maps to ` + "`" + `nil, error` + "`" + ` tuple return (or just ` + "`" + `nil` + "`" + ` for the interface value).

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sort"
	"sync"
)

type Plugin interface {
	Name() string
	Execute()
}

type PluginRegistry struct {
	mu        sync.RWMutex
	factories map[string]func() Plugin
}

var (
	registry     *PluginRegistry
	registryOnce sync.Once
)

func GetRegistry() *PluginRegistry {
	registryOnce.Do(func() {
		registry = &PluginRegistry{
			factories: make(map[string]func() Plugin),
		}
	})
	return registry
}

func (r *PluginRegistry) Register(name string, factory func() Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
}

func (r *PluginRegistry) Create(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	factory, ok := r.factories[name]
	if !ok {
		return nil, false
	}
	return factory(), true
}

func (r *PluginRegistry) ListPlugins() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Concrete plugins

type LogPlugin struct{}

func NewLogPlugin() Plugin { return &LogPlugin{} }

func (p *LogPlugin) Name() string { return "log" }

func (p *LogPlugin) Execute() { fmt.Println("Logging...") }

type MetricsPlugin struct{}

func NewMetricsPlugin() Plugin { return &MetricsPlugin{} }

func (p *MetricsPlugin) Name() string { return "metrics" }

func (p *MetricsPlugin) Execute() { fmt.Println("Collecting metrics...") }

// Auto-registration via init()
func init() {
	GetRegistry().Register("log", NewLogPlugin)
	GetRegistry().Register("metrics", NewMetricsPlugin)
}

func main() {
	reg := GetRegistry()

	for _, name := range reg.ListPlugins() {
		plugin, ok := reg.Create(name)
		if ok {
			plugin.Execute()
		}
	}
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Equivalent | Notes |
|---|---|---|
| Abstract class (pure virtuals) | ` + "`" + `interface` + "`" + ` | Go interfaces are implicitly satisfied |
| Virtual method | Interface method | No ` + "`" + `virtual` + "`" + ` keyword needed |
| ` + "`" + `override` + "`" + ` keyword | (implicit) | Compiler checks satisfaction automatically |
| Virtual destructor | (not needed) or ` + "`" + `Close() error` + "`" + ` in interface | GC handles memory; ` + "`" + `Close` + "`" + ` for resources |
| ` + "`" + `class Derived : public Base` + "`" + ` | Struct with methods matching interface | No inheritance keyword |
| Constructor (` + "`" + `Derived(args)` + "`" + `) | ` + "`" + `func NewDerived(args) Interface` + "`" + ` | Factory function returns interface |
| ` + "`" + `std::unique_ptr<Base>` + "`" + ` | Interface value | Interfaces hold pointer internally |
| ` + "`" + `std::make_unique<T>(args)` + "`" + ` | ` + "`" + `&T{fields}` + "`" + ` | Struct literal with address-of |
| Factory function with if/else | Factory function with ` + "`" + `switch` + "`" + ` | Cleaner dispatch |
| ` + "`" + `throw std::invalid_argument` + "`" + ` | ` + "`" + `return nil, fmt.Errorf(...)` + "`" + ` | Error return instead of exception |
| ` + "`" + `std::function<R(Args)>` + "`" + ` | ` + "`" + `func(Args) R` + "`" + ` | First-class function type |
| ` + "`" + `std::map<string, FactoryFunc>` + "`" + ` | ` + "`" + `map[string]func() Interface` + "`" + ` | Function map for registration |
| Static constructor auto-registration | ` + "`" + `init()` + "`" + ` function | Runs before ` + "`" + `main()` + "`" + ` |
| ` + "`" + `PluginRegistrar<T>` + "`" + ` template | Direct ` + "`" + `Register(name, NewT)` + "`" + ` calls | No template needed |
| ` + "`" + `std::move(factory)` + "`" + ` | (dropped) | Go has no move semantics |
| ` + "`" + `nullptr` + "`" + ` return | ` + "`" + `nil, false` + "`" + ` or ` + "`" + `nil, error` + "`" + ` | Comma-ok or error pattern |
| ` + "`" + `explicit` + "`" + ` constructor | (always explicit in Go) | Named factory functions |
| Default parameters | Variadic args or functional options | ` + "`" + `func New(opts ...Option)` + "`" + ` |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/patterns/observer_channel.md",
			Body: `# Observer Pattern to Channels and Callbacks

> C++ observer/listener patterns mapped to Go channels, callback functions, and a generic EventBus.

---

## 1. Basic Observer: ` + "`" + `addListener` + "`" + ` / ` + "`" + `removeListener` + "`" + ` to Channel Subscribe/Unsubscribe

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <algorithm>
#include <mutex>

class Event {
public:
    std::string type;
    std::string data;
    Event(const std::string& type, const std::string& data) : type(type), data(data) {}
};

class EventEmitter {
public:
    using Listener = std::function<void(const Event&)>;

    int addListener(const std::string& eventType, Listener listener) {
        std::lock_guard<std::mutex> lock(mtx);
        int id = nextID++;
        listeners.push_back({id, eventType, std::move(listener)});
        return id;
    }

    void removeListener(int id) {
        std::lock_guard<std::mutex> lock(mtx);
        listeners.erase(
            std::remove_if(listeners.begin(), listeners.end(),
                [id](const ListenerEntry& e) { return e.id == id; }),
            listeners.end()
        );
    }

    void emit(const Event& event) {
        std::lock_guard<std::mutex> lock(mtx);
        for (const auto& entry : listeners) {
            if (entry.eventType == event.type) {
                entry.callback(event);
            }
        }
    }

private:
    struct ListenerEntry {
        int id;
        std::string eventType;
        Listener callback;
    };

    std::vector<ListenerEntry> listeners;
    std::mutex mtx;
    int nextID = 0;
};

int main() {
    EventEmitter emitter;

    int id1 = emitter.addListener("click", [](const Event& e) {
        std::cout << "Click handler: " << e.data << std::endl;
    });

    int id2 = emitter.addListener("click", [](const Event& e) {
        std::cout << "Another click handler: " << e.data << std::endl;
    });

    emitter.addListener("hover", [](const Event& e) {
        std::cout << "Hover: " << e.data << std::endl;
    });

    emitter.emit(Event("click", "button1"));
    emitter.removeListener(id1);
    emitter.emit(Event("click", "button2"));

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "ClassDef",
      "name": "Event",
      "members": {
        "public": [
          { "type": "FieldDecl", "name": "type", "fieldType": "std::string" },
          { "type": "FieldDecl", "name": "data", "fieldType": "std::string" },
          {
            "type": "Constructor",
            "params": [
              { "name": "type", "paramType": "const std::string&" },
              { "name": "data", "paramType": "const std::string&" }
            ]
          }
        ]
      }
    },
    {
      "type": "ClassDef",
      "name": "EventEmitter",
      "members": {
        "public": [
          { "type": "TypeAlias", "name": "Listener", "underlying": "std::function<void(const Event&)>" },
          {
            "type": "MethodDef", "name": "addListener",
            "params": [
              { "name": "eventType", "paramType": "const std::string&" },
              { "name": "listener", "paramType": "Listener" }
            ],
            "returnType": "int"
          },
          {
            "type": "MethodDef", "name": "removeListener",
            "params": [{ "name": "id", "paramType": "int" }],
            "returnType": "void"
          },
          {
            "type": "MethodDef", "name": "emit",
            "params": [{ "name": "event", "paramType": "const Event&" }],
            "returnType": "void"
          }
        ],
        "private": [
          {
            "type": "StructDef",
            "name": "ListenerEntry",
            "members": [
              { "type": "FieldDecl", "name": "id", "fieldType": "int" },
              { "type": "FieldDecl", "name": "eventType", "fieldType": "std::string" },
              { "type": "FieldDecl", "name": "callback", "fieldType": "Listener" }
            ]
          },
          { "type": "FieldDecl", "name": "listeners", "fieldType": "std::vector<ListenerEntry>" },
          { "type": "FieldDecl", "name": "mtx", "fieldType": "std::mutex" },
          { "type": "FieldDecl", "name": "nextID", "fieldType": "int", "init": { "type": "IntLiteral", "value": 0 } }
        ]
      }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["fmt", "sync"],
  "types": [
    {
      "type": "Struct",
      "name": "Event",
      "fields": [
        { "name": "Type", "fieldType": "string" },
        { "name": "Data", "fieldType": "string" }
      ]
    },
    {
      "type": "Struct",
      "name": "listenerEntry",
      "fields": [
        { "name": "id", "fieldType": "int" },
        { "name": "eventType", "fieldType": "string" },
        { "name": "callback", "fieldType": "func(Event)" }
      ]
    },
    {
      "type": "Struct",
      "name": "EventEmitter",
      "fields": [
        { "name": "mu", "fieldType": "sync.RWMutex" },
        { "name": "listeners", "fieldType": "[]listenerEntry" },
        { "name": "nextID", "fieldType": "int" }
      ]
    }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "NewEventEmitter",
      "returnType": "*EventEmitter",
      "body": [
        { "type": "Return", "value": { "type": "AddressOf", "operand": { "type": "StructLiteral", "structType": "EventEmitter" } } }
      ]
    },
    {
      "type": "Method",
      "receiver": { "name": "e", "receiverType": "*EventEmitter" },
      "name": "AddListener",
      "params": [
        { "name": "eventType", "paramType": "string" },
        { "name": "callback", "paramType": "func(Event)" }
      ],
      "returnType": "int"
    },
    {
      "type": "Method",
      "receiver": { "name": "e", "receiverType": "*EventEmitter" },
      "name": "RemoveListener",
      "params": [{ "name": "id", "paramType": "int" }]
    },
    {
      "type": "Method",
      "receiver": { "name": "e", "receiverType": "*EventEmitter" },
      "name": "Emit",
      "params": [{ "name": "event", "paramType": "Event" }]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `std::function<void(const Event&)>` + "`" + `**: Maps directly to ` + "`" + `func(Event)` + "`" + `. Go's function values are first-class and serve the same role as ` + "`" + `std::function` + "`" + `.
2. **Listener registration with IDs**: The ` + "`" + `addListener` + "`" + ` returns an ` + "`" + `int` + "`" + ` ID for later removal. This pattern translates directly, with each entry tracked in a slice.
3. **` + "`" + `std::remove_if` + "`" + ` + ` + "`" + `erase` + "`" + `**: Maps to slice filtering. Build a new slice excluding the target ID, or use the swap-and-truncate pattern.
4. **` + "`" + `std::lock_guard<std::mutex>` + "`" + `**: Maps to ` + "`" + `sync.RWMutex` + "`" + ` with ` + "`" + `Lock` + "`" + `/` + "`" + `RLock` + "`" + ` + deferred ` + "`" + `Unlock` + "`" + `/` + "`" + `RUnlock` + "`" + `.
5. **Lambda callbacks**: Go closures (` + "`" + `func(Event) { ... }` + "`" + `) replace C++ lambdas.
6. **Nested struct**: ` + "`" + `ListenerEntry` + "`" + ` becomes an unexported ` + "`" + `listenerEntry` + "`" + ` type (lowercase) since it is private.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sync"
)

type Event struct {
	Type string
	Data string
}

type listenerEntry struct {
	id        int
	eventType string
	callback  func(Event)
}

type EventEmitter struct {
	mu        sync.RWMutex
	listeners []listenerEntry
	nextID    int
}

func NewEventEmitter() *EventEmitter {
	return &EventEmitter{}
}

func (e *EventEmitter) AddListener(eventType string, callback func(Event)) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	id := e.nextID
	e.nextID++
	e.listeners = append(e.listeners, listenerEntry{
		id:        id,
		eventType: eventType,
		callback:  callback,
	})
	return id
}

func (e *EventEmitter) RemoveListener(id int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	filtered := e.listeners[:0]
	for _, entry := range e.listeners {
		if entry.id != id {
			filtered = append(filtered, entry)
		}
	}
	e.listeners = filtered
}

func (e *EventEmitter) Emit(event Event) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, entry := range e.listeners {
		if entry.eventType == event.Type {
			entry.callback(event)
		}
	}
}

func main() {
	emitter := NewEventEmitter()

	id1 := emitter.AddListener("click", func(e Event) {
		fmt.Println("Click handler:", e.Data)
	})

	_ = emitter.AddListener("click", func(e Event) {
		fmt.Println("Another click handler:", e.Data)
	})

	emitter.AddListener("hover", func(e Event) {
		fmt.Println("Hover:", e.Data)
	})

	emitter.Emit(Event{Type: "click", Data: "button1"})
	emitter.RemoveListener(id1)
	emitter.Emit(Event{Type: "click", Data: "button2"})
}
` + "`" + `` + "`" + `` + "`" + `

---

## 2. Channel-Based Observer: Event Dispatch via Channels

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>

struct Message {
    std::string topic;
    std::string payload;
};

class MessageBroker {
public:
    using Handler = std::function<void(const Message&)>;

    void subscribe(const std::string& topic, Handler handler) {
        std::lock_guard<std::mutex> lock(mtx);
        subscribers[topic].push_back(std::move(handler));
    }

    void publish(const Message& msg) {
        std::lock_guard<std::mutex> lock(queueMtx);
        messageQueue.push(msg);
        cv.notify_one();
    }

    void start() {
        running = true;
        worker = std::thread([this]() {
            while (running) {
                Message msg;
                {
                    std::unique_lock<std::mutex> lock(queueMtx);
                    cv.wait(lock, [this]() {
                        return !messageQueue.empty() || !running;
                    });
                    if (!running && messageQueue.empty()) break;
                    msg = messageQueue.front();
                    messageQueue.pop();
                }

                std::lock_guard<std::mutex> lock(mtx);
                auto it = subscribers.find(msg.topic);
                if (it != subscribers.end()) {
                    for (const auto& handler : it->second) {
                        handler(msg);
                    }
                }
            }
        });
    }

    void stop() {
        running = false;
        cv.notify_one();
        if (worker.joinable()) {
            worker.join();
        }
    }

private:
    std::map<std::string, std::vector<Handler>> subscribers;
    std::queue<Message> messageQueue;
    std::mutex mtx;
    std::mutex queueMtx;
    std::condition_variable cv;
    std::thread worker;
    std::atomic<bool> running{false};
};
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "StructDef",
      "name": "Message",
      "members": [
        { "type": "FieldDecl", "name": "topic", "fieldType": "std::string" },
        { "type": "FieldDecl", "name": "payload", "fieldType": "std::string" }
      ]
    },
    {
      "type": "ClassDef",
      "name": "MessageBroker",
      "members": {
        "public": [
          { "type": "TypeAlias", "name": "Handler", "underlying": "std::function<void(const Message&)>" },
          { "type": "MethodDef", "name": "subscribe", "params": [{ "name": "topic", "paramType": "const std::string&" }, { "name": "handler", "paramType": "Handler" }] },
          { "type": "MethodDef", "name": "publish", "params": [{ "name": "msg", "paramType": "const Message&" }] },
          { "type": "MethodDef", "name": "start" },
          { "type": "MethodDef", "name": "stop" }
        ],
        "private": [
          { "type": "FieldDecl", "name": "subscribers", "fieldType": "std::map<std::string, std::vector<Handler>>" },
          { "type": "FieldDecl", "name": "messageQueue", "fieldType": "std::queue<Message>" },
          { "type": "FieldDecl", "name": "mtx", "fieldType": "std::mutex" },
          { "type": "FieldDecl", "name": "queueMtx", "fieldType": "std::mutex" },
          { "type": "FieldDecl", "name": "cv", "fieldType": "std::condition_variable" },
          { "type": "FieldDecl", "name": "worker", "fieldType": "std::thread" },
          { "type": "FieldDecl", "name": "running", "fieldType": "std::atomic<bool>" }
        ]
      }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["fmt", "sync"],
  "types": [
    {
      "type": "Struct",
      "name": "Message",
      "fields": [
        { "name": "Topic", "fieldType": "string" },
        { "name": "Payload", "fieldType": "string" }
      ]
    },
    {
      "type": "Struct",
      "name": "MessageBroker",
      "fields": [
        { "name": "mu", "fieldType": "sync.RWMutex" },
        { "name": "subscribers", "fieldType": "map[string][]func(Message)" },
        { "name": "messages", "fieldType": "chan Message" },
        { "name": "done", "fieldType": "chan struct{}" }
      ]
    }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "NewMessageBroker",
      "params": [{ "name": "bufferSize", "paramType": "int" }],
      "returnType": "*MessageBroker",
      "body": [
        {
          "type": "Return",
          "value": {
            "type": "AddressOf",
            "operand": {
              "type": "StructLiteral",
              "structType": "MessageBroker",
              "fields": {
                "subscribers": { "type": "Make", "makeType": "map[string][]func(Message)" },
                "messages": { "type": "Make", "makeType": "chan Message", "size": { "type": "Ref", "name": "bufferSize" } },
                "done": { "type": "Make", "makeType": "chan struct{}" }
              }
            }
          }
        }
      ]
    },
    {
      "type": "Method",
      "receiver": { "name": "b", "receiverType": "*MessageBroker" },
      "name": "Subscribe",
      "comment": "Thread-safe subscription"
    },
    {
      "type": "Method",
      "receiver": { "name": "b", "receiverType": "*MessageBroker" },
      "name": "Publish",
      "comment": "Non-blocking send to buffered channel"
    },
    {
      "type": "Method",
      "receiver": { "name": "b", "receiverType": "*MessageBroker" },
      "name": "Start",
      "comment": "Launch goroutine to process messages"
    },
    {
      "type": "Method",
      "receiver": { "name": "b", "receiverType": "*MessageBroker" },
      "name": "Stop",
      "comment": "Close channel and wait for goroutine"
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `std::queue` + "`" + ` + ` + "`" + `std::condition_variable` + "`" + ` + ` + "`" + `std::mutex` + "`" + `**: This entire combination maps to a single Go buffered channel (` + "`" + `chan Message` + "`" + `). Channels handle queuing, blocking, and notification natively.
2. **` + "`" + `std::thread` + "`" + ` worker loop**: Maps to a goroutine launched with ` + "`" + `go` + "`" + `. The ` + "`" + `for msg := range ch` + "`" + ` loop replaces the ` + "`" + `while(running)` + "`" + ` + ` + "`" + `cv.wait` + "`" + ` pattern.
3. **` + "`" + `std::atomic<bool> running` + "`" + `**: Replaced by closing the channel. Closing the ` + "`" + `messages` + "`" + ` channel causes ` + "`" + `range` + "`" + ` to terminate.
4. **` + "`" + `stop()` + "`" + ` with ` + "`" + `join()` + "`" + `**: Maps to closing the channel and reading from a ` + "`" + `done` + "`" + ` channel to wait for the goroutine to finish.
5. **` + "`" + `publish` + "`" + ` with ` + "`" + `notify_one` + "`" + `**: Simply sends on the buffered channel. If the channel is full, the sender blocks (back-pressure) or you use a ` + "`" + `select` + "`" + ` with ` + "`" + `default` + "`" + ` for non-blocking behavior.
6. **Subscriber map**: Same pattern -- ` + "`" + `map[string][]func(Message)` + "`" + ` with ` + "`" + `sync.RWMutex` + "`" + ` protection for concurrent subscription.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sync"
)

type Message struct {
	Topic   string
	Payload string
}

type MessageBroker struct {
	mu          sync.RWMutex
	subscribers map[string][]func(Message)
	messages    chan Message
	done        chan struct{}
}

func NewMessageBroker(bufferSize int) *MessageBroker {
	return &MessageBroker{
		subscribers: make(map[string][]func(Message)),
		messages:    make(chan Message, bufferSize),
		done:        make(chan struct{}),
	}
}

func (b *MessageBroker) Subscribe(topic string, handler func(Message)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[topic] = append(b.subscribers[topic], handler)
}

func (b *MessageBroker) Publish(msg Message) {
	b.messages <- msg
}

func (b *MessageBroker) Start() {
	go func() {
		defer close(b.done)
		for msg := range b.messages {
			b.mu.RLock()
			handlers := b.subscribers[msg.Topic]
			b.mu.RUnlock()
			for _, handler := range handlers {
				handler(msg)
			}
		}
	}()
}

func (b *MessageBroker) Stop() {
	close(b.messages)
	<-b.done
}

func main() {
	broker := NewMessageBroker(100)

	broker.Subscribe("order.created", func(m Message) {
		fmt.Println("Order handler:", m.Payload)
	})

	broker.Subscribe("order.created", func(m Message) {
		fmt.Println("Audit log:", m.Payload)
	})

	broker.Subscribe("user.login", func(m Message) {
		fmt.Println("Login event:", m.Payload)
	})

	broker.Start()

	broker.Publish(Message{Topic: "order.created", Payload: "order-123"})
	broker.Publish(Message{Topic: "user.login", Payload: "alice"})
	broker.Publish(Message{Topic: "order.created", Payload: "order-456"})

	broker.Stop()
}
` + "`" + `` + "`" + `` + "`" + `

---

## 3. Generic EventBus: Typed Subscriptions Using Generics and Channels

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <typeindex>
#include <any>
#include <mutex>

class EventBus {
public:
    template<typename T>
    int subscribe(std::function<void(const T&)> handler) {
        std::lock_guard<std::mutex> lock(mtx);
        auto key = std::type_index(typeid(T));
        int id = nextID++;
        handlers[key].push_back({id, [handler](const std::any& event) {
            handler(std::any_cast<const T&>(event));
        }});
        return id;
    }

    void unsubscribe(int id) {
        std::lock_guard<std::mutex> lock(mtx);
        for (auto& [key, entries] : handlers) {
            entries.erase(
                std::remove_if(entries.begin(), entries.end(),
                    [id](const HandlerEntry& e) { return e.id == id; }),
                entries.end()
            );
        }
    }

    template<typename T>
    void publish(const T& event) {
        std::lock_guard<std::mutex> lock(mtx);
        auto key = std::type_index(typeid(T));
        auto it = handlers.find(key);
        if (it != handlers.end()) {
            for (const auto& entry : it->second) {
                entry.callback(event);
            }
        }
    }

private:
    struct HandlerEntry {
        int id;
        std::function<void(const std::any&)> callback;
    };

    std::map<std::type_index, std::vector<HandlerEntry>> handlers;
    std::mutex mtx;
    int nextID = 0;
};

// Event types
struct UserCreated {
    std::string username;
    std::string email;
};

struct OrderPlaced {
    int orderID;
    double total;
};

int main() {
    EventBus bus;

    bus.subscribe<UserCreated>([](const UserCreated& e) {
        std::cout << "User created: " << e.username << " (" << e.email << ")" << std::endl;
    });

    bus.subscribe<OrderPlaced>([](const OrderPlaced& e) {
        std::cout << "Order placed: #" << e.orderID << " total: $" << e.total << std::endl;
    });

    bus.publish(UserCreated{"alice", "alice@example.com"});
    bus.publish(OrderPlaced{42, 99.99});

    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "ClassDef",
      "name": "EventBus",
      "members": {
        "public": [
          {
            "type": "TemplateMethodDef",
            "name": "subscribe",
            "typeParams": ["T"],
            "params": [{ "name": "handler", "paramType": "std::function<void(const T&)>" }],
            "returnType": "int"
          },
          {
            "type": "MethodDef",
            "name": "unsubscribe",
            "params": [{ "name": "id", "paramType": "int" }]
          },
          {
            "type": "TemplateMethodDef",
            "name": "publish",
            "typeParams": ["T"],
            "params": [{ "name": "event", "paramType": "const T&" }]
          }
        ],
        "private": [
          {
            "type": "StructDef",
            "name": "HandlerEntry",
            "members": [
              { "type": "FieldDecl", "name": "id", "fieldType": "int" },
              { "type": "FieldDecl", "name": "callback", "fieldType": "std::function<void(const std::any&)>" }
            ]
          },
          { "type": "FieldDecl", "name": "handlers", "fieldType": "std::map<std::type_index, std::vector<HandlerEntry>>" },
          { "type": "FieldDecl", "name": "mtx", "fieldType": "std::mutex" },
          { "type": "FieldDecl", "name": "nextID", "fieldType": "int" }
        ]
      }
    },
    {
      "type": "StructDef",
      "name": "UserCreated",
      "members": [
        { "type": "FieldDecl", "name": "username", "fieldType": "std::string" },
        { "type": "FieldDecl", "name": "email", "fieldType": "std::string" }
      ]
    },
    {
      "type": "StructDef",
      "name": "OrderPlaced",
      "members": [
        { "type": "FieldDecl", "name": "orderID", "fieldType": "int" },
        { "type": "FieldDecl", "name": "total", "fieldType": "double" }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["fmt", "sync"],
  "types": [
    {
      "type": "GenericStruct",
      "name": "Subscription",
      "typeParams": [{ "name": "T", "constraint": "any" }],
      "fields": [
        { "name": "ch", "fieldType": "chan T" },
        { "name": "done", "fieldType": "chan struct{}" }
      ]
    },
    {
      "type": "GenericStruct",
      "name": "Topic",
      "typeParams": [{ "name": "T", "constraint": "any" }],
      "fields": [
        { "name": "mu", "fieldType": "sync.RWMutex" },
        { "name": "subscribers", "fieldType": "map[int]*Subscription[T]" },
        { "name": "nextID", "fieldType": "int" }
      ]
    }
  ],
  "functions": [
    {
      "type": "GenericFunc",
      "name": "NewTopic",
      "typeParams": [{ "name": "T", "constraint": "any" }],
      "returnType": "*Topic[T]"
    },
    {
      "type": "GenericMethod",
      "receiver": { "name": "t", "receiverType": "*Topic[T]" },
      "name": "Subscribe",
      "params": [{ "name": "handler", "paramType": "func(T)" }],
      "returnType": "int"
    },
    {
      "type": "GenericMethod",
      "receiver": { "name": "t", "receiverType": "*Topic[T]" },
      "name": "Unsubscribe",
      "params": [{ "name": "id", "paramType": "int" }]
    },
    {
      "type": "GenericMethod",
      "receiver": { "name": "t", "receiverType": "*Topic[T]" },
      "name": "Publish",
      "params": [{ "name": "event", "paramType": "T" }]
    },
    {
      "type": "GenericMethod",
      "receiver": { "name": "t", "receiverType": "*Topic[T]" },
      "name": "Close"
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `std::type_index` + "`" + ` keyed map**: C++ uses RTTI (` + "`" + `typeid` + "`" + `) to key handlers by event type. In Go, the generic approach uses separate ` + "`" + `Topic[T]` + "`" + ` instances per event type, making the type key unnecessary.
2. **` + "`" + `std::any` + "`" + ` + ` + "`" + `std::any_cast` + "`" + `**: Eliminated by generics. Each ` + "`" + `Topic[T]` + "`" + ` is strongly typed for event type ` + "`" + `T` + "`" + `.
3. **Template methods on EventBus**: Go does not support generic methods on non-generic types. Instead, use generic free-standing types: ` + "`" + `Topic[T]` + "`" + ` with methods. Each event type gets its own ` + "`" + `Topic` + "`" + ` instance.
4. **Channel-per-subscriber**: Each subscriber gets a dedicated ` + "`" + `chan T` + "`" + `. The ` + "`" + `Publish` + "`" + ` method sends to all subscriber channels. This decouples publishers from subscribers and enables async processing.
5. **Goroutine per subscriber**: Each subscription spawns a goroutine that reads from the channel and calls the handler. This replaces the direct callback invocation and enables non-blocking dispatch.
6. **Unsubscribe via close**: Closing the subscriber's channel signals the goroutine to stop.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sync"
)

// Topic provides a typed pub/sub channel for events of type T.
type Topic[T any] struct {
	mu          sync.RWMutex
	subscribers map[int]*subscription[T]
	nextID      int
}

type subscription[T any] struct {
	ch   chan T
	done chan struct{}
}

func NewTopic[T any]() *Topic[T] {
	return &Topic[T]{
		subscribers: make(map[int]*subscription[T]),
	}
}

func (t *Topic[T]) Subscribe(handler func(T)) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	id := t.nextID
	t.nextID++

	sub := &subscription[T]{
		ch:   make(chan T, 16),
		done: make(chan struct{}),
	}
	t.subscribers[id] = sub

	go func() {
		defer close(sub.done)
		for event := range sub.ch {
			handler(event)
		}
	}()

	return id
}

func (t *Topic[T]) Unsubscribe(id int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	sub, ok := t.subscribers[id]
	if !ok {
		return
	}
	close(sub.ch)
	<-sub.done
	delete(t.subscribers, id)
}

func (t *Topic[T]) Publish(event T) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, sub := range t.subscribers {
		sub.ch <- event
	}
}

func (t *Topic[T]) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, sub := range t.subscribers {
		close(sub.ch)
		<-sub.done
		delete(t.subscribers, id)
	}
}

// Event types

type UserCreated struct {
	Username string
	Email    string
}

type OrderPlaced struct {
	OrderID int
	Total   float64
}

func main() {
	userTopic := NewTopic[UserCreated]()
	orderTopic := NewTopic[OrderPlaced]()

	userTopic.Subscribe(func(e UserCreated) {
		fmt.Printf("User created: %s (%s)\n", e.Username, e.Email)
	})

	orderTopic.Subscribe(func(e OrderPlaced) {
		fmt.Printf("Order placed: #%d total: $%.2f\n", e.OrderID, e.Total)
	})

	userTopic.Publish(UserCreated{Username: "alice", Email: "alice@example.com"})
	orderTopic.Publish(OrderPlaced{OrderID: 42, Total: 99.99})

	userTopic.Close()
	orderTopic.Close()
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Equivalent | Notes |
|---|---|---|
| ` + "`" + `std::function<void(const T&)>` + "`" + ` | ` + "`" + `func(T)` + "`" + ` | First-class function type |
| Lambda ` + "`" + `[](const Event& e) { ... }` + "`" + ` | ` + "`" + `func(e Event) { ... }` + "`" + ` | Closure literal |
| ` + "`" + `addListener` + "`" + ` returning ID | ` + "`" + `Subscribe` + "`" + ` returning ` + "`" + `int` + "`" + ` | ID-based unsubscription |
| ` + "`" + `removeListener(id)` + "`" + ` | ` + "`" + `Unsubscribe(id)` + "`" + ` | Filter or delete from map |
| ` + "`" + `std::vector<Listener>` + "`" + ` | ` + "`" + `[]func(Event)` + "`" + ` or ` + "`" + `map[int]*subscription` + "`" + ` | Slice or map of handlers |
| ` + "`" + `std::mutex` + "`" + ` + ` + "`" + `std::lock_guard` + "`" + ` | ` + "`" + `sync.RWMutex` + "`" + ` + ` + "`" + `Lock()` + "`" + `/` + "`" + `defer Unlock()` + "`" + ` | Read-write lock for subscribers |
| ` + "`" + `std::queue` + "`" + ` + ` + "`" + `condition_variable` + "`" + ` | Buffered ` + "`" + `chan T` + "`" + ` | Channel replaces queue + CV |
| ` + "`" + `std::thread` + "`" + ` worker | ` + "`" + `go func() { ... }()` + "`" + ` | Goroutine |
| ` + "`" + `thread.join()` + "`" + ` | ` + "`" + `<-done` + "`" + ` channel | Wait for goroutine completion |
| ` + "`" + `std::atomic<bool> running` + "`" + ` | Close channel + ` + "`" + `range` + "`" + ` termination | Closing channel signals stop |
| ` + "`" + `std::type_index(typeid(T))` + "`" + ` | Separate ` + "`" + `Topic[T]` + "`" + ` per type | Generics replace RTTI |
| ` + "`" + `std::any` + "`" + ` + ` + "`" + `std::any_cast<T>` + "`" + ` | Generic type parameter ` + "`" + `T` + "`" + ` | Type-safe at compile time |
| Template method ` + "`" + `subscribe<T>` + "`" + ` | ` + "`" + `topic.Subscribe(handler)` + "`" + ` on ` + "`" + `Topic[T]` + "`" + ` | Go methods cannot have own type params |
| ` + "`" + `notify_one` + "`" + ` / ` + "`" + `notify_all` + "`" + ` | Channel send / close | Channel operations replace CV |
| Callback-based dispatch | Channel + goroutine per subscriber | Async processing by default |
| ` + "`" + `emit` + "`" + ` in caller's thread | ` + "`" + `Publish` + "`" + ` sends to channels | Non-blocking with buffered channels |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/patterns/singleton.md",
			Body: `# Singleton Pattern to sync.Once

> C++ singleton implementations mapped to Go's ` + "`" + `sync.Once` + "`" + ` with package-level variables.

---

## 1. Classic Singleton: Static Instance with Private Constructor to ` + "`" + `sync.Once` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <string>
#include <mutex>
#include <fstream>

class Logger {
private:
    std::ofstream logFile;
    std::string filename;

    // Private constructor
    Logger(const std::string& fname) : filename(fname) {
        logFile.open(filename, std::ios::app);
    }

    // Delete copy/move
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    static Logger* instance;
    static std::mutex mtx;

public:
    static Logger& getInstance(const std::string& fname = "app.log") {
        std::lock_guard<std::mutex> lock(mtx);
        if (instance == nullptr) {
            instance = new Logger(fname);
        }
        return *instance;
    }

    void info(const std::string& msg) {
        logFile << "[INFO] " << msg << std::endl;
        std::cout << "[INFO] " << msg << std::endl;
    }

    void error(const std::string& msg) {
        logFile << "[ERROR] " << msg << std::endl;
        std::cerr << "[ERROR] " << msg << std::endl;
    }

    ~Logger() {
        if (logFile.is_open()) {
            logFile.close();
        }
    }
};

// Static member initialization
Logger* Logger::instance = nullptr;
std::mutex Logger::mtx;

int main() {
    Logger& log = Logger::getInstance("myapp.log");
    log.info("Application started");
    log.error("Something went wrong");
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "ClassDef",
      "name": "Logger",
      "members": {
        "private": [
          { "type": "FieldDecl", "name": "logFile", "fieldType": "std::ofstream" },
          { "type": "FieldDecl", "name": "filename", "fieldType": "std::string" },
          {
            "type": "Constructor",
            "params": [{ "name": "fname", "paramType": "const std::string&" }],
            "initList": [{ "member": "filename", "value": { "type": "NameExpr", "name": "fname" } }],
            "body": [
              { "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "logFile.open", "args": [{ "type": "NameExpr", "name": "filename" }, { "type": "NameExpr", "name": "std::ios::app" }] } }
            ]
          },
          { "type": "DeletedMethod", "name": "Logger", "kind": "copy_constructor" },
          { "type": "DeletedMethod", "name": "operator=", "kind": "copy_assignment" },
          { "type": "StaticFieldDecl", "name": "instance", "fieldType": "Logger*", "init": { "type": "NullLiteral" } },
          { "type": "StaticFieldDecl", "name": "mtx", "fieldType": "std::mutex" }
        ],
        "public": [
          {
            "type": "StaticMethod",
            "name": "getInstance",
            "params": [{ "name": "fname", "paramType": "const std::string&", "default": { "type": "StringLiteral", "value": "app.log" } }],
            "returnType": "Logger&",
            "body": [
              { "type": "VarDecl", "name": "lock", "declType": "std::lock_guard<std::mutex>", "init": { "type": "NameExpr", "name": "mtx" } },
              {
                "type": "IfStmt",
                "condition": { "type": "BinaryOp", "op": "==", "left": { "type": "NameExpr", "name": "instance" }, "right": { "type": "NullLiteral" } },
                "then": [
                  { "type": "ExprStmt", "expr": { "type": "AssignExpr", "left": { "type": "NameExpr", "name": "instance" }, "right": { "type": "NewExpr", "className": "Logger", "args": [{ "type": "NameExpr", "name": "fname" }] } } }
                ]
              },
              { "type": "ReturnStmt", "value": { "type": "DerefExpr", "operand": { "type": "NameExpr", "name": "instance" } } }
            ]
          },
          {
            "type": "MethodDef",
            "name": "info",
            "params": [{ "name": "msg", "paramType": "const std::string&" }],
            "returnType": "void"
          },
          {
            "type": "MethodDef",
            "name": "error",
            "params": [{ "name": "msg", "paramType": "const std::string&" }],
            "returnType": "void"
          },
          {
            "type": "Destructor",
            "body": [
              { "type": "IfStmt", "condition": { "type": "CallExpr", "callee": "logFile.is_open" }, "then": [{ "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "logFile.close" } }] }
            ]
          }
        ]
      }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["fmt", "os", "sync"],
  "types": [
    {
      "type": "Struct",
      "name": "Logger",
      "fields": [
        { "name": "logFile", "fieldType": "*os.File" },
        { "name": "filename", "fieldType": "string" }
      ]
    }
  ],
  "packageVars": [
    { "name": "loggerInstance", "varType": "*Logger" },
    { "name": "loggerOnce", "varType": "sync.Once" }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "GetLogger",
      "params": [{ "name": "filename", "paramType": "string" }],
      "returnType": "*Logger",
      "body": [
        {
          "type": "Call",
          "func": "loggerOnce.Do",
          "args": [{
            "type": "FuncLiteral",
            "body": [
              {
                "type": "MultiAssign",
                "names": ["f", "err"],
                "value": { "type": "Call", "func": "os.OpenFile", "args": [
                  { "type": "Ref", "name": "filename" },
                  { "type": "BinaryOp", "op": "|", "left": { "type": "Ref", "name": "os.O_APPEND" }, "right": { "type": "BinaryOp", "op": "|", "left": { "type": "Ref", "name": "os.O_CREATE" }, "right": { "type": "Ref", "name": "os.O_WRONLY" } } },
                  { "type": "Literal", "value": "0644" }
                ]}
              },
              {
                "type": "If",
                "condition": { "type": "BinaryOp", "op": "!=", "left": { "type": "Ref", "name": "err" }, "right": { "type": "Nil" } },
                "then": [{ "type": "Call", "func": "panic", "args": [{ "type": "Ref", "name": "err" }] }]
              },
              {
                "type": "Assign",
                "name": "loggerInstance",
                "value": {
                  "type": "AddressOf",
                  "operand": { "type": "StructLiteral", "structType": "Logger", "fields": { "logFile": { "type": "Ref", "name": "f" }, "filename": { "type": "Ref", "name": "filename" } } }
                }
              }
            ]
          }]
        },
        { "type": "Return", "value": { "type": "Ref", "name": "loggerInstance" } }
      ]
    },
    {
      "type": "Method",
      "receiver": { "name": "l", "receiverType": "*Logger" },
      "name": "Info",
      "params": [{ "name": "msg", "paramType": "string" }],
      "body": [
        { "type": "Call", "func": "fmt.Fprintf", "args": [{ "type": "FieldAccess", "object": "l", "field": "logFile" }, { "type": "Literal", "value": "[INFO] %s\\n" }, { "type": "Ref", "name": "msg" }] },
        { "type": "Call", "func": "fmt.Printf", "args": [{ "type": "Literal", "value": "[INFO] %s\\n" }, { "type": "Ref", "name": "msg" }] }
      ]
    },
    {
      "type": "Method",
      "receiver": { "name": "l", "receiverType": "*Logger" },
      "name": "Error",
      "params": [{ "name": "msg", "paramType": "string" }],
      "body": [
        { "type": "Call", "func": "fmt.Fprintf", "args": [{ "type": "FieldAccess", "object": "l", "field": "logFile" }, { "type": "Literal", "value": "[ERROR] %s\\n" }, { "type": "Ref", "name": "msg" }] },
        { "type": "Call", "func": "fmt.Fprintf", "args": [{ "type": "Ref", "name": "os.Stderr" }, { "type": "Literal", "value": "[ERROR] %s\\n" }, { "type": "Ref", "name": "msg" }] }
      ]
    },
    {
      "type": "Method",
      "receiver": { "name": "l", "receiverType": "*Logger" },
      "name": "Close",
      "returnType": "error",
      "body": [
        { "type": "Return", "value": { "type": "Call", "func": "l.logFile.Close" } }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Private constructor**: Go has no constructors. The struct type is unexported (lowercase) or the fields are unexported, and a package-level function ` + "`" + `GetLogger` + "`" + ` controls access.
2. **Static instance + mutex**: Replaced by ` + "`" + `sync.Once` + "`" + ` + package-level variable. ` + "`" + `sync.Once.Do` + "`" + ` guarantees the initialization function runs exactly once, even with concurrent callers.
3. **Deleted copy/move**: Go structs containing ` + "`" + `*os.File` + "`" + ` are naturally not copyable in a meaningful way. The pointer receiver ensures sharing.
4. **Destructor**: Maps to a ` + "`" + `Close() error` + "`" + ` method. The caller is responsible for calling ` + "`" + `defer logger.Close()` + "`" + `.
5. **` + "`" + `std::lock_guard` + "`" + `**: Eliminated because ` + "`" + `sync.Once` + "`" + ` handles all synchronization internally.
6. **Default parameter**: Go does not support default parameters. Options: provide a separate ` + "`" + `GetDefaultLogger()` + "`" + ` wrapper, or require the caller to always pass the filename.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"os"
	"sync"
)

type Logger struct {
	logFile  *os.File
	filename string
}

var (
	loggerInstance *Logger
	loggerOnce     sync.Once
)

func GetLogger(filename string) *Logger {
	loggerOnce.Do(func() {
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(fmt.Sprintf("failed to open log file: %v", err))
		}
		loggerInstance = &Logger{
			logFile:  f,
			filename: filename,
		}
	})
	return loggerInstance
}

func (l *Logger) Info(msg string) {
	fmt.Fprintf(l.logFile, "[INFO] %s\n", msg)
	fmt.Printf("[INFO] %s\n", msg)
}

func (l *Logger) Error(msg string) {
	fmt.Fprintf(l.logFile, "[ERROR] %s\n", msg)
	fmt.Fprintf(os.Stderr, "[ERROR] %s\n", msg)
}

func (l *Logger) Close() error {
	return l.logFile.Close()
}

func main() {
	log := GetLogger("myapp.log")
	defer log.Close()

	log.Info("Application started")
	log.Error("Something went wrong")
}
` + "`" + `` + "`" + `` + "`" + `

---

## 2. Meyer's Singleton to ` + "`" + `sync.Once` + "`" + ` + Package Function

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <string>
#include <map>
#include <mutex>

class ConfigManager {
public:
    static ConfigManager& getInstance() {
        static ConfigManager instance;
        return instance;
    }

    void set(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(mtx);
        config[key] = value;
    }

    std::string get(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = config.find(key);
        if (it != config.end()) {
            return it->second;
        }
        return "";
    }

    bool has(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mtx);
        return config.find(key) != config.end();
    }

private:
    ConfigManager() = default;
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    std::map<std::string, std::string> config;
    mutable std::mutex mtx;
};

int main() {
    auto& cfg = ConfigManager::getInstance();
    cfg.set("host", "localhost");
    cfg.set("port", "8080");

    if (cfg.has("host")) {
        std::string host = cfg.get("host");
    }
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "ClassDef",
      "name": "ConfigManager",
      "members": {
        "public": [
          {
            "type": "StaticMethod",
            "name": "getInstance",
            "returnType": "ConfigManager&",
            "body": [
              {
                "type": "StaticVarDecl",
                "name": "instance",
                "declType": "ConfigManager",
                "comment": "Meyer's singleton - static local initialized once"
              },
              { "type": "ReturnStmt", "value": { "type": "NameExpr", "name": "instance" } }
            ]
          },
          {
            "type": "MethodDef",
            "name": "set",
            "params": [
              { "name": "key", "paramType": "const std::string&" },
              { "name": "value", "paramType": "const std::string&" }
            ],
            "returnType": "void",
            "body": [
              { "type": "VarDecl", "name": "lock", "declType": "std::lock_guard<std::mutex>", "init": { "type": "NameExpr", "name": "mtx" } },
              { "type": "ExprStmt", "expr": { "type": "AssignExpr", "left": { "type": "IndexExpr", "base": { "type": "NameExpr", "name": "config" }, "index": { "type": "NameExpr", "name": "key" } }, "right": { "type": "NameExpr", "name": "value" } } }
            ]
          },
          {
            "type": "MethodDef",
            "name": "get",
            "isConst": true,
            "params": [{ "name": "key", "paramType": "const std::string&" }],
            "returnType": "std::string",
            "body": [
              { "type": "VarDecl", "name": "lock", "declType": "std::lock_guard<std::mutex>", "init": { "type": "NameExpr", "name": "mtx" } },
              { "type": "VarDecl", "name": "it", "declType": "auto", "init": { "type": "CallExpr", "callee": "config.find", "args": [{ "type": "NameExpr", "name": "key" }] } },
              {
                "type": "IfStmt",
                "condition": { "type": "BinaryOp", "op": "!=", "left": { "type": "NameExpr", "name": "it" }, "right": { "type": "CallExpr", "callee": "config.end" } },
                "then": [{ "type": "ReturnStmt", "value": { "type": "MemberExpr", "object": "it", "member": "second" } }]
              },
              { "type": "ReturnStmt", "value": { "type": "StringLiteral", "value": "" } }
            ]
          },
          {
            "type": "MethodDef",
            "name": "has",
            "isConst": true,
            "params": [{ "name": "key", "paramType": "const std::string&" }],
            "returnType": "bool"
          }
        ],
        "private": [
          { "type": "Constructor", "defaulted": true },
          { "type": "Destructor", "defaulted": true },
          { "type": "DeletedMethod", "kind": "copy_constructor" },
          { "type": "DeletedMethod", "kind": "copy_assignment" },
          { "type": "FieldDecl", "name": "config", "fieldType": "std::map<std::string, std::string>" },
          { "type": "FieldDecl", "name": "mtx", "fieldType": "std::mutex", "mutable": true }
        ]
      }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["sync"],
  "types": [
    {
      "type": "Struct",
      "name": "ConfigManager",
      "fields": [
        { "name": "mu", "fieldType": "sync.RWMutex" },
        { "name": "config", "fieldType": "map[string]string" }
      ]
    }
  ],
  "packageVars": [
    { "name": "cfgInstance", "varType": "*ConfigManager" },
    { "name": "cfgOnce", "varType": "sync.Once" }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "GetConfig",
      "returnType": "*ConfigManager",
      "body": [
        {
          "type": "Call",
          "func": "cfgOnce.Do",
          "args": [{
            "type": "FuncLiteral",
            "body": [
              {
                "type": "Assign",
                "name": "cfgInstance",
                "value": {
                  "type": "AddressOf",
                  "operand": {
                    "type": "StructLiteral",
                    "structType": "ConfigManager",
                    "fields": {
                      "config": { "type": "Make", "makeType": "map[string]string" }
                    }
                  }
                }
              }
            ]
          }]
        },
        { "type": "Return", "value": { "type": "Ref", "name": "cfgInstance" } }
      ]
    },
    {
      "type": "Method",
      "receiver": { "name": "c", "receiverType": "*ConfigManager" },
      "name": "Set",
      "params": [
        { "name": "key", "paramType": "string" },
        { "name": "value", "paramType": "string" }
      ],
      "body": [
        { "type": "Call", "func": "c.mu.Lock" },
        { "type": "Defer", "call": { "type": "Call", "func": "c.mu.Unlock" } },
        { "type": "MapAssign", "map": "c.config", "key": { "type": "Ref", "name": "key" }, "value": { "type": "Ref", "name": "value" } }
      ]
    },
    {
      "type": "Method",
      "receiver": { "name": "c", "receiverType": "*ConfigManager" },
      "name": "Get",
      "params": [{ "name": "key", "paramType": "string" }],
      "returnType": "string",
      "body": [
        { "type": "Call", "func": "c.mu.RLock" },
        { "type": "Defer", "call": { "type": "Call", "func": "c.mu.RUnlock" } },
        { "type": "Return", "value": { "type": "MapAccess", "map": "c.config", "key": { "type": "Ref", "name": "key" } } }
      ]
    },
    {
      "type": "Method",
      "receiver": { "name": "c", "receiverType": "*ConfigManager" },
      "name": "Has",
      "params": [{ "name": "key", "paramType": "string" }],
      "returnType": "bool",
      "body": [
        { "type": "Call", "func": "c.mu.RLock" },
        { "type": "Defer", "call": { "type": "Call", "func": "c.mu.RUnlock" } },
        {
          "type": "MultiAssign",
          "names": ["_", "ok"],
          "value": { "type": "MapAccess", "map": "c.config", "key": { "type": "Ref", "name": "key" } }
        },
        { "type": "Return", "value": { "type": "Ref", "name": "ok" } }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Meyer's singleton (static local)**: C++11 guarantees thread-safe initialization of ` + "`" + `static` + "`" + ` local variables. The Go equivalent is ` + "`" + `sync.Once` + "`" + `, which provides the same guarantee.
2. **` + "`" + `std::mutex` + "`" + ` for method access**: Maps to ` + "`" + `sync.RWMutex` + "`" + `. Read-only methods (` + "`" + `get` + "`" + `, ` + "`" + `has` + "`" + ` which are ` + "`" + `const` + "`" + `) use ` + "`" + `RLock` + "`" + `/` + "`" + `RUnlock` + "`" + `. Write methods (` + "`" + `set` + "`" + `) use ` + "`" + `Lock` + "`" + `/` + "`" + `Unlock` + "`" + `.
3. **` + "`" + `mutable` + "`" + ` keyword on mutex**: Go's ` + "`" + `sync.RWMutex` + "`" + ` does not require ` + "`" + `mutable` + "`" + ` since Go has no const methods. The receiver is always a pointer for methods that need to lock.
4. **` + "`" + `std::map` + "`" + ` with ` + "`" + `.find()` + "`" + ` / ` + "`" + `.end()` + "`" + `**: Maps to Go's map access with comma-ok idiom: ` + "`" + `val, ok := m[key]` + "`" + `.
5. **Default constructor**: The factory function ` + "`" + `GetConfig()` + "`" + ` initializes the map with ` + "`" + `make(map[string]string)` + "`" + `.
6. **Iterator pattern**: ` + "`" + `config.find(key) != config.end()` + "`" + ` + ` + "`" + `it->second` + "`" + ` collapses to a single ` + "`" + `config[key]` + "`" + ` or ` + "`" + `_, ok := config[key]` + "`" + `.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"sync"
)

type ConfigManager struct {
	mu     sync.RWMutex
	config map[string]string
}

var (
	cfgInstance *ConfigManager
	cfgOnce    sync.Once
)

func GetConfig() *ConfigManager {
	cfgOnce.Do(func() {
		cfgInstance = &ConfigManager{
			config: make(map[string]string),
		}
	})
	return cfgInstance
}

func (c *ConfigManager) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config[key] = value
}

func (c *ConfigManager) Get(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config[key]
}

func (c *ConfigManager) Has(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.config[key]
	return ok
}

func main() {
	cfg := GetConfig()
	cfg.Set("host", "localhost")
	cfg.Set("port", "8080")

	if cfg.Has("host") {
		host := cfg.Get("host")
		fmt.Println(host)
	}
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Equivalent | Notes |
|---|---|---|
| Private constructor | Unexported struct + exported factory function | ` + "`" + `GetLogger()` + "`" + ` returns ` + "`" + `*Logger` + "`" + ` |
| ` + "`" + `static T* instance` + "`" + ` + ` + "`" + `std::mutex` + "`" + ` | ` + "`" + `var instance *T` + "`" + ` + ` + "`" + `var once sync.Once` + "`" + ` | Package-level variables |
| ` + "`" + `std::lock_guard<std::mutex>` + "`" + ` in ` + "`" + `getInstance` + "`" + ` | ` + "`" + `sync.Once.Do(func() { ... })` + "`" + ` | Once handles all synchronization |
| Meyer's singleton (` + "`" + `static T instance` + "`" + `) | ` + "`" + `sync.Once.Do(func() { ... })` + "`" + ` | Same pattern, both are thread-safe |
| Deleted copy constructor / assignment | (not needed) | Pointer semantics prevent meaningful copy |
| ` + "`" + `std::mutex` + "`" + ` in methods | ` + "`" + `sync.RWMutex` + "`" + ` | Read methods use ` + "`" + `RLock` + "`" + `, write use ` + "`" + `Lock` + "`" + ` |
| ` + "`" + `mutable std::mutex` + "`" + ` | ` + "`" + `sync.RWMutex` + "`" + ` field (no special keyword) | Go has no const methods |
| ` + "`" + `std::map::find` + "`" + ` + ` + "`" + `end()` + "`" + ` check | ` + "`" + `_, ok := m[key]` + "`" + ` | Comma-ok idiom |
| Destructor closing resources | ` + "`" + `Close() error` + "`" + ` method + ` + "`" + `defer` + "`" + ` | Caller manages cleanup |
| Default parameter | Overloaded factory or separate function | ` + "`" + `GetLogger("file")` + "`" + ` vs ` + "`" + `GetDefaultLogger()` + "`" + ` |
| ` + "`" + `static` + "`" + ` method | Package-level function | ` + "`" + `GetConfig()` + "`" + ` not ` + "`" + `ConfigManager.GetConfig()` + "`" + ` |
| ` + "`" + `std::map<K,V>` + "`" + ` | ` + "`" + `map[K]V` + "`" + ` | Must ` + "`" + `make()` + "`" + ` before use |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/preprocessor/defines_const.md",
			Body: `# Preprocessor Defines to Go Constants and Functions

> C++ ` + "`" + `#define` + "`" + ` directives mapped to Go ` + "`" + `const` + "`" + `, ` + "`" + `iota` + "`" + `, generics, and code generation.

---

## 1. Simple Constants: ` + "`" + `#define CONSTANT` + "`" + ` to ` + "`" + `const` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#define MAX_RETRIES 5
#define PI 3.14159265358979
#define APP_NAME "togo"
#define BUFFER_SIZE 4096
#define ENABLED true

int main() {
    char buf[BUFFER_SIZE];
    for (int i = 0; i < MAX_RETRIES; i++) {
        // retry logic
    }
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "preprocessor": [
    { "type": "Define", "name": "MAX_RETRIES", "value": { "type": "IntLiteral", "value": 5 } },
    { "type": "Define", "name": "PI", "value": { "type": "FloatLiteral", "value": 3.14159265358979 } },
    { "type": "Define", "name": "APP_NAME", "value": { "type": "StringLiteral", "value": "togo" } },
    { "type": "Define", "name": "BUFFER_SIZE", "value": { "type": "IntLiteral", "value": 4096 } },
    { "type": "Define", "name": "ENABLED", "value": { "type": "BoolLiteral", "value": true } }
  ],
  "declarations": [
    {
      "type": "FunctionDef",
      "name": "main",
      "returnType": "int",
      "body": [
        { "type": "VarDecl", "name": "buf", "declType": "char[]", "arraySize": { "type": "NameExpr", "name": "BUFFER_SIZE" } },
        {
          "type": "ForStmt",
          "init": { "type": "VarDecl", "name": "i", "declType": "int", "init": { "type": "IntLiteral", "value": 0 } },
          "condition": { "type": "BinaryOp", "op": "<", "left": { "type": "NameExpr", "name": "i" }, "right": { "type": "NameExpr", "name": "MAX_RETRIES" } },
          "increment": { "type": "UnaryOp", "op": "++", "operand": { "type": "NameExpr", "name": "i" } },
          "body": []
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "constants": [
    { "name": "MaxRetries", "constType": "int", "value": 5 },
    { "name": "Pi", "constType": "float64", "value": 3.14159265358979 },
    { "name": "AppName", "constType": "string", "value": "togo" },
    { "name": "BufferSize", "constType": "int", "value": 4096 },
    { "name": "Enabled", "constType": "bool", "value": true }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "main",
      "body": [
        {
          "type": "VarDecl",
          "name": "buf",
          "varType": "[BufferSize]byte"
        },
        {
          "type": "For",
          "init": { "type": "VarDecl", "name": "i", "varType": "int", "init": { "type": "Literal", "value": 0 } },
          "condition": { "type": "BinaryOp", "op": "<", "left": { "type": "Ref", "name": "i" }, "right": { "type": "Ref", "name": "MaxRetries" } },
          "post": { "type": "Increment", "name": "i" },
          "body": []
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Name transformation**: ` + "`" + `SCREAMING_SNAKE_CASE` + "`" + ` becomes ` + "`" + `PascalCase` + "`" + ` for exported constants or ` + "`" + `camelCase` + "`" + ` for unexported. The adapter uses heuristics: if the define is used across files, it becomes exported.
2. **Type inference**: The literal type determines the Go constant type. Integer literals become untyped ` + "`" + `int` + "`" + `, float literals become ` + "`" + `float64` + "`" + `, string literals become ` + "`" + `string` + "`" + `, boolean become ` + "`" + `bool` + "`" + `.
3. **` + "`" + `char[]` + "`" + ` with define size**: Maps to ` + "`" + `[N]byte` + "`" + ` where ` + "`" + `N` + "`" + ` is the constant name, preserving the indirection.
4. **Grouped declaration**: Multiple related constants are placed in a single ` + "`" + `const (...)` + "`" + ` block.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

const (
	MaxRetries = 5
	Pi         = 3.14159265358979
	AppName    = "togo"
	BufferSize = 4096
	Enabled    = true
)

func main() {
	var buf [BufferSize]byte
	_ = buf
	for i := 0; i < MaxRetries; i++ {
		// retry logic
	}
}
` + "`" + `` + "`" + `` + "`" + `

---

## 2. Bit Flag Enums: ` + "`" + `#define FLAG` + "`" + ` to ` + "`" + `iota` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#define PERM_READ    0x01
#define PERM_WRITE   0x02
#define PERM_EXECUTE 0x04
#define PERM_ALL     (PERM_READ | PERM_WRITE | PERM_EXECUTE)

#define LOG_NONE     0
#define LOG_ERROR    1
#define LOG_WARN     2
#define LOG_INFO     3
#define LOG_DEBUG    4

bool hasPermission(unsigned int perms, unsigned int flag) {
    return (perms & flag) != 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "preprocessor": [
    { "type": "Define", "name": "PERM_READ", "value": { "type": "IntLiteral", "value": 1, "base": "hex" } },
    { "type": "Define", "name": "PERM_WRITE", "value": { "type": "IntLiteral", "value": 2, "base": "hex" } },
    { "type": "Define", "name": "PERM_EXECUTE", "value": { "type": "IntLiteral", "value": 4, "base": "hex" } },
    {
      "type": "Define", "name": "PERM_ALL",
      "value": {
        "type": "BinaryOp", "op": "|",
        "left": {
          "type": "BinaryOp", "op": "|",
          "left": { "type": "NameExpr", "name": "PERM_READ" },
          "right": { "type": "NameExpr", "name": "PERM_WRITE" }
        },
        "right": { "type": "NameExpr", "name": "PERM_EXECUTE" }
      }
    },
    { "type": "Define", "name": "LOG_NONE", "value": { "type": "IntLiteral", "value": 0 } },
    { "type": "Define", "name": "LOG_ERROR", "value": { "type": "IntLiteral", "value": 1 } },
    { "type": "Define", "name": "LOG_WARN", "value": { "type": "IntLiteral", "value": 2 } },
    { "type": "Define", "name": "LOG_INFO", "value": { "type": "IntLiteral", "value": 3 } },
    { "type": "Define", "name": "LOG_DEBUG", "value": { "type": "IntLiteral", "value": 4 } }
  ],
  "declarations": [
    {
      "type": "FunctionDef",
      "name": "hasPermission",
      "params": [
        { "name": "perms", "paramType": "unsigned int" },
        { "name": "flag", "paramType": "unsigned int" }
      ],
      "returnType": "bool",
      "body": [
        {
          "type": "ReturnStmt",
          "value": {
            "type": "BinaryOp", "op": "!=",
            "left": { "type": "BinaryOp", "op": "&", "left": { "type": "NameExpr", "name": "perms" }, "right": { "type": "NameExpr", "name": "flag" } },
            "right": { "type": "IntLiteral", "value": 0 }
          }
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "types": [
    { "type": "TypeAlias", "name": "Permission", "underlying": "uint" },
    { "type": "TypeAlias", "name": "LogLevel", "underlying": "int" }
  ],
  "constants": [
    {
      "type": "ConstGroup",
      "typeName": "Permission",
      "useIota": true,
      "iotaExpr": "1 << iota",
      "values": [
        { "name": "PermRead" },
        { "name": "PermWrite" },
        { "name": "PermExecute" }
      ]
    },
    {
      "type": "Const",
      "name": "PermAll",
      "constType": "Permission",
      "value": { "type": "BinaryOp", "op": "|", "left": { "type": "BinaryOp", "op": "|", "left": { "type": "Ref", "name": "PermRead" }, "right": { "type": "Ref", "name": "PermWrite" } }, "right": { "type": "Ref", "name": "PermExecute" } }
    },
    {
      "type": "ConstGroup",
      "typeName": "LogLevel",
      "useIota": true,
      "iotaExpr": "iota",
      "values": [
        { "name": "LogNone" },
        { "name": "LogError" },
        { "name": "LogWarn" },
        { "name": "LogInfo" },
        { "name": "LogDebug" }
      ]
    }
  ],
  "functions": [
    {
      "type": "Func",
      "name": "hasPermission",
      "params": [
        { "name": "perms", "paramType": "Permission" },
        { "name": "flag", "paramType": "Permission" }
      ],
      "returnType": "bool",
      "body": [
        {
          "type": "Return",
          "value": { "type": "BinaryOp", "op": "!=", "left": { "type": "BinaryOp", "op": "&", "left": { "type": "Ref", "name": "perms" }, "right": { "type": "Ref", "name": "flag" } }, "right": { "type": "Literal", "value": 0 } }
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Detect bit-flag pattern**: When defines follow a powers-of-two sequence (0x01, 0x02, 0x04, ...), use ` + "`" + `1 << iota` + "`" + `.
2. **Detect sequential enum pattern**: When defines are consecutive integers starting from 0 or 1, use ` + "`" + `iota` + "`" + ` (with optional offset).
3. **Introduce a named type**: Create a type alias (` + "`" + `type Permission uint` + "`" + `) to provide type safety that raw ` + "`" + `#define` + "`" + ` lacks.
4. **Composite flags**: ` + "`" + `PERM_ALL = READ | WRITE | EXECUTE` + "`" + ` becomes a separate const outside the ` + "`" + `iota` + "`" + ` group, using the component constants.
5. **Common prefix stripping**: ` + "`" + `PERM_READ` + "`" + ` becomes ` + "`" + `PermRead` + "`" + `, ` + "`" + `LOG_ERROR` + "`" + ` becomes ` + "`" + `LogError` + "`" + `. The prefix is retained but transformed to PascalCase.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

type Permission uint

const (
	PermRead    Permission = 1 << iota // 0x01
	PermWrite                          // 0x02
	PermExecute                        // 0x04
)

const PermAll = PermRead | PermWrite | PermExecute

type LogLevel int

const (
	LogNone  LogLevel = iota // 0
	LogError                 // 1
	LogWarn                  // 2
	LogInfo                  // 3
	LogDebug                 // 4
)

func hasPermission(perms, flag Permission) bool {
	return perms&flag != 0
}
` + "`" + `` + "`" + `` + "`" + `

---

## 3. Function-Like Macros: ` + "`" + `#define MAX(a,b)` + "`" + ` to Generic Functions

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define CLAMP(val, lo, hi) (MIN(MAX(val, lo), hi))
#define ABS(x) ((x) >= 0 ? (x) : -(x))
#define STRINGIFY(x) #x
#define CONCAT(a, b) a ## b

int main() {
    int a = MAX(10, 20);
    double b = MIN(3.14, 2.71);
    int c = CLAMP(150, 0, 100);
    int d = ABS(-42);
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "preprocessor": [
    {
      "type": "FunctionMacro",
      "name": "MAX",
      "params": ["a", "b"],
      "body": {
        "type": "TernaryOp",
        "condition": { "type": "BinaryOp", "op": ">", "left": { "type": "NameExpr", "name": "a" }, "right": { "type": "NameExpr", "name": "b" } },
        "thenExpr": { "type": "NameExpr", "name": "a" },
        "elseExpr": { "type": "NameExpr", "name": "b" }
      }
    },
    {
      "type": "FunctionMacro",
      "name": "MIN",
      "params": ["a", "b"],
      "body": {
        "type": "TernaryOp",
        "condition": { "type": "BinaryOp", "op": "<", "left": { "type": "NameExpr", "name": "a" }, "right": { "type": "NameExpr", "name": "b" } },
        "thenExpr": { "type": "NameExpr", "name": "a" },
        "elseExpr": { "type": "NameExpr", "name": "b" }
      }
    },
    {
      "type": "FunctionMacro",
      "name": "CLAMP",
      "params": ["val", "lo", "hi"],
      "body": {
        "type": "CallExpr",
        "callee": "MIN",
        "args": [
          { "type": "CallExpr", "callee": "MAX", "args": [{ "type": "NameExpr", "name": "val" }, { "type": "NameExpr", "name": "lo" }] },
          { "type": "NameExpr", "name": "hi" }
        ]
      }
    },
    {
      "type": "FunctionMacro",
      "name": "ABS",
      "params": ["x"],
      "body": {
        "type": "TernaryOp",
        "condition": { "type": "BinaryOp", "op": ">=", "left": { "type": "NameExpr", "name": "x" }, "right": { "type": "IntLiteral", "value": 0 } },
        "thenExpr": { "type": "NameExpr", "name": "x" },
        "elseExpr": { "type": "UnaryOp", "op": "-", "operand": { "type": "NameExpr", "name": "x" } }
      }
    },
    {
      "type": "FunctionMacro",
      "name": "STRINGIFY",
      "params": ["x"],
      "body": { "type": "StringifyOp", "operand": { "type": "NameExpr", "name": "x" } }
    },
    {
      "type": "FunctionMacro",
      "name": "CONCAT",
      "params": ["a", "b"],
      "body": { "type": "TokenPasteOp", "left": { "type": "NameExpr", "name": "a" }, "right": { "type": "NameExpr", "name": "b" } }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "imports": ["cmp"],
  "functions": [
    {
      "type": "GenericFunc",
      "name": "Max",
      "typeParams": [{ "name": "T", "constraint": "cmp.Ordered" }],
      "params": [
        { "name": "a", "paramType": "T" },
        { "name": "b", "paramType": "T" }
      ],
      "returnType": "T",
      "body": [
        {
          "type": "If",
          "condition": { "type": "BinaryOp", "op": ">", "left": { "type": "Ref", "name": "a" }, "right": { "type": "Ref", "name": "b" } },
          "then": [{ "type": "Return", "value": { "type": "Ref", "name": "a" } }]
        },
        { "type": "Return", "value": { "type": "Ref", "name": "b" } }
      ]
    },
    {
      "type": "GenericFunc",
      "name": "Min",
      "typeParams": [{ "name": "T", "constraint": "cmp.Ordered" }],
      "params": [
        { "name": "a", "paramType": "T" },
        { "name": "b", "paramType": "T" }
      ],
      "returnType": "T",
      "body": [
        {
          "type": "If",
          "condition": { "type": "BinaryOp", "op": "<", "left": { "type": "Ref", "name": "a" }, "right": { "type": "Ref", "name": "b" } },
          "then": [{ "type": "Return", "value": { "type": "Ref", "name": "a" } }]
        },
        { "type": "Return", "value": { "type": "Ref", "name": "b" } }
      ]
    },
    {
      "type": "GenericFunc",
      "name": "Clamp",
      "typeParams": [{ "name": "T", "constraint": "cmp.Ordered" }],
      "params": [
        { "name": "val", "paramType": "T" },
        { "name": "lo", "paramType": "T" },
        { "name": "hi", "paramType": "T" }
      ],
      "returnType": "T",
      "body": [
        { "type": "Return", "value": { "type": "Call", "func": "Min", "args": [{ "type": "Call", "func": "Max", "args": [{ "type": "Ref", "name": "val" }, { "type": "Ref", "name": "lo" }] }, { "type": "Ref", "name": "hi" }] } }
      ]
    },
    {
      "type": "GenericFunc",
      "name": "Abs",
      "typeParams": [{ "name": "T", "constraint": "cmp.Ordered" }],
      "params": [{ "name": "x", "paramType": "T" }],
      "returnType": "T",
      "body": [
        {
          "type": "If",
          "condition": { "type": "BinaryOp", "op": ">=", "left": { "type": "Ref", "name": "x" }, "right": { "type": "Literal", "value": 0 } },
          "then": [{ "type": "Return", "value": { "type": "Ref", "name": "x" } }]
        },
        { "type": "Return", "value": { "type": "UnaryOp", "op": "-", "operand": { "type": "Ref", "name": "x" } } }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Function-like macros become generic functions**: Macros like ` + "`" + `MAX(a,b)` + "`" + ` that operate on comparable types map to ` + "`" + `func Max[T cmp.Ordered](a, b T) T` + "`" + `. The ` + "`" + `cmp.Ordered` + "`" + ` constraint covers all numeric and string types.
2. **Ternary to if/else**: C++ ternary ` + "`" + `(cond) ? a : b` + "`" + ` becomes an ` + "`" + `if/else` + "`" + ` block since Go has no ternary operator.
3. **Macro composition preserved**: ` + "`" + `CLAMP` + "`" + ` calling ` + "`" + `MIN` + "`" + `/` + "`" + `MAX` + "`" + ` becomes ` + "`" + `Clamp` + "`" + ` calling ` + "`" + `Min` + "`" + `/` + "`" + `Max` + "`" + `.
4. **Stringification (` + "`" + `#x` + "`" + `)**: No direct Go equivalent. Emits a comment or uses ` + "`" + `fmt.Sprintf("%v", x)` + "`" + `. For compile-time stringification, suggest ` + "`" + `//go:generate stringer` + "`" + `.
5. **Token pasting (` + "`" + `##` + "`" + `)**: No Go equivalent. Requires code generation. The adapter emits a ` + "`" + `//go:generate` + "`" + ` comment or LLM fallback.
6. **Standard library preference**: For Go 1.21+, prefer ` + "`" + `max()` + "`" + ` and ` + "`" + `min()` + "`" + ` builtins. For Go 1.22+, prefer ` + "`" + `max()` + "`" + `/` + "`" + `min()` + "`" + ` directly.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import "cmp"

func Max[T cmp.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func Min[T cmp.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func Clamp[T cmp.Ordered](val, lo, hi T) T {
	return Min(Max(val, lo), hi)
}

func Abs[T cmp.Ordered](x T) T {
	if x >= 0 {
		return x
	}
	return -x
}

func main() {
	a := Max(10, 20)
	b := Min(3.14, 2.71)
	c := Clamp(150, 0, 100)
	d := Abs(-42)
	_, _, _, _ = a, b, c, d
}
` + "`" + `` + "`" + `` + "`" + `

---

## 4. String Concatenation Macros to ` + "`" + `const` + "`" + ` or ` + "`" + `fmt.Sprintf` + "`" + `

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#define BASE_URL "https://api.example.com"
#define API_VERSION "/v2"
#define ENDPOINT_USERS BASE_URL API_VERSION "/users"
#define ENDPOINT_ITEMS BASE_URL API_VERSION "/items"

#define LOG_PREFIX "[MyApp] "
#define LOG_MSG(msg) LOG_PREFIX msg
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "preprocessor": [
    { "type": "Define", "name": "BASE_URL", "value": { "type": "StringLiteral", "value": "https://api.example.com" } },
    { "type": "Define", "name": "API_VERSION", "value": { "type": "StringLiteral", "value": "/v2" } },
    {
      "type": "Define", "name": "ENDPOINT_USERS",
      "value": {
        "type": "StringConcat",
        "parts": [
          { "type": "MacroRef", "name": "BASE_URL" },
          { "type": "MacroRef", "name": "API_VERSION" },
          { "type": "StringLiteral", "value": "/users" }
        ]
      }
    },
    {
      "type": "Define", "name": "ENDPOINT_ITEMS",
      "value": {
        "type": "StringConcat",
        "parts": [
          { "type": "MacroRef", "name": "BASE_URL" },
          { "type": "MacroRef", "name": "API_VERSION" },
          { "type": "StringLiteral", "value": "/items" }
        ]
      }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "constants": [
    { "name": "BaseURL", "constType": "string", "value": "https://api.example.com" },
    { "name": "APIVersion", "constType": "string", "value": "/v2" },
    {
      "name": "EndpointUsers",
      "constType": "string",
      "value": { "type": "BinaryOp", "op": "+", "left": { "type": "BinaryOp", "op": "+", "left": { "type": "Ref", "name": "BaseURL" }, "right": { "type": "Ref", "name": "APIVersion" } }, "right": { "type": "Literal", "value": "/users" } }
    },
    {
      "name": "EndpointItems",
      "constType": "string",
      "value": { "type": "BinaryOp", "op": "+", "left": { "type": "BinaryOp", "op": "+", "left": { "type": "Ref", "name": "BaseURL" }, "right": { "type": "Ref", "name": "APIVersion" } }, "right": { "type": "Literal", "value": "/items" } }
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Adjacent string literal concatenation**: C preprocessor concatenates adjacent string literals at compile time. In Go, use ` + "`" + `+` + "`" + ` operator on string constants (which the compiler also evaluates at compile time).
2. **Macro references in concatenation**: Resolve to the constant name, using ` + "`" + `+` + "`" + ` for concatenation.
3. **` + "`" + `LOG_MSG(msg)` + "`" + ` style macros**: When the macro takes a string parameter, convert to a function ` + "`" + `func logMsg(msg string) string` + "`" + ` or inline the prefix.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

const (
	BaseURL    = "https://api.example.com"
	APIVersion = "/v2"

	EndpointUsers = BaseURL + APIVersion + "/users"
	EndpointItems = BaseURL + APIVersion + "/items"

	LogPrefix = "[MyApp] "
)

func logMsg(msg string) string {
	return LogPrefix + msg
}
` + "`" + `` + "`" + `` + "`" + `

---

## 5. X-Macros to Code Generation

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
// Define all error codes in one place
#define ERROR_LIST \
    X(OK, 0, "success") \
    X(NOT_FOUND, 1, "not found") \
    X(TIMEOUT, 2, "timeout") \
    X(PERMISSION, 3, "permission denied")

// Generate enum
enum ErrorCode {
    #define X(name, val, str) ERR_##name = val,
    ERROR_LIST
    #undef X
};

// Generate string function
const char* errorString(ErrorCode code) {
    switch (code) {
        #define X(name, val, str) case ERR_##name: return str;
        ERROR_LIST
        #undef X
        default: return "unknown";
    }
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "preprocessor": [
    {
      "type": "XMacro",
      "name": "ERROR_LIST",
      "entries": [
        { "fields": ["OK", 0, "success"] },
        { "fields": ["NOT_FOUND", 1, "not found"] },
        { "fields": ["TIMEOUT", 2, "timeout"] },
        { "fields": ["PERMISSION", 3, "permission denied"] }
      ]
    }
  ],
  "declarations": [
    {
      "type": "EnumDef",
      "name": "ErrorCode",
      "generatedFrom": "XMacro:ERROR_LIST",
      "values": [
        { "name": "ERR_OK", "value": 0 },
        { "name": "ERR_NOT_FOUND", "value": 1 },
        { "name": "ERR_TIMEOUT", "value": 2 },
        { "name": "ERR_PERMISSION", "value": 3 }
      ]
    },
    {
      "type": "FunctionDef",
      "name": "errorString",
      "params": [{ "name": "code", "paramType": "ErrorCode" }],
      "returnType": "const char*",
      "body": [
        {
          "type": "SwitchStmt",
          "expr": { "type": "NameExpr", "name": "code" },
          "cases": [
            { "value": { "type": "NameExpr", "name": "ERR_OK" }, "body": [{ "type": "ReturnStmt", "value": { "type": "StringLiteral", "value": "success" } }] },
            { "value": { "type": "NameExpr", "name": "ERR_NOT_FOUND" }, "body": [{ "type": "ReturnStmt", "value": { "type": "StringLiteral", "value": "not found" } }] },
            { "value": { "type": "NameExpr", "name": "ERR_TIMEOUT" }, "body": [{ "type": "ReturnStmt", "value": { "type": "StringLiteral", "value": "timeout" } }] },
            { "value": { "type": "NameExpr", "name": "ERR_PERMISSION" }, "body": [{ "type": "ReturnStmt", "value": { "type": "StringLiteral", "value": "permission denied" } }] }
          ],
          "default": [{ "type": "ReturnStmt", "value": { "type": "StringLiteral", "value": "unknown" } }]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "main",
  "types": [
    { "type": "TypeAlias", "name": "ErrorCode", "underlying": "int" }
  ],
  "constants": [
    {
      "type": "ConstGroup",
      "typeName": "ErrorCode",
      "useIota": true,
      "values": [
        { "name": "ErrOK" },
        { "name": "ErrNotFound" },
        { "name": "ErrTimeout" },
        { "name": "ErrPermission" }
      ]
    }
  ],
  "functions": [
    {
      "type": "Method",
      "receiver": { "name": "c", "receiverType": "ErrorCode" },
      "name": "String",
      "returnType": "string",
      "body": [
        {
          "type": "Switch",
          "expr": { "type": "Ref", "name": "c" },
          "cases": [
            { "value": { "type": "Ref", "name": "ErrOK" }, "body": [{ "type": "Return", "value": { "type": "Literal", "value": "success" } }] },
            { "value": { "type": "Ref", "name": "ErrNotFound" }, "body": [{ "type": "Return", "value": { "type": "Literal", "value": "not found" } }] },
            { "value": { "type": "Ref", "name": "ErrTimeout" }, "body": [{ "type": "Return", "value": { "type": "Literal", "value": "timeout" } }] },
            { "value": { "type": "Ref", "name": "ErrPermission" }, "body": [{ "type": "Return", "value": { "type": "Literal", "value": "permission denied" } }] }
          ],
          "default": [{ "type": "Return", "value": { "type": "Literal", "value": "unknown" } }]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **X-macro detection**: The adapter recognizes the X-macro pattern: a list macro ` + "`" + `ERROR_LIST` + "`" + ` expanded with different ` + "`" + `#define X(...)` + "`" + ` bodies. It extracts the tabular data.
2. **Enum generation**: The first expansion (enum values) becomes an ` + "`" + `iota` + "`" + ` const group with a named type.
3. **String function**: The second expansion (switch on enum) becomes a ` + "`" + `String() string` + "`" + ` method, satisfying ` + "`" + `fmt.Stringer` + "`" + `.
4. **Alternative: ` + "`" + `//go:generate` + "`" + `**: For large X-macro tables, the adapter may emit a ` + "`" + `//go:generate stringer` + "`" + ` directive or a custom generator instead of inlining the switch.
5. **Name normalization**: ` + "`" + `ERR_NOT_FOUND` + "`" + ` becomes ` + "`" + `ErrNotFound` + "`" + ` (Go-idiomatic error naming).

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

type ErrorCode int

const (
	ErrOK         ErrorCode = iota // 0
	ErrNotFound                    // 1
	ErrTimeout                     // 2
	ErrPermission                  // 3
)

func (c ErrorCode) String() string {
	switch c {
	case ErrOK:
		return "success"
	case ErrNotFound:
		return "not found"
	case ErrTimeout:
		return "timeout"
	case ErrPermission:
		return "permission denied"
	default:
		return "unknown"
	}
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Equivalent | Notes |
|---|---|---|
| ` + "`" + `#define CONSTANT 42` + "`" + ` | ` + "`" + `const Constant = 42` + "`" + ` | Untyped constant, PascalCase name |
| ` + "`" + `#define PI 3.14` + "`" + ` | ` + "`" + `const Pi = 3.14` + "`" + ` | Untyped float64 constant |
| ` + "`" + `#define STR "hello"` + "`" + ` | ` + "`" + `const Str = "hello"` + "`" + ` | String constant |
| ` + "`" + `#define FLAG_A 0x01` + "`" + ` ... (powers of 2) | ` + "`" + `const ( FlagA = 1 << iota; ... )` + "`" + ` | Bit flags with ` + "`" + `iota` + "`" + ` |
| ` + "`" + `#define LEVEL_0 0` + "`" + ` ... (sequential) | ` + "`" + `const ( Level0 = iota; ... )` + "`" + ` | Sequential enum with ` + "`" + `iota` + "`" + ` |
| ` + "`" + `#define MAX(a,b) ((a)>(b)?(a):(b))` + "`" + ` | ` + "`" + `func Max[T cmp.Ordered](a, b T) T` + "`" + ` | Generic function |
| ` + "`" + `#define ABS(x)` + "`" + ` | ` + "`" + `func Abs[T cmp.Ordered](x T) T` + "`" + ` | Generic with constraint |
| ` + "`" + `#x` + "`" + ` (stringify) | ` + "`" + `//go:generate stringer` + "`" + ` or ` + "`" + `fmt.Sprintf` + "`" + ` | No compile-time equivalent |
| ` + "`" + `a ## b` + "`" + ` (token paste) | ` + "`" + `//go:generate` + "`" + ` or manual naming | No Go equivalent |
| Adjacent string concat | ` + "`" + `const S = A + B + "/path"` + "`" + ` | Compile-time string concatenation |
| X-macros | ` + "`" + `iota` + "`" + ` + ` + "`" + `String()` + "`" + ` method | Tabular code generation |
| ` + "`" + `SCREAMING_SNAKE` + "`" + ` naming | ` + "`" + `PascalCase` + "`" + ` | Go exported naming convention |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/preprocessor/ifdef_buildtags.md",
			Body: `# Preprocessor ifdef to Go Build Tags and Platform Files

> C++ conditional compilation directives mapped to Go build constraints, platform-specific files, and build tags.

---

## 1. Platform Detection: ` + "`" + `#ifdef _WIN32` + "`" + ` to ` + "`" + `//go:build` + "`" + ` Directives

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <string>

#ifdef _WIN32
    #include <windows.h>
    std::string getHomeDir() {
        char path[MAX_PATH];
        GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH);
        return std::string(path);
    }
    std::string pathSeparator() {
        return "\\";
    }
#elif defined(__linux__)
    #include <unistd.h>
    #include <pwd.h>
    std::string getHomeDir() {
        struct passwd* pw = getpwuid(getuid());
        return std::string(pw->pw_dir);
    }
    std::string pathSeparator() {
        return "/";
    }
#elif defined(__APPLE__)
    #include <unistd.h>
    #include <pwd.h>
    std::string getHomeDir() {
        struct passwd* pw = getpwuid(getuid());
        return std::string(pw->pw_dir);
    }
    std::string pathSeparator() {
        return "/";
    }
#endif
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "ConditionalBlock",
      "branches": [
        {
          "condition": { "type": "Defined", "name": "_WIN32" },
          "declarations": [
            {
              "type": "FunctionDef",
              "name": "getHomeDir",
              "returnType": "std::string",
              "body": [
                { "type": "VarDecl", "name": "path", "declType": "char[]", "arraySize": { "type": "NameExpr", "name": "MAX_PATH" } },
                { "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "GetEnvironmentVariableA", "args": [{ "type": "StringLiteral", "value": "USERPROFILE" }, { "type": "NameExpr", "name": "path" }, { "type": "NameExpr", "name": "MAX_PATH" }] } },
                { "type": "ReturnStmt", "value": { "type": "ConstructExpr", "className": "std::string", "args": [{ "type": "NameExpr", "name": "path" }] } }
              ]
            },
            {
              "type": "FunctionDef",
              "name": "pathSeparator",
              "returnType": "std::string",
              "body": [
                { "type": "ReturnStmt", "value": { "type": "StringLiteral", "value": "\\" } }
              ]
            }
          ]
        },
        {
          "condition": { "type": "Defined", "name": "__linux__" },
          "declarations": [
            {
              "type": "FunctionDef",
              "name": "getHomeDir",
              "returnType": "std::string",
              "body": [
                { "type": "VarDecl", "name": "pw", "declType": "struct passwd*", "init": { "type": "CallExpr", "callee": "getpwuid", "args": [{ "type": "CallExpr", "callee": "getuid" }] } },
                { "type": "ReturnStmt", "value": { "type": "MemberExpr", "object": "pw", "member": "pw_dir" } }
              ]
            },
            {
              "type": "FunctionDef",
              "name": "pathSeparator",
              "returnType": "std::string",
              "body": [
                { "type": "ReturnStmt", "value": { "type": "StringLiteral", "value": "/" } }
              ]
            }
          ]
        },
        {
          "condition": { "type": "Defined", "name": "__APPLE__" },
          "declarations": [
            {
              "type": "FunctionDef",
              "name": "getHomeDir",
              "returnType": "std::string",
              "body": [
                { "type": "VarDecl", "name": "pw", "declType": "struct passwd*", "init": { "type": "CallExpr", "callee": "getpwuid", "args": [{ "type": "CallExpr", "callee": "getuid" }] } },
                { "type": "ReturnStmt", "value": { "type": "MemberExpr", "object": "pw", "member": "pw_dir" } }
              ]
            },
            {
              "type": "FunctionDef",
              "name": "pathSeparator",
              "returnType": "std::string",
              "body": [
                { "type": "ReturnStmt", "value": { "type": "StringLiteral", "value": "/" } }
              ]
            }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "MultiFileModule",
  "package": "platform",
  "files": [
    {
      "filename": "home_windows.go",
      "buildConstraint": "windows",
      "imports": ["os"],
      "functions": [
        {
          "type": "Func",
          "name": "getHomeDir",
          "returnType": "string",
          "body": [
            { "type": "Return", "value": { "type": "Call", "func": "os.Getenv", "args": [{ "type": "Literal", "value": "USERPROFILE" }] } }
          ]
        },
        {
          "type": "Func",
          "name": "pathSeparator",
          "returnType": "string",
          "body": [
            { "type": "Return", "value": { "type": "Literal", "value": "\\\\" } }
          ]
        }
      ]
    },
    {
      "filename": "home_linux.go",
      "buildConstraint": "linux",
      "imports": ["os/user"],
      "functions": [
        {
          "type": "Func",
          "name": "getHomeDir",
          "returnType": "string",
          "body": [
            { "type": "MultiAssign", "names": ["u", "_"], "value": { "type": "Call", "func": "user.Current" } },
            { "type": "Return", "value": { "type": "FieldAccess", "object": "u", "field": "HomeDir" } }
          ]
        },
        {
          "type": "Func",
          "name": "pathSeparator",
          "returnType": "string",
          "body": [
            { "type": "Return", "value": { "type": "Literal", "value": "/" } }
          ]
        }
      ]
    },
    {
      "filename": "home_darwin.go",
      "buildConstraint": "darwin",
      "imports": ["os/user"],
      "functions": [
        {
          "type": "Func",
          "name": "getHomeDir",
          "returnType": "string",
          "body": [
            { "type": "MultiAssign", "names": ["u", "_"], "value": { "type": "Call", "func": "user.Current" } },
            { "type": "Return", "value": { "type": "FieldAccess", "object": "u", "field": "HomeDir" } }
          ]
        },
        {
          "type": "Func",
          "name": "pathSeparator",
          "returnType": "string",
          "body": [
            { "type": "Return", "value": { "type": "Literal", "value": "/" } }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Split into platform files**: Each ` + "`" + `#ifdef` + "`" + ` / ` + "`" + `#elif` + "`" + ` branch for a platform macro becomes a separate ` + "`" + `.go` + "`" + ` file with the appropriate suffix (` + "`" + `_windows.go` + "`" + `, ` + "`" + `_linux.go` + "`" + `, ` + "`" + `_darwin.go` + "`" + `).
2. **Build constraints**: Each file gets a ` + "`" + `//go:build <platform>` + "`" + ` directive at the top. Go's build system selects the correct file at compile time.
3. **Platform macro mapping**:
   - ` + "`" + `_WIN32` + "`" + ` / ` + "`" + `_WIN64` + "`" + ` maps to ` + "`" + `//go:build windows` + "`" + `
   - ` + "`" + `__linux__` + "`" + ` maps to ` + "`" + `//go:build linux` + "`" + `
   - ` + "`" + `__APPLE__` + "`" + ` maps to ` + "`" + `//go:build darwin` + "`" + `
   - ` + "`" + `__unix__` + "`" + ` maps to ` + "`" + `//go:build unix` + "`" + ` (available since Go 1.19)
4. **API translation**: Platform-specific C APIs are translated to their Go ` + "`" + `os` + "`" + ` / ` + "`" + `os/user` + "`" + ` equivalents. ` + "`" + `GetEnvironmentVariableA("USERPROFILE")` + "`" + ` becomes ` + "`" + `os.Getenv("USERPROFILE")` + "`" + `. ` + "`" + `getpwuid(getuid())` + "`" + ` becomes ` + "`" + `user.Current()` + "`" + `.
5. **Merge identical branches**: When linux and darwin share the same implementation, consider merging into a ` + "`" + `_unix.go` + "`" + ` file with ` + "`" + `//go:build unix` + "`" + ` instead.
6. **Prefer ` + "`" + `os.UserHomeDir` + "`" + `**: The adapter recognizes this home-directory pattern and may suggest ` + "`" + `os.UserHomeDir()` + "`" + ` as a cross-platform alternative, eliminating the need for platform files entirely.

### Go Output

**home_windows.go**
` + "`" + `` + "`" + `` + "`" + `go
//go:build windows

package platform

import "os"

func getHomeDir() string {
	return os.Getenv("USERPROFILE")
}

func pathSeparator() string {
	return "\\"
}
` + "`" + `` + "`" + `` + "`" + `

**home_linux.go**
` + "`" + `` + "`" + `` + "`" + `go
//go:build linux

package platform

import "os/user"

func getHomeDir() string {
	u, _ := user.Current()
	return u.HomeDir
}

func pathSeparator() string {
	return "/"
}
` + "`" + `` + "`" + `` + "`" + `

**home_darwin.go**
` + "`" + `` + "`" + `` + "`" + `go
//go:build darwin

package platform

import "os/user"

func getHomeDir() string {
	u, _ := user.Current()
	return u.HomeDir
}

func pathSeparator() string {
	return "/"
}
` + "`" + `` + "`" + `` + "`" + `

**Cross-platform alternative (preferred):**
` + "`" + `` + "`" + `` + "`" + `go
package platform

import (
	"os"
	"path/filepath"
)

func getHomeDir() string {
	dir, _ := os.UserHomeDir()
	return dir
}

func pathSeparator() string {
	return string(filepath.Separator)
}
` + "`" + `` + "`" + `` + "`" + `

---

## 2. Debug Conditionals: ` + "`" + `#ifdef DEBUG` + "`" + ` to Build Tags

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <iostream>
#include <string>

#ifdef DEBUG
    #define LOG_DEBUG(msg) std::cerr << "[DEBUG] " << msg << std::endl
    #define ASSERT(cond, msg) \
        if (!(cond)) { \
            std::cerr << "ASSERT FAILED: " << msg << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::abort(); \
        }
#else
    #define LOG_DEBUG(msg)
    #define ASSERT(cond, msg)
#endif

void processItem(const std::string& item) {
    LOG_DEBUG("Processing: " + item);
    ASSERT(!item.empty(), "item must not be empty");

    // actual processing
    std::cout << "Processed: " << item << std::endl;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "preprocessor": [
    {
      "type": "ConditionalBlock",
      "branches": [
        {
          "condition": { "type": "Defined", "name": "DEBUG" },
          "defines": [
            {
              "type": "FunctionMacro",
              "name": "LOG_DEBUG",
              "params": ["msg"],
              "body": {
                "type": "ExprStmt",
                "expr": { "type": "BinaryOp", "op": "<<", "left": { "type": "NameExpr", "name": "std::cerr" }, "right": { "type": "NameExpr", "name": "msg" } }
              }
            },
            {
              "type": "FunctionMacro",
              "name": "ASSERT",
              "params": ["cond", "msg"],
              "body": {
                "type": "IfStmt",
                "condition": { "type": "UnaryOp", "op": "!", "operand": { "type": "NameExpr", "name": "cond" } },
                "then": [{ "type": "CallExpr", "callee": "std::abort" }]
              }
            }
          ]
        },
        {
          "condition": "else",
          "defines": [
            { "type": "FunctionMacro", "name": "LOG_DEBUG", "params": ["msg"], "body": { "type": "Empty" } },
            { "type": "FunctionMacro", "name": "ASSERT", "params": ["cond", "msg"], "body": { "type": "Empty" } }
          ]
        }
      ]
    }
  ],
  "declarations": [
    {
      "type": "FunctionDef",
      "name": "processItem",
      "params": [{ "name": "item", "paramType": "const std::string&" }],
      "returnType": "void",
      "body": [
        { "type": "MacroCall", "name": "LOG_DEBUG", "args": [{ "type": "StringLiteral", "value": "Processing: " }] },
        { "type": "MacroCall", "name": "ASSERT", "args": [{ "type": "UnaryOp", "op": "!", "operand": { "type": "CallExpr", "callee": "item.empty" } }, { "type": "StringLiteral", "value": "item must not be empty" }] }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "MultiFileModule",
  "package": "main",
  "files": [
    {
      "filename": "debug.go",
      "buildConstraint": "debug",
      "imports": ["fmt", "os", "runtime"],
      "functions": [
        {
          "type": "Func",
          "name": "logDebug",
          "params": [{ "name": "msg", "paramType": "string" }],
          "body": [
            { "type": "Call", "func": "fmt.Fprintf", "args": [{ "type": "Ref", "name": "os.Stderr" }, { "type": "Literal", "value": "[DEBUG] %s\\n" }, { "type": "Ref", "name": "msg" }] }
          ]
        },
        {
          "type": "Func",
          "name": "assert",
          "params": [
            { "name": "cond", "paramType": "bool" },
            { "name": "msg", "paramType": "string" }
          ],
          "body": [
            {
              "type": "If",
              "condition": { "type": "UnaryOp", "op": "!", "operand": { "type": "Ref", "name": "cond" } },
              "then": [
                { "type": "Call", "func": "panic", "args": [{ "type": "Call", "func": "fmt.Sprintf", "args": [{ "type": "Literal", "value": "ASSERT FAILED: %s" }, { "type": "Ref", "name": "msg" }] }] }
              ]
            }
          ]
        }
      ]
    },
    {
      "filename": "debug_release.go",
      "buildConstraint": "!debug",
      "functions": [
        {
          "type": "Func",
          "name": "logDebug",
          "params": [{ "name": "_", "paramType": "string" }],
          "body": []
        },
        {
          "type": "Func",
          "name": "assert",
          "params": [
            { "name": "_", "paramType": "bool" },
            { "name": "_", "paramType": "string" }
          ],
          "body": []
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Custom build tags**: ` + "`" + `#ifdef DEBUG` + "`" + ` maps to ` + "`" + `//go:build debug` + "`" + `. Build with ` + "`" + `go build -tags debug` + "`" + ` to enable.
2. **Two-file pattern**: Create ` + "`" + `debug.go` + "`" + ` (with ` + "`" + `//go:build debug` + "`" + `) containing the real implementations, and ` + "`" + `debug_release.go` + "`" + ` (with ` + "`" + `//go:build !debug` + "`" + `) containing no-op stubs.
3. **Function signatures must match**: Both files must define the same functions with the same signatures so the package compiles regardless of which tag is active.
4. **` + "`" + `__FILE__` + "`" + ` / ` + "`" + `__LINE__` + "`" + `**: Map to ` + "`" + `runtime.Caller(1)` + "`" + ` for file and line information in Go. This is a runtime operation rather than compile-time.
5. **` + "`" + `std::abort()` + "`" + `**: Maps to ` + "`" + `panic()` + "`" + ` or ` + "`" + `os.Exit(1)` + "`" + `. For assertions, ` + "`" + `panic` + "`" + ` is more idiomatic as it produces a stack trace.

### Go Output

**debug.go**
` + "`" + `` + "`" + `` + "`" + `go
//go:build debug

package main

import (
	"fmt"
	"os"
)

func logDebug(msg string) {
	fmt.Fprintf(os.Stderr, "[DEBUG] %s\n", msg)
}

func assert(cond bool, msg string) {
	if !cond {
		panic(fmt.Sprintf("ASSERT FAILED: %s", msg))
	}
}
` + "`" + `` + "`" + `` + "`" + `

**debug_release.go**
` + "`" + `` + "`" + `` + "`" + `go
//go:build !debug

package main

func logDebug(_ string) {}

func assert(_ bool, _ string) {}
` + "`" + `` + "`" + `` + "`" + `

**process.go** (main logic, no build tag)
` + "`" + `` + "`" + `` + "`" + `go
package main

import "fmt"

func processItem(item string) {
	logDebug("Processing: " + item)
	assert(item != "", "item must not be empty")

	fmt.Println("Processed:", item)
}
` + "`" + `` + "`" + `` + "`" + `

---

## 3. Header Guards: ` + "`" + `#ifndef` + "`" + ` / ` + "`" + `#define` + "`" + ` / ` + "`" + `#endif` + "`" + ` (Removed)

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#ifndef MATH_UTILS_H
#define MATH_UTILS_H

#include <cmath>

inline double distance(double x1, double y1, double x2, double y2) {
    return std::sqrt((x2-x1)*(x2-x1) + (y2-y1)*(y2-y1));
}

inline double degToRad(double deg) {
    return deg * M_PI / 180.0;
}

#endif // MATH_UTILS_H
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "preprocessor": [
    {
      "type": "HeaderGuard",
      "name": "MATH_UTILS_H"
    }
  ],
  "declarations": [
    {
      "type": "FunctionDef",
      "name": "distance",
      "isInline": true,
      "params": [
        { "name": "x1", "paramType": "double" },
        { "name": "y1", "paramType": "double" },
        { "name": "x2", "paramType": "double" },
        { "name": "y2", "paramType": "double" }
      ],
      "returnType": "double",
      "body": [
        {
          "type": "ReturnStmt",
          "value": {
            "type": "CallExpr",
            "callee": "std::sqrt",
            "args": [{ "type": "BinaryOp", "op": "+", "left": { "type": "BinaryOp", "op": "*" }, "right": { "type": "BinaryOp", "op": "*" } }]
          }
        }
      ]
    },
    {
      "type": "FunctionDef",
      "name": "degToRad",
      "isInline": true,
      "params": [{ "name": "deg", "paramType": "double" }],
      "returnType": "double",
      "body": [
        {
          "type": "ReturnStmt",
          "value": {
            "type": "BinaryOp", "op": "/",
            "left": { "type": "BinaryOp", "op": "*", "left": { "type": "NameExpr", "name": "deg" }, "right": { "type": "NameExpr", "name": "M_PI" } },
            "right": { "type": "FloatLiteral", "value": 180.0 }
          }
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "Module",
  "name": "mathutils",
  "imports": ["math"],
  "functions": [
    {
      "type": "Func",
      "name": "Distance",
      "params": [
        { "name": "x1", "paramType": "float64" },
        { "name": "y1", "paramType": "float64" },
        { "name": "x2", "paramType": "float64" },
        { "name": "y2", "paramType": "float64" }
      ],
      "returnType": "float64",
      "body": [
        {
          "type": "Return",
          "value": {
            "type": "Call",
            "func": "math.Sqrt",
            "args": [{
              "type": "BinaryOp", "op": "+",
              "left": { "type": "BinaryOp", "op": "*", "left": { "type": "BinaryOp", "op": "-", "left": { "type": "Ref", "name": "x2" }, "right": { "type": "Ref", "name": "x1" } }, "right": { "type": "BinaryOp", "op": "-", "left": { "type": "Ref", "name": "x2" }, "right": { "type": "Ref", "name": "x1" } } },
              "right": { "type": "BinaryOp", "op": "*", "left": { "type": "BinaryOp", "op": "-", "left": { "type": "Ref", "name": "y2" }, "right": { "type": "Ref", "name": "y1" } }, "right": { "type": "BinaryOp", "op": "-", "left": { "type": "Ref", "name": "y2" }, "right": { "type": "Ref", "name": "y1" } } }
            }]
          }
        }
      ]
    },
    {
      "type": "Func",
      "name": "DegToRad",
      "params": [{ "name": "deg", "paramType": "float64" }],
      "returnType": "float64",
      "body": [
        {
          "type": "Return",
          "value": {
            "type": "BinaryOp", "op": "/",
            "left": { "type": "BinaryOp", "op": "*", "left": { "type": "Ref", "name": "deg" }, "right": { "type": "Ref", "name": "math.Pi" } },
            "right": { "type": "Literal", "value": 180.0 }
          }
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Header guards are removed entirely**: Go has no header files and no include guard mechanism. Each ` + "`" + `.go` + "`" + ` file belongs to a package, and the compiler handles deduplication.
2. **Header name to package name**: ` + "`" + `MATH_UTILS_H` + "`" + ` suggests a package name ` + "`" + `mathutils` + "`" + `. The adapter derives the package from the guard name or the filename.
3. **` + "`" + `inline` + "`" + ` keyword**: Dropped. Go inlines functions automatically based on compiler heuristics. The ` + "`" + `inline` + "`" + ` qualifier has no Go equivalent.
4. **` + "`" + `M_PI` + "`" + `**: Maps to ` + "`" + `math.Pi` + "`" + `.
5. **` + "`" + `#pragma once` + "`" + `**: Also removed, same as header guards.
6. **` + "`" + `#include <cmath>` + "`" + `**: Maps to ` + "`" + `import "math"` + "`" + `.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package mathutils

import "math"

func Distance(x1, y1, x2, y2 float64) float64 {
	dx := x2 - x1
	dy := y2 - y1
	return math.Sqrt(dx*dx + dy*dy)
}

func DegToRad(deg float64) float64 {
	return deg * math.Pi / 180.0
}
` + "`" + `` + "`" + `` + "`" + `

---

## 4. Cross-Platform Socket Code: ` + "`" + `#ifdef` + "`" + ` to Platform Files

### C++ Source

` + "`" + `` + "`" + `` + "`" + `cpp
#include <string>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")

    void initNetwork() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    void cleanupNetwork() {
        WSACleanup();
    }

    int createSocket() {
        return static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    }

    void closeSocket(int fd) {
        closesocket(fd);
    }
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>

    void initNetwork() {
        // no-op on Unix
    }

    void cleanupNetwork() {
        // no-op on Unix
    }

    int createSocket() {
        return socket(AF_INET, SOCK_STREAM, 0);
    }

    void closeSocket(int fd) {
        close(fd);
    }
#endif

int main() {
    initNetwork();

    int sock = createSocket();
    // ... use socket ...
    closeSocket(sock);

    cleanupNetwork();
    return 0;
}
` + "`" + `` + "`" + `` + "`" + `

### AST (Simplified)

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "TranslationUnit",
  "declarations": [
    {
      "type": "ConditionalBlock",
      "branches": [
        {
          "condition": { "type": "Defined", "name": "_WIN32" },
          "declarations": [
            { "type": "FunctionDef", "name": "initNetwork", "returnType": "void", "body": [{ "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "WSAStartup" } }] },
            { "type": "FunctionDef", "name": "cleanupNetwork", "returnType": "void", "body": [{ "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "WSACleanup" } }] },
            { "type": "FunctionDef", "name": "createSocket", "returnType": "int", "body": [{ "type": "ReturnStmt", "value": { "type": "CallExpr", "callee": "socket" } }] },
            { "type": "FunctionDef", "name": "closeSocket", "params": [{ "name": "fd", "paramType": "int" }], "returnType": "void", "body": [{ "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "closesocket" } }] }
          ]
        },
        {
          "condition": "else",
          "declarations": [
            { "type": "FunctionDef", "name": "initNetwork", "returnType": "void", "body": [] },
            { "type": "FunctionDef", "name": "cleanupNetwork", "returnType": "void", "body": [] },
            { "type": "FunctionDef", "name": "createSocket", "returnType": "int", "body": [{ "type": "ReturnStmt", "value": { "type": "CallExpr", "callee": "socket" } }] },
            { "type": "FunctionDef", "name": "closeSocket", "params": [{ "name": "fd", "paramType": "int" }], "returnType": "void", "body": [{ "type": "ExprStmt", "expr": { "type": "CallExpr", "callee": "close" } }] }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### IR

` + "`" + `` + "`" + `` + "`" + `json
{
  "type": "MultiFileModule",
  "package": "main",
  "comment": "Go's net package abstracts platform differences. Direct conversion to platform files is possible but net.Dial/net.Listen is preferred.",
  "files": [
    {
      "filename": "main.go",
      "imports": ["fmt", "net"],
      "functions": [
        {
          "type": "Func",
          "name": "main",
          "body": [
            {
              "type": "MultiAssign",
              "names": ["conn", "err"],
              "value": { "type": "Call", "func": "net.Dial", "args": [{ "type": "Literal", "value": "tcp" }, { "type": "Literal", "value": "localhost:8080" }] }
            },
            {
              "type": "If",
              "condition": { "type": "BinaryOp", "op": "!=", "left": { "type": "Ref", "name": "err" }, "right": { "type": "Nil" } },
              "then": [
                { "type": "Call", "func": "fmt.Println", "args": [{ "type": "Literal", "value": "Error:" }, { "type": "Ref", "name": "err" }] },
                { "type": "Return" }
              ]
            },
            { "type": "Defer", "call": { "type": "Call", "func": "conn.Close" } }
          ]
        }
      ]
    }
  ]
}
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Prefer Go standard library abstractions**: Go's ` + "`" + `net` + "`" + ` package already handles cross-platform socket differences internally. The entire ` + "`" + `#ifdef` + "`" + ` block can be replaced with ` + "`" + `net.Dial` + "`" + ` / ` + "`" + `net.Listen` + "`" + `.
2. **Eliminate init/cleanup**: ` + "`" + `WSAStartup` + "`" + `/` + "`" + `WSACleanup` + "`" + ` have no Go equivalents because the Go runtime handles network initialization.
3. **When platform files are still needed**: If the C++ code uses platform-specific APIs beyond what Go's standard library abstracts (e.g., raw syscalls, ioctl, platform-specific socket options), then split into ` + "`" + `_windows.go` + "`" + ` and ` + "`" + `_unix.go` + "`" + ` files using ` + "`" + `syscall` + "`" + ` or ` + "`" + `golang.org/x/sys` + "`" + `.
4. **` + "`" + `#else` + "`" + ` for non-Windows**: In Go, use ` + "`" + `//go:build !windows` + "`" + ` or the more specific ` + "`" + `//go:build unix` + "`" + ` constraint.
5. **` + "`" + `closesocket` + "`" + ` vs ` + "`" + `close` + "`" + `**: Both map to ` + "`" + `conn.Close()` + "`" + ` via the ` + "`" + `net.Conn` + "`" + ` interface.

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package main

import (
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer conn.Close()

	// ... use conn ...
}
` + "`" + `` + "`" + `` + "`" + `

---

## Key Rules Table

| C++ Pattern | Go Equivalent | Notes |
|---|---|---|
| ` + "`" + `#ifdef _WIN32` + "`" + ` | ` + "`" + `//go:build windows` + "`" + ` in ` + "`" + `_windows.go` + "`" + ` | File-level build constraint |
| ` + "`" + `#ifdef __linux__` + "`" + ` | ` + "`" + `//go:build linux` + "`" + ` in ` + "`" + `_linux.go` + "`" + ` | Linux-specific file |
| ` + "`" + `#ifdef __APPLE__` + "`" + ` | ` + "`" + `//go:build darwin` + "`" + ` in ` + "`" + `_darwin.go` + "`" + ` | macOS-specific file |
| ` + "`" + `#ifdef __unix__` + "`" + ` | ` + "`" + `//go:build unix` + "`" + ` in ` + "`" + `_unix.go` + "`" + ` | Unix (linux + darwin + freebsd + ...) |
| ` + "`" + `#ifdef DEBUG` + "`" + ` | ` + "`" + `//go:build debug` + "`" + ` | Custom tag, build with ` + "`" + `-tags debug` + "`" + ` |
| ` + "`" + `#ifndef NDEBUG` + "`" + ` | ` + "`" + `//go:build !release` + "`" + ` | Inverted tag for debug builds |
| ` + "`" + `#ifndef HEADER_H` + "`" + ` / ` + "`" + `#define HEADER_H` + "`" + ` | (removed) | Go has no header guards |
| ` + "`" + `#pragma once` + "`" + ` | (removed) | Go has no header guards |
| ` + "`" + `#include <header>` + "`" + ` | ` + "`" + `import "package"` + "`" + ` | Package import |
| ` + "`" + `#else` + "`" + ` | ` + "`" + `//go:build !tag` + "`" + ` in separate file | Negated constraint in stub file |
| ` + "`" + `#elif defined(X)` + "`" + ` | Additional ` + "`" + `_platform.go` + "`" + ` file | One file per platform branch |
| ` + "`" + `__FILE__` + "`" + ` | ` + "`" + `runtime.Caller(0)` + "`" + ` | Runtime file name |
| ` + "`" + `__LINE__` + "`" + ` | ` + "`" + `runtime.Caller(0)` + "`" + ` | Runtime line number |
| ` + "`" + `__func__` + "`" + ` | (reflect or hardcode) | No direct equivalent |
| Platform socket APIs | ` + "`" + `net.Dial` + "`" + ` / ` + "`" + `net.Listen` + "`" + ` | Go stdlib abstracts platform |
| ` + "`" + `WSAStartup` + "`" + ` / ` + "`" + `WSACleanup` + "`" + ` | (removed) | Go runtime handles init |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/templates/generics.md",
			Body: `# C++ Templates to Go Generics

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <vector>
#include <string>
#include <algorithm>

// Function template
template<typename T>
T max(T a, T b) {
    return (a > b) ? a : b;
}

// Function template with multiple type parameters
template<typename T, typename U>
auto add(T a, U b) -> decltype(a + b) {
    return a + b;
}

// SFINAE-constrained function template
template<typename T>
typename std::enable_if<std::is_arithmetic<T>::value, T>::type
abs_val(T x) {
    return (x < 0) ? -x : x;
}

// Class template
template<typename T>
class Stack {
public:
    Stack() = default;

    void push(T value) {
        items_.push_back(value);
    }

    T pop() {
        T top = items_.back();
        items_.pop_back();
        return top;
    }

    T peek() const {
        return items_.back();
    }

    bool empty() const {
        return items_.empty();
    }

    size_t size() const {
        return items_.size();
    }

private:
    std::vector<T> items_;
};

// Class template with multiple type parameters
template<typename K, typename V>
class Pair {
public:
    Pair(K key, V value) : key_(key), value_(value) {}

    K key() const { return key_; }
    V value() const { return value_; }

private:
    K key_;
    V value_;
};
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
[
  {
    "type": "TemplateDecl",
    "params": [
      {"name": "T", "kind": "typename"}
    ],
    "declaration": {
      "type": "Function",
      "name": "max",
      "return_type": {"name": "T"},
      "params": [
        {"name": "a", "type": {"name": "T"}},
        {"name": "b", "type": {"name": "T"}}
      ],
      "body": [
        {
          "type": "ReturnStmt",
          "value": {
            "type": "BinaryExpr",
            "operator": ">",
            "left": {"type": "Identifier", "name": "a"},
            "right": {"type": "Identifier", "name": "b"}
          }
        }
      ],
      "template_params": [{"name": "T", "kind": "typename"}]
    }
  },
  {
    "type": "TemplateDecl",
    "params": [
      {"name": "T", "kind": "typename"}
    ],
    "declaration": {
      "type": "Class",
      "kind": "class",
      "name": "Stack",
      "fields": [
        {
          "name": "items_",
          "type": {
            "name": "std::vector",
            "template_args": [{"name": "T"}]
          },
          "access": "private"
        }
      ],
      "constructors": [
        {"params": [], "access": "public"}
      ],
      "methods": [
        {
          "name": "push",
          "return_type": {"name": "void"},
          "params": [{"name": "value", "type": {"name": "T"}}],
          "access": "public"
        },
        {
          "name": "pop",
          "return_type": {"name": "T"},
          "params": [],
          "access": "public"
        },
        {
          "name": "peek",
          "return_type": {"name": "T"},
          "params": [],
          "access": "public",
          "const": true
        },
        {
          "name": "empty",
          "return_type": {"name": "bool"},
          "params": [],
          "access": "public",
          "const": true
        },
        {
          "name": "size",
          "return_type": {"name": "size_t"},
          "params": [],
          "access": "public",
          "const": true
        }
      ],
      "template_params": [{"name": "T", "kind": "typename"}]
    }
  },
  {
    "type": "TemplateDecl",
    "params": [
      {"name": "K", "kind": "typename"},
      {"name": "V", "kind": "typename"}
    ],
    "declaration": {
      "type": "Class",
      "kind": "class",
      "name": "Pair",
      "fields": [
        {"name": "key_", "type": {"name": "K"}, "access": "private"},
        {"name": "value_", "type": {"name": "V"}, "access": "private"}
      ],
      "constructors": [{
        "params": [
          {"name": "key", "type": {"name": "K"}},
          {"name": "value", "type": {"name": "V"}}
        ],
        "init_list": [
          {"member": "key_", "value": "key"},
          {"member": "value_", "value": "value"}
        ],
        "access": "public"
      }],
      "methods": [
        {
          "name": "key",
          "return_type": {"name": "K"},
          "params": [],
          "access": "public",
          "const": true
        },
        {
          "name": "value",
          "return_type": {"name": "V"},
          "params": [],
          "access": "public",
          "const": true
        }
      ],
      "template_params": [
        {"name": "K", "kind": "typename"},
        {"name": "V", "kind": "typename"}
      ]
    }
  }
]
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
[
  {
    "type": "FuncDecl",
    "name": "Max",
    "type_params": ["T"],
    "params": [
      {"name": "a", "type": {"kind": "primitive", "name": "T"}},
      {"name": "b", "type": {"kind": "primitive", "name": "T"}}
    ],
    "returns": [{"type": {"kind": "primitive", "name": "T"}}],
    "body": [
      {
        "type": "IfStmt",
        "cond": {"type": "BinaryExpr", "op": ">", "left": "a", "right": "b"},
        "then": [{"type": "ReturnStmt", "values": ["a"]}],
        "else": [{"type": "ReturnStmt", "values": ["b"]}]
      }
    ]
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "Stack",
    "type_params": ["T"],
    "fields": [
      {"name": "items", "type": {"kind": "slice", "elem_type": {"kind": "primitive", "name": "T"}}}
    ]
  },
  {
    "type": "FuncDecl",
    "name": "NewStack",
    "type_params": ["T"],
    "params": [],
    "returns": [{"type": {"kind": "pointer", "name": "*Stack[T]"}}],
    "body": [
      {"type": "ReturnStmt", "values": ["&Stack[T]{}"]}
    ]
  },
  {
    "type": "FuncDecl",
    "name": "Push",
    "receiver": {"name": "s", "type": {"kind": "pointer", "name": "*Stack[T]"}},
    "params": [{"name": "value", "type": {"kind": "primitive", "name": "T"}}],
    "body": [
      {"type": "AssignStmt", "lhs": ["s.items"], "op": "=", "rhs": ["append(s.items, value)"]}
    ]
  },
  {
    "type": "FuncDecl",
    "name": "Pop",
    "receiver": {"name": "s", "type": {"kind": "pointer", "name": "*Stack[T]"}},
    "returns": [{"type": {"kind": "primitive", "name": "T"}}],
    "body": [
      {"type": "VarDecl", "name": "top", "value": "s.items[len(s.items)-1]"},
      {"type": "AssignStmt", "lhs": ["s.items"], "op": "=", "rhs": ["s.items[:len(s.items)-1]"]},
      {"type": "ReturnStmt", "values": ["top"]}
    ]
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "Pair",
    "type_params": ["K", "V"],
    "fields": [
      {"name": "Key", "type": {"kind": "primitive", "name": "K"}},
      {"name": "Value", "type": {"kind": "primitive", "name": "V"}}
    ]
  },
  {
    "type": "FuncDecl",
    "name": "NewPair",
    "type_params": ["K", "V"],
    "params": [
      {"name": "key", "type": {"kind": "primitive", "name": "K"}},
      {"name": "value", "type": {"kind": "primitive", "name": "V"}}
    ],
    "returns": [{"type": {"kind": "pointer", "name": "*Pair[K, V]"}}],
    "body": [
      {"type": "ReturnStmt", "values": ["&Pair[K, V]{Key: key, Value: value}"]}
    ]
  }
]
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **` + "`" + `typename T` + "`" + ` → ` + "`" + `[T any]` + "`" + `** as the default generic constraint; unconstrained template parameters map to ` + "`" + `any` + "`" + `
2. **Comparison-based templates → ` + "`" + `[T cmp.Ordered]` + "`" + `** when the body uses ` + "`" + `<` + "`" + `, ` + "`" + `>` + "`" + `, ` + "`" + `<=` + "`" + `, ` + "`" + `>=` + "`" + ` operators on type parameters
3. **` + "`" + `std::enable_if<std::is_arithmetic<T>>` + "`" + ` → ` + "`" + `[T constraints.Integer | constraints.Float]` + "`" + `** mapping SFINAE to Go type constraints from the ` + "`" + `golang.org/x/exp/constraints` + "`" + ` package
4. **` + "`" + `std::enable_if<std::is_integral<T>>` + "`" + ` → ` + "`" + `[T constraints.Integer]` + "`" + `** for integral-only constraints
5. **Class template → generic struct** with ` + "`" + `type_params` + "`" + ` propagated to the ` + "`" + `TypeDecl` + "`" + ` and all method receivers
6. **Constructor → ` + "`" + `NewX[T]()` + "`" + ` factory** preserving type parameters in the factory function signature
7. **` + "`" + `std::vector<T>` + "`" + ` field → ` + "`" + `[]T` + "`" + ` slice** the template argument flows through ` + "`" + `lowerType` + "`" + ` into slice element type
8. **Multiple type params → ` + "`" + `[K, V any]` + "`" + `** or ` + "`" + `[K comparable, V any]` + "`" + ` when K is used as a map key
9. **` + "`" + `auto` + "`" + ` return type with ` + "`" + `decltype` + "`" + ` → inferred** Go generics infer return types from the constraint or explicit return type annotation
10. **Template param ` + "`" + `Kind: "int"` + "`" + ` (non-type params) → constant parameter** converted to a regular function parameter of the corresponding Go type

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package containers

import "cmp"

// Max returns the greater of two ordered values.
func Max[T cmp.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

// Add returns the sum of two numeric values.
func Add[T, U Numeric, R Numeric](a T, b U) R {
	return R(a) + R(b)
}

// AbsVal returns the absolute value of a numeric type.
func AbsVal[T Numeric](x T) T {
	if x < 0 {
		return -x
	}
	return x
}

// Numeric is a constraint for arithmetic types (mirrors std::is_arithmetic).
type Numeric interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
		~float32 | ~float64
}

// Stack is a generic LIFO container.
type Stack[T any] struct {
	items []T
}

// NewStack creates an empty stack.
func NewStack[T any]() *Stack[T] {
	return &Stack[T]{}
}

// Push adds a value to the top of the stack.
func (s *Stack[T]) Push(value T) {
	s.items = append(s.items, value)
}

// Pop removes and returns the top value from the stack.
func (s *Stack[T]) Pop() T {
	top := s.items[len(s.items)-1]
	s.items = s.items[:len(s.items)-1]
	return top
}

// Peek returns the top value without removing it.
func (s *Stack[T]) Peek() T {
	return s.items[len(s.items)-1]
}

// Empty reports whether the stack has no elements.
func (s *Stack[T]) Empty() bool {
	return len(s.items) == 0
}

// Size returns the number of elements in the stack.
func (s *Stack[T]) Size() int {
	return len(s.items)
}

// Pair holds two values of potentially different types.
type Pair[K, V any] struct {
	Key   K
	Value V
}

// NewPair creates a Pair with the given key and value.
func NewPair[K, V any](key K, value V) *Pair[K, V] {
	return &Pair[K, V]{Key: key, Value: value}
}
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| ` + "`" + `template<typename T>` + "`" + ` | ` + "`" + `[T any]` + "`" + ` | ` + "`" + `TemplateDecl` + "`" + ` + ` + "`" + `TemplateParam{Kind: "typename"}` + "`" + ` | ` + "`" + `FuncDecl.TypeParams` + "`" + ` / ` + "`" + `TypeDecl.TypeParams` + "`" + ` |
| ` + "`" + `template<typename T> class X` + "`" + ` | ` + "`" + `type X[T any] struct` + "`" + ` | ` + "`" + `TemplateDecl` + "`" + ` wrapping ` + "`" + `Class` + "`" + ` | ` + "`" + `TypeDecl{TypeParams: ["T"]}` + "`" + ` |
| ` + "`" + `template<typename T> T fn(T)` + "`" + ` | ` + "`" + `func Fn[T any](a T) T` + "`" + ` | ` + "`" + `TemplateDecl` + "`" + ` wrapping ` + "`" + `Function` + "`" + ` | ` + "`" + `FuncDecl{TypeParams: ["T"]}` + "`" + ` |
| ` + "`" + `std::enable_if<is_arithmetic<T>>` + "`" + ` | ` + "`" + `[T Numeric]` + "`" + ` constraint interface | ` + "`" + `TypeRef` + "`" + ` with SFINAE pattern | ` + "`" + `TypeDecl{Kind: "interface"}` + "`" + ` for constraint |
| ` + "`" + `std::vector<T>` + "`" + ` member | ` + "`" + `[]T` + "`" + ` field | ` + "`" + `TypeRef{Name: "std::vector", TemplateArgs: [T]}` + "`" + ` | ` + "`" + `TypeRef{Kind: "slice", ElemType: T}` + "`" + ` |
| ` + "`" + `operator>` + "`" + ` on type param | ` + "`" + `cmp.Ordered` + "`" + ` constraint | ` + "`" + `BinaryExpr{Operator: ">"}` + "`" + ` | Detected during adapt phase |
| Multiple ` + "`" + `typename K, V` + "`" + ` | ` + "`" + `[K, V any]` + "`" + ` | Multiple ` + "`" + `TemplateParam` + "`" + ` nodes | Multiple entries in ` + "`" + `TypeParams` + "`" + ` |
| Non-type ` + "`" + `template<int N>` + "`" + ` | Regular parameter ` + "`" + `n int` + "`" + ` | ` + "`" + `TemplateParam{Kind: "int"}` + "`" + ` | ` + "`" + `ParamDecl{Name: "n", Type: int}` + "`" + ` |
| ` + "`" + `size_t` + "`" + ` return type | ` + "`" + `int` + "`" + ` | ` + "`" + `TypeRef{Name: "size_t"}` + "`" + ` | ` + "`" + `TypeRef{Kind: "primitive", Name: "uint"}` + "`" + ` mapped to ` + "`" + `int` + "`" + ` for idiomatic Go |
| Default template arg ` + "`" + `T = int` + "`" + ` | No direct equivalent; use type inference | ` + "`" + `TemplateParam{Default: "int"}` + "`" + ` | Omitted; callers specify type |
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/strategies/templates/specialization.md",
			Body: `# Template Specialization to Go Patterns

## Pipeline: C++ → AST → IR → Go

### C++ Source Pattern

` + "`" + `` + "`" + `` + "`" + `cpp
#include <string>
#include <sstream>
#include <vector>
#include <type_traits>

// Primary template
template<typename T>
class Serializer {
public:
    std::string serialize(const T& value) {
        std::ostringstream oss;
        oss << value;
        return oss.str();
    }

    T deserialize(const std::string& data) {
        std::istringstream iss(data);
        T value;
        iss >> value;
        return value;
    }
};

// Full specialization for std::string
template<>
class Serializer<std::string> {
public:
    std::string serialize(const std::string& value) {
        return "\"" + value + "\"";
    }

    std::string deserialize(const std::string& data) {
        return data.substr(1, data.size() - 2);
    }
};

// Full specialization for bool
template<>
class Serializer<bool> {
public:
    std::string serialize(const bool& value) {
        return value ? "true" : "false";
    }

    bool deserialize(const std::string& data) {
        return data == "true";
    }
};

// Partial specialization for pointers
template<typename T>
class Container {
public:
    void store(T value) {
        data_ = value;
    }
    T get() const { return data_; }
private:
    T data_;
};

// Partial specialization for pointer types
template<typename T>
class Container<T*> {
public:
    void store(T* value) {
        data_ = *value;
        is_set_ = true;
    }
    T get() const { return data_; }
    bool has_value() const { return is_set_; }
private:
    T data_;
    bool is_set_ = false;
};

// Partial specialization for std::vector
template<typename T>
class Container<std::vector<T>> {
public:
    void store(std::vector<T> value) {
        data_ = std::move(value);
    }
    std::vector<T> get() const { return data_; }
    size_t count() const { return data_.size(); }
private:
    std::vector<T> data_;
};

// Compile-time dispatch with constexpr if (C++17)
template<typename T>
std::string to_debug_string(const T& value) {
    if constexpr (std::is_integral_v<T>) {
        return "int:" + std::to_string(value);
    } else if constexpr (std::is_floating_point_v<T>) {
        return "float:" + std::to_string(value);
    } else {
        return "other:" + std::string(value);
    }
}
` + "`" + `` + "`" + `` + "`" + `

### AST Representation

` + "`" + `` + "`" + `` + "`" + `json
[
  {
    "type": "TemplateDecl",
    "params": [{"name": "T", "kind": "typename"}],
    "declaration": {
      "type": "Class",
      "kind": "class",
      "name": "Serializer",
      "methods": [
        {
          "name": "serialize",
          "return_type": {"name": "std::string"},
          "params": [{"name": "value", "type": {"name": "T", "const": true, "reference": true}}],
          "access": "public"
        },
        {
          "name": "deserialize",
          "return_type": {"name": "T"},
          "params": [{"name": "data", "type": {"name": "std::string", "const": true, "reference": true}}],
          "access": "public"
        }
      ],
      "template_params": [{"name": "T", "kind": "typename"}]
    }
  },
  {
    "type": "TemplateDecl",
    "params": [],
    "declaration": {
      "type": "Class",
      "kind": "class",
      "name": "Serializer",
      "methods": [
        {
          "name": "serialize",
          "return_type": {"name": "std::string"},
          "params": [{"name": "value", "type": {"name": "std::string", "const": true, "reference": true}}],
          "access": "public"
        },
        {
          "name": "deserialize",
          "return_type": {"name": "std::string"},
          "params": [{"name": "data", "type": {"name": "std::string", "const": true, "reference": true}}],
          "access": "public"
        }
      ],
      "template_params": []
    }
  },
  {
    "type": "TemplateDecl",
    "params": [{"name": "T", "kind": "typename"}],
    "declaration": {
      "type": "Class",
      "kind": "class",
      "name": "Container",
      "fields": [{"name": "data_", "type": {"name": "T"}, "access": "private"}],
      "template_params": [{"name": "T", "kind": "typename"}]
    }
  },
  {
    "type": "TemplateDecl",
    "params": [{"name": "T", "kind": "typename"}],
    "declaration": {
      "type": "Class",
      "kind": "class",
      "name": "Container",
      "fields": [
        {"name": "data_", "type": {"name": "T"}, "access": "private"},
        {"name": "is_set_", "type": {"name": "bool"}, "access": "private"}
      ],
      "methods": [
        {
          "name": "store",
          "return_type": {"name": "void"},
          "params": [{"name": "value", "type": {"name": "T", "pointer": true}}],
          "access": "public"
        },
        {
          "name": "has_value",
          "return_type": {"name": "bool"},
          "params": [],
          "access": "public",
          "const": true
        }
      ],
      "template_params": [{"name": "T", "kind": "typename"}]
    }
  },
  {
    "type": "TemplateDecl",
    "params": [{"name": "T", "kind": "typename"}],
    "declaration": {
      "type": "Function",
      "name": "to_debug_string",
      "return_type": {"name": "std::string"},
      "params": [{"name": "value", "type": {"name": "T", "const": true, "reference": true}}],
      "body": [
        {
          "type": "IfStmt",
          "condition": {"type": "RawExpr", "text": "std::is_integral_v<T>"},
          "then": [{"type": "ReturnStmt"}],
          "else": [
            {
              "type": "IfStmt",
              "condition": {"type": "RawExpr", "text": "std::is_floating_point_v<T>"},
              "then": [{"type": "ReturnStmt"}],
              "else": [{"type": "ReturnStmt"}]
            }
          ]
        }
      ],
      "template_params": [{"name": "T", "kind": "typename"}]
    }
  }
]
` + "`" + `` + "`" + `` + "`" + `

### IR Representation

` + "`" + `` + "`" + `` + "`" + `json
[
  {
    "type": "TypeDecl",
    "kind": "interface",
    "name": "Serializer",
    "comment": "Interface for type-specific serialization",
    "methods": [
      {
        "name": "Serialize",
        "params": [{"name": "value", "type": {"kind": "primitive", "name": "any"}}],
        "returns": [{"type": {"kind": "primitive", "name": "string"}}]
      },
      {
        "name": "Deserialize",
        "params": [{"name": "data", "type": {"kind": "primitive", "name": "string"}}],
        "returns": [
          {"type": {"kind": "primitive", "name": "any"}},
          {"type": {"kind": "primitive", "name": "error"}}
        ]
      }
    ]
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "StringSerializer",
    "comment": "From C++ full specialization Serializer<std::string>"
  },
  {
    "type": "FuncDecl",
    "name": "Serialize",
    "receiver": {"name": "s", "type": {"kind": "pointer", "name": "*StringSerializer"}},
    "params": [{"name": "value", "type": {"kind": "primitive", "name": "any"}}],
    "returns": [{"type": {"kind": "primitive", "name": "string"}}]
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "BoolSerializer",
    "comment": "From C++ full specialization Serializer<bool>"
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "Container",
    "type_params": ["T"],
    "fields": [
      {"name": "Data", "type": {"kind": "primitive", "name": "T"}}
    ]
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "PointerContainer",
    "type_params": ["T"],
    "fields": [
      {"name": "Data", "type": {"kind": "primitive", "name": "T"}},
      {"name": "IsSet", "type": {"kind": "primitive", "name": "bool"}}
    ],
    "comment": "From C++ partial specialization Container<T*>"
  },
  {
    "type": "TypeDecl",
    "kind": "struct",
    "name": "SliceContainer",
    "type_params": ["T"],
    "fields": [
      {"name": "Data", "type": {"kind": "slice", "elem_type": {"kind": "primitive", "name": "T"}}}
    ],
    "comment": "From C++ partial specialization Container<std::vector<T>>"
  },
  {
    "type": "FuncDecl",
    "name": "ToDebugString",
    "params": [{"name": "value", "type": {"kind": "primitive", "name": "any"}}],
    "returns": [{"type": {"kind": "primitive", "name": "string"}}],
    "body": [
      {
        "type": "SwitchStmt",
        "tag": null,
        "cases": [
          {"values": ["int"], "body": [{"type": "ReturnStmt"}]},
          {"values": ["float64"], "body": [{"type": "ReturnStmt"}]},
          {"default": true, "body": [{"type": "ReturnStmt"}]}
        ]
      }
    ],
    "comment": "From C++ constexpr if with type traits"
  }
]
` + "`" + `` + "`" + `` + "`" + `

### Conversion Strategy

1. **Full specialization → concrete type** each ` + "`" + `template<> class X<ConcreteType>` + "`" + ` becomes a separate named struct (e.g., ` + "`" + `Serializer<std::string>` + "`" + ` becomes ` + "`" + `StringSerializer` + "`" + `) with no type parameters
2. **Partial specialization → constrained generic** each ` + "`" + `template<typename T> class X<T*>` + "`" + ` becomes a separate generic struct with a descriptive name (e.g., ` + "`" + `Container<T*>` + "`" + ` becomes ` + "`" + `PointerContainer[T any]` + "`" + `)
3. **Primary template with specializations → interface + implementations** when full specializations exist for a class template, extract a common interface and implement it on each concrete struct
4. **` + "`" + `constexpr if` + "`" + ` with type traits → type switch** compile-time dispatch on ` + "`" + `std::is_integral_v` + "`" + `, ` + "`" + `std::is_floating_point_v` + "`" + `, etc. becomes a runtime ` + "`" + `switch v := value.(type)` + "`" + ` in Go
5. **` + "`" + `std::is_arithmetic` + "`" + ` → ` + "`" + `Numeric` + "`" + ` constraint interface** SFINAE type traits map to Go constraint interfaces with union types (` + "`" + `~int | ~float64 | ...` + "`" + `)
6. **` + "`" + `std::is_integral` + "`" + ` → ` + "`" + `constraints.Integer` + "`" + `** or a custom ` + "`" + `Integer` + "`" + ` constraint interface
7. **` + "`" + `std::is_floating_point` + "`" + ` → ` + "`" + `constraints.Float` + "`" + `** or a custom ` + "`" + `Float` + "`" + ` constraint interface
8. **Specialization hierarchy → factory function** provide a ` + "`" + `NewSerializer[T any]()` + "`" + ` that returns the correct implementation via type switch for common concrete types
9. **Partial specialization for ` + "`" + `T*` + "`" + ` → optional pattern** pointer partial specializations often model optional values; convert to ` + "`" + `*T` + "`" + ` or a custom optional wrapper in Go
10. **Partial specialization for ` + "`" + `vector<T>` + "`" + ` → slice-specific type** creates a named type wrapping ` + "`" + `[]T` + "`" + ` with additional methods like ` + "`" + `Count()` + "`" + `

### Go Output

` + "`" + `` + "`" + `` + "`" + `go
package serializer

import (
	"fmt"
	"strconv"
)

// Serializer defines the interface for type-specific serialization.
type Serializer[T any] interface {
	Serialize(value T) string
	Deserialize(data string) (T, error)
}

// StringSerializer handles string serialization (from template<> Serializer<std::string>).
type StringSerializer struct{}

// Serialize wraps the string in quotes.
func (s *StringSerializer) Serialize(value string) string {
	return "\"" + value + "\""
}

// Deserialize strips surrounding quotes.
func (s *StringSerializer) Deserialize(data string) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("invalid string data: %s", data)
	}
	return data[1 : len(data)-1], nil
}

// BoolSerializer handles bool serialization (from template<> Serializer<bool>).
type BoolSerializer struct{}

// Serialize converts bool to "true" or "false".
func (s *BoolSerializer) Serialize(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// Deserialize parses "true" or "false".
func (s *BoolSerializer) Deserialize(data string) (bool, error) {
	return data == "true", nil
}

// IntSerializer handles integer serialization (from primary template).
type IntSerializer struct{}

// Serialize converts int to its string representation.
func (s *IntSerializer) Serialize(value int) string {
	return strconv.Itoa(value)
}

// Deserialize parses a string as int.
func (s *IntSerializer) Deserialize(data string) (int, error) {
	return strconv.Atoi(data)
}

// Container holds a single value (from primary template).
type Container[T any] struct {
	Data T
}

// NewContainer creates a Container with the given value.
func NewContainer[T any](value T) *Container[T] {
	return &Container[T]{Data: value}
}

// Store sets the container value.
func (c *Container[T]) Store(value T) {
	c.Data = value
}

// Get returns the stored value.
func (c *Container[T]) Get() T {
	return c.Data
}

// PointerContainer holds an optional value (from partial specialization Container<T*>).
type PointerContainer[T any] struct {
	Data  T
	IsSet bool
}

// Store dereferences the pointer and stores the value.
func (c *PointerContainer[T]) Store(value *T) {
	if value != nil {
		c.Data = *value
		c.IsSet = true
	}
}

// Get returns the stored value.
func (c *PointerContainer[T]) Get() T {
	return c.Data
}

// HasValue reports whether a value has been stored.
func (c *PointerContainer[T]) HasValue() bool {
	return c.IsSet
}

// SliceContainer holds a slice of values (from partial specialization Container<vector<T>>).
type SliceContainer[T any] struct {
	Data []T
}

// Store replaces the stored slice.
func (c *SliceContainer[T]) Store(value []T) {
	c.Data = value
}

// Get returns the stored slice.
func (c *SliceContainer[T]) Get() []T {
	return c.Data
}

// Count returns the number of elements.
func (c *SliceContainer[T]) Count() int {
	return len(c.Data)
}

// ToDebugString returns a type-prefixed debug representation (from constexpr if).
func ToDebugString(value any) string {
	switch v := value.(type) {
	case int:
		return "int:" + strconv.Itoa(v)
	case int64:
		return "int:" + strconv.FormatInt(v, 10)
	case float64:
		return "float:" + strconv.FormatFloat(v, 'f', -1, 64)
	case float32:
		return "float:" + strconv.FormatFloat(float64(v), 'f', -1, 32)
	case string:
		return "other:" + v
	default:
		return "other:" + fmt.Sprint(v)
	}
}
` + "`" + `` + "`" + `` + "`" + `

### Key Rules

| C++ Pattern | Go Equivalent | AST Node | IR Node |
|-------------|---------------|----------|---------|
| ` + "`" + `template<> class X<string>` + "`" + ` | ` + "`" + `type StringX struct{}` + "`" + ` (concrete) | ` + "`" + `TemplateDecl{Params: []}` + "`" + ` wrapping ` + "`" + `Class` + "`" + ` | ` + "`" + `TypeDecl` + "`" + ` with no ` + "`" + `TypeParams` + "`" + ` |
| ` + "`" + `template<> class X<bool>` + "`" + ` | ` + "`" + `type BoolX struct{}` + "`" + ` (concrete) | ` + "`" + `TemplateDecl{Params: []}` + "`" + ` wrapping ` + "`" + `Class` + "`" + ` | ` + "`" + `TypeDecl` + "`" + ` with no ` + "`" + `TypeParams` + "`" + ` |
| ` + "`" + `template<typename T> class X<T*>` + "`" + ` | ` + "`" + `type PointerX[T any] struct{}` + "`" + ` | ` + "`" + `TemplateDecl` + "`" + ` wrapping ` + "`" + `Class` + "`" + ` (pointer pattern) | ` + "`" + `TypeDecl{TypeParams: ["T"]}` + "`" + ` |
| ` + "`" + `template<typename T> class X<vector<T>>` + "`" + ` | ` + "`" + `type SliceX[T any] struct{}` + "`" + ` | ` + "`" + `TemplateDecl` + "`" + ` wrapping ` + "`" + `Class` + "`" + ` (vector pattern) | ` + "`" + `TypeDecl{TypeParams: ["T"]}` + "`" + ` |
| ` + "`" + `constexpr if (is_integral_v<T>)` + "`" + ` | ` + "`" + `switch v := value.(type)` + "`" + ` | ` + "`" + `IfStmt` + "`" + ` with type-trait ` + "`" + `RawExpr` + "`" + ` condition | ` + "`" + `SwitchStmt` + "`" + ` (type switch) |
| ` + "`" + `std::is_integral_v<T>` + "`" + ` | ` + "`" + `case int, int64:` + "`" + ` | ` + "`" + `RawExpr` + "`" + ` in condition | ` + "`" + `CaseClause{Values: [int types]}` + "`" + ` |
| ` + "`" + `std::is_floating_point_v<T>` + "`" + ` | ` + "`" + `case float32, float64:` + "`" + ` | ` + "`" + `RawExpr` + "`" + ` in condition | ` + "`" + `CaseClause{Values: [float types]}` + "`" + ` |
| Primary template + specializations | Interface + concrete impls | Multiple ` + "`" + `TemplateDecl` + "`" + ` with same class name | ` + "`" + `TypeDecl{Kind: "interface"}` + "`" + ` + concrete ` + "`" + `TypeDecl` + "`" + ` nodes |
| ` + "`" + `std::to_string(value)` + "`" + ` | ` + "`" + `strconv.Itoa(v)` + "`" + ` / ` + "`" + `fmt.Sprint(v)` + "`" + ` | ` + "`" + `CallExpr` + "`" + ` with ` + "`" + `ScopeExpr{Scope: "std"}` + "`" + ` | ` + "`" + `CallExpr{Func: "strconv.Itoa"}` + "`" + ` |
| Specialization selection (compile-time) | Factory or type switch (runtime) | Multiple ` + "`" + `TemplateDecl` + "`" + ` nodes | ` + "`" + `FuncDecl` + "`" + ` with ` + "`" + `SwitchStmt` + "`" + ` body |
`,
		},
	)
}
