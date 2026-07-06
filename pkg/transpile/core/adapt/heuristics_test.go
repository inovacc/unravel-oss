package adapt

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
)

func TestDefaultHeuristics_Count(t *testing.T) {
	h := DefaultHeuristics()

	if len(h) == 0 {
		t.Error("expected non-empty default heuristics")
	}
}

func TestHeuristic_RAIIMatch(t *testing.T) {
	h := heuristicRAIIToDefer()

	tests := []struct {
		name  string
		node  ir.Node
		match bool
	}{
		{
			name: "Close method",
			node: &ir.ExprStmt{Expr: &ir.MethodCallExpr{
				Receiver: &ir.IdentExpr{Name: "f"},
				Method:   "Close",
			}},
			match: true,
		},
		{
			name: "Unlock method",
			node: &ir.ExprStmt{Expr: &ir.MethodCallExpr{
				Receiver: &ir.IdentExpr{Name: "mu"},
				Method:   "Unlock",
			}},
			match: true,
		},
		{
			name:  "non-RAII call",
			node:  &ir.ExprStmt{Expr: &ir.CallExpr{Func: "fmt.Println"}},
			match: false,
		},
		{
			name:  "non-statement",
			node:  &ir.VarDecl{Name: "x"},
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.Match(tt.node)
			if got != tt.match {
				t.Errorf("Match() = %v, want %v", got, tt.match)
			}
		})
	}
}

func TestHeuristic_RAIIApply(t *testing.T) {
	h := heuristicRAIIToDefer()

	node := &ir.ExprStmt{Expr: &ir.MethodCallExpr{
		Receiver: &ir.IdentExpr{Name: "f"},
		Method:   "Close",
	}}

	result := h.Apply(node)

	if _, ok := result.(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt, got %T", result)
	}
}

func TestHeuristic_CoutMatch(t *testing.T) {
	h := heuristicCoutToFmt()

	node := &ir.ExprStmt{Expr: &ir.CallExpr{Func: "fmt.Print"}}

	if !h.Match(node) {
		t.Error("expected Match() = true for fmt.Print")
	}

	nonMatch := &ir.ExprStmt{Expr: &ir.CallExpr{Func: "doSomething"}}

	if h.Match(nonMatch) {
		t.Error("expected Match() = false for doSomething")
	}
}

func TestHeuristic_CerrMatch(t *testing.T) {
	h := heuristicCerrToStderr()

	node := &ir.ExprStmt{Expr: &ir.CallExpr{Func: "std.cerr"}}

	if !h.Match(node) {
		t.Error("expected Match() = true for std.cerr")
	}
}

func TestHeuristic_CerrApply(t *testing.T) {
	h := heuristicCerrToStderr()

	node := &ir.ExprStmt{Expr: &ir.CallExpr{
		Func: "std.cerr",
		Args: []ir.Expr{&ir.LiteralExpr{Kind: "string", Value: `"error"`}},
	}}

	result := h.Apply(node)

	stmt, ok := result.(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected *ir.ExprStmt, got %T", result)
	}

	call, ok := stmt.Expr.(*ir.CallExpr)
	if !ok {
		t.Fatalf("expected *ir.CallExpr, got %T", stmt.Expr)
	}

	if call.Func != "fmt.Fprintln" {
		t.Errorf("Func = %q, want %q", call.Func, "fmt.Fprintln")
	}

	// First arg should be os.Stderr
	if len(call.Args) < 2 {
		t.Fatalf("expected at least 2 args, got %d", len(call.Args))
	}

	ident, ok := call.Args[0].(*ir.IdentExpr)
	if !ok {
		t.Fatalf("expected *ir.IdentExpr as first arg, got %T", call.Args[0])
	}

	if ident.Name != "os.Stderr" {
		t.Errorf("first arg = %q, want %q", ident.Name, "os.Stderr")
	}
}

func TestHeuristic_CoutApply(t *testing.T) {
	h := heuristicCoutToFmt()

	node := &ir.ExprStmt{Expr: &ir.CallExpr{
		Func: "fmt.Print",
		Args: []ir.Expr{&ir.LiteralExpr{Kind: "string", Value: `"hello"`}},
	}}

	result := h.Apply(node)
	stmt := result.(*ir.ExprStmt)
	call := stmt.Expr.(*ir.CallExpr)

	if call.Func != "fmt.Println" {
		t.Errorf("Func = %q, want %q", call.Func, "fmt.Println")
	}
}

func TestHeuristic_IteratorMatch(t *testing.T) {
	h := heuristicIteratorToRange()

	// Should match: for loop with != end() condition
	node := &ir.ForStmt{
		Cond: &ir.BinaryExpr{
			Left: &ir.IdentExpr{Name: "it"},
			Op:   "!=",
			Right: &ir.CallExpr{
				Func: "end",
			},
		},
		Body: []ir.Node{},
	}

	if !h.Match(node) {
		t.Error("expected Match() = true for iterator pattern")
	}

	// Should not match: regular for loop
	nonMatch := &ir.ForStmt{
		Cond: &ir.BinaryExpr{
			Left:  &ir.IdentExpr{Name: "i"},
			Op:    "<",
			Right: &ir.LiteralExpr{Kind: "int", Value: "10"},
		},
		Body: []ir.Node{},
	}

	if h.Match(nonMatch) {
		t.Error("expected Match() = false for regular for loop")
	}

	// Should not match: different node type
	if h.Match(&ir.VarDecl{Name: "x"}) {
		t.Error("expected Match() = false for VarDecl")
	}
}

func TestHeuristic_IteratorApply(t *testing.T) {
	h := heuristicIteratorToRange()

	node := &ir.ForStmt{
		Cond: &ir.BinaryExpr{
			Left: &ir.IdentExpr{Name: "it"},
			Op:   "!=",
			Right: &ir.CallExpr{
				Func: "end",
			},
		},
		Body: []ir.Node{
			&ir.ExprStmt{Expr: &ir.IdentExpr{Name: "process"}},
		},
	}

	result := h.Apply(node)

	rangeStmt, ok := result.(*ir.RangeStmt)
	if !ok {
		t.Fatalf("expected *ir.RangeStmt, got %T", result)
	}

	if rangeStmt.Value != "_" {
		t.Errorf("Value = %q, want %q", rangeStmt.Value, "_")
	}

	if len(rangeStmt.Body) != 1 {
		t.Errorf("expected 1 body stmt, got %d", len(rangeStmt.Body))
	}
}

func TestHeuristic_SingletonMatch(t *testing.T) {
	h := heuristicSingletonToSyncOnce()

	// Should match: function with "instance" variable
	node := &ir.FuncDecl{
		Name: "GetInstance",
		Body: []ir.Node{
			&ir.VarDecl{Name: "instance", Type: &ir.TypeRef{Kind: ir.KindPointer, Name: "*Singleton"}},
		},
	}

	if !h.Match(node) {
		t.Error("expected Match() = true for singleton pattern")
	}

	// Should match with "Instance" too
	node2 := &ir.FuncDecl{
		Name: "GetInstance",
		Body: []ir.Node{
			&ir.VarDecl{Name: "Instance", Type: &ir.TypeRef{Kind: ir.KindPointer, Name: "*Singleton"}},
		},
	}

	if !h.Match(node2) {
		t.Error("expected Match() = true for Instance pattern")
	}

	// Should not match
	nonMatch := &ir.FuncDecl{
		Name: "RegularFunc",
		Body: []ir.Node{
			&ir.VarDecl{Name: "x", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
		},
	}

	if h.Match(nonMatch) {
		t.Error("expected Match() = false for non-singleton")
	}

	// Should not match non-FuncDecl
	if h.Match(&ir.VarDecl{Name: "instance"}) {
		t.Error("expected Match() = false for VarDecl")
	}
}

func TestHeuristic_SingletonApply(t *testing.T) {
	h := heuristicSingletonToSyncOnce()

	node := &ir.FuncDecl{
		Name: "GetInstance",
		Body: []ir.Node{
			&ir.VarDecl{Name: "instance"},
		},
	}

	result := h.Apply(node)

	fn, ok := result.(*ir.FuncDecl)
	if !ok {
		t.Fatalf("expected *ir.FuncDecl, got %T", result)
	}

	if fn.Comment == "" {
		t.Error("expected sync.Once comment")
	}
}

func TestHeuristic_ThreadMatch(t *testing.T) {
	h := heuristicThreadToGoroutine()

	node := &ir.VarDecl{
		Name: "t",
		Type: &ir.TypeRef{Name: "/* goroutine */"},
	}

	if !h.Match(node) {
		t.Error("expected Match() = true for thread")
	}

	// Non-match: different type
	nonMatch := &ir.VarDecl{
		Name: "t",
		Type: &ir.TypeRef{Name: "int"},
	}

	if h.Match(nonMatch) {
		t.Error("expected Match() = false for non-thread")
	}

	// Non-match: nil type
	if h.Match(&ir.VarDecl{Name: "t"}) {
		t.Error("expected Match() = false for nil type")
	}

	// Non-match: non-VarDecl
	if h.Match(&ir.ExprStmt{Expr: &ir.IdentExpr{Name: "x"}}) {
		t.Error("expected Match() = false for non-VarDecl")
	}
}

func TestHeuristic_ThreadApply(t *testing.T) {
	h := heuristicThreadToGoroutine()

	node := &ir.VarDecl{
		Name: "t",
		Type: &ir.TypeRef{Name: "/* goroutine */"},
	}

	result := h.Apply(node)

	stmt, ok := result.(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected *ir.ExprStmt, got %T", result)
	}

	call, ok := stmt.Expr.(*ir.CallExpr)
	if !ok {
		t.Fatalf("expected *ir.CallExpr, got %T", stmt.Expr)
	}

	if call.Func != "go func()" {
		t.Errorf("Func = %q, want %q", call.Func, "go func()")
	}
}

func TestHeuristic_MutexMatch(t *testing.T) {
	h := heuristicMutexToSync()

	node := &ir.VarDecl{
		Name: "mu",
		Type: &ir.TypeRef{Name: "sync.Mutex"},
	}

	if !h.Match(node) {
		t.Error("expected Match() = true for mutex")
	}

	// Non-match
	if h.Match(&ir.VarDecl{Name: "mu", Type: &ir.TypeRef{Name: "int"}}) {
		t.Error("expected Match() = false for non-mutex")
	}

	if h.Match(&ir.VarDecl{Name: "mu"}) {
		t.Error("expected Match() = false for nil type")
	}
}

func TestHeuristic_MutexApply(t *testing.T) {
	h := heuristicMutexToSync()

	node := &ir.VarDecl{
		Name: "mu",
		Type: &ir.TypeRef{Name: "sync.Mutex"},
	}

	result := h.Apply(node)
	// Should return the node unchanged
	if result != node {
		t.Error("expected same node returned")
	}
}

func TestHeuristic_AtomicMatch(t *testing.T) {
	h := heuristicAtomicToSyncAtomic()

	node := &ir.VarDecl{
		Name: "counter",
		Type: &ir.TypeRef{Name: "atomic.Value"},
	}

	if !h.Match(node) {
		t.Error("expected Match() = true for atomic")
	}

	if h.Match(&ir.VarDecl{Name: "x", Type: &ir.TypeRef{Name: "int"}}) {
		t.Error("expected Match() = false for non-atomic")
	}

	if h.Match(&ir.VarDecl{Name: "x"}) {
		t.Error("expected Match() = false for nil type")
	}
}

func TestHeuristic_AtomicApply(t *testing.T) {
	h := heuristicAtomicToSyncAtomic()

	node := &ir.VarDecl{
		Name: "counter",
		Type: &ir.TypeRef{Name: "atomic.Value"},
	}

	result := h.Apply(node)
	if result != node {
		t.Error("expected same node returned")
	}
}

func TestHeuristic_RAIIMatchRelease(t *testing.T) {
	h := heuristicRAIIToDefer()

	node := &ir.ExprStmt{Expr: &ir.MethodCallExpr{
		Receiver: &ir.IdentExpr{Name: "ptr"},
		Method:   "Release",
	}}

	if !h.Match(node) {
		t.Error("expected Match() = true for Release")
	}
}

func TestHeuristic_RAIIMatchDestroy(t *testing.T) {
	h := heuristicRAIIToDefer()

	node := &ir.ExprStmt{Expr: &ir.MethodCallExpr{
		Receiver: &ir.IdentExpr{Name: "resource"},
		Method:   "Destroy",
	}}

	if !h.Match(node) {
		t.Error("expected Match() = true for Destroy")
	}
}
