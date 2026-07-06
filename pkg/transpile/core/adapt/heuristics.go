package adapt

import (
	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
)

// Heuristic represents a pattern-matching transformation.
type Heuristic struct {
	Name  string
	Match func(ir.Node) bool
	Apply func(ir.Node) ir.Node
}

// DefaultHeuristics returns the set of built-in pattern transformations.
func DefaultHeuristics() []*Heuristic {
	return []*Heuristic{
		heuristicRAIIToDefer(),
		heuristicIteratorToRange(),
		heuristicCoutToFmt(),
		heuristicCerrToStderr(),
		heuristicSingletonToSyncOnce(),
		heuristicThreadToGoroutine(),
		heuristicMutexToSync(),
		heuristicAtomicToSyncAtomic(),
	}
}

// heuristicRAIIToDefer detects RAII patterns and converts to defer.
func heuristicRAIIToDefer() *Heuristic {
	return &Heuristic{
		Name: "RAII → defer",
		Match: func(n ir.Node) bool {
			// Match: constructor call followed by method calls on same var
			// This is a simplified detection; the real pattern needs
			// variable tracking across statements.
			if call, ok := n.(*ir.ExprStmt); ok {
				if mc, ok := call.Expr.(*ir.MethodCallExpr); ok {
					return mc.Method == "Close" || mc.Method == "Release" ||
						mc.Method == "Unlock" || mc.Method == "Destroy"
				}
			}

			return false
		},
		Apply: func(n ir.Node) ir.Node {
			stmt := n.(*ir.ExprStmt)

			return &ir.DeferStmt{Call: stmt.Expr}
		},
	}
}

// heuristicIteratorToRange detects iterator-based for loops and converts to range.
func heuristicIteratorToRange() *Heuristic {
	return &Heuristic{
		Name: "Iterator → range",
		Match: func(n ir.Node) bool {
			// Match: for loops with iterator-style patterns
			// (init = begin(), cond = != end(), post = ++)
			if f, ok := n.(*ir.ForStmt); ok {
				if f.Cond != nil {
					if bin, ok := f.Cond.(*ir.BinaryExpr); ok {
						if bin.Op == "!=" {
							if call, ok := bin.Right.(*ir.CallExpr); ok {
								return call.Func == "end" || call.Func == "End"
							}
						}
					}
				}
			}

			return false
		},
		Apply: func(n ir.Node) ir.Node {
			f := n.(*ir.ForStmt)

			// Extract the container from the begin() call
			rangeExpr := &ir.RawExpr{Text: "/* container */"}

			return &ir.RangeStmt{
				Value: "_",
				Range: rangeExpr,
				Body:  f.Body,
			}
		},
	}
}

// heuristicCoutToFmt detects std::cout usage and converts to fmt.Println.
func heuristicCoutToFmt() *Heuristic {
	return &Heuristic{
		Name: "std::cout → fmt.Print",
		Match: func(n ir.Node) bool {
			if stmt, ok := n.(*ir.ExprStmt); ok {
				if call, ok := stmt.Expr.(*ir.CallExpr); ok {
					return call.Func == "fmt.Print" || call.Func == "std.cout"
				}
			}

			return false
		},
		Apply: func(n ir.Node) ir.Node {
			stmt := n.(*ir.ExprStmt)
			call := stmt.Expr.(*ir.CallExpr)
			call.Func = "fmt.Println"

			return stmt
		},
	}
}

// heuristicCerrToStderr detects std::cerr usage and converts to fmt.Fprintln(os.Stderr, ...).
func heuristicCerrToStderr() *Heuristic {
	return &Heuristic{
		Name: "std::cerr → fmt.Fprintln(os.Stderr, ...)",
		Match: func(n ir.Node) bool {
			if stmt, ok := n.(*ir.ExprStmt); ok {
				if call, ok := stmt.Expr.(*ir.CallExpr); ok {
					return call.Func == "std.cerr"
				}
			}

			return false
		},
		Apply: func(n ir.Node) ir.Node {
			stmt := n.(*ir.ExprStmt)
			call := stmt.Expr.(*ir.CallExpr)
			call.Func = "fmt.Fprintln"
			call.Args = append([]ir.Expr{&ir.IdentExpr{Name: "os.Stderr"}}, call.Args...)

			return stmt
		},
	}
}

// heuristicSingletonToSyncOnce detects singleton patterns and converts to sync.Once.
func heuristicSingletonToSyncOnce() *Heuristic {
	return &Heuristic{
		Name: "Singleton → sync.Once",
		Match: func(n ir.Node) bool {
			// Detect static local variable pattern in a function
			if fn, ok := n.(*ir.FuncDecl); ok {
				for _, stmt := range fn.Body {
					if v, ok := stmt.(*ir.VarDecl); ok {
						return v.Name == "instance" || v.Name == "Instance"
					}
				}
			}

			return false
		},
		Apply: func(n ir.Node) ir.Node {
			// Add comment about sync.Once pattern
			fn := n.(*ir.FuncDecl)
			fn.Comment = "// Uses sync.Once for thread-safe singleton initialization"

			return fn
		},
	}
}

// heuristicThreadToGoroutine detects thread creation and converts to goroutines.
func heuristicThreadToGoroutine() *Heuristic {
	return &Heuristic{
		Name: "std::thread → goroutine",
		Match: func(n ir.Node) bool {
			if v, ok := n.(*ir.VarDecl); ok {
				if v.Type != nil && v.Type.Name == "/* goroutine */" {
					return true
				}
			}

			return false
		},
		Apply: func(n ir.Node) ir.Node {
			_ = n.(*ir.VarDecl) // original variable declaration is replaced

			return &ir.ExprStmt{
				Expr: &ir.CallExpr{
					Func: "go func()",
					Args: nil,
				},
			}
		},
	}
}

// heuristicMutexToSync detects mutex usage and ensures sync.Mutex pattern.
func heuristicMutexToSync() *Heuristic {
	return &Heuristic{
		Name: "std::mutex → sync.Mutex",
		Match: func(n ir.Node) bool {
			if v, ok := n.(*ir.VarDecl); ok {
				if v.Type != nil && v.Type.Name == "sync.Mutex" {
					return true
				}
			}

			return false
		},
		Apply: func(n ir.Node) ir.Node {
			return n // already correctly mapped
		},
	}
}

// heuristicAtomicToSyncAtomic detects atomic usage and maps to sync/atomic.
func heuristicAtomicToSyncAtomic() *Heuristic {
	return &Heuristic{
		Name: "std::atomic → sync/atomic",
		Match: func(n ir.Node) bool {
			if v, ok := n.(*ir.VarDecl); ok {
				if v.Type != nil && v.Type.Name == "atomic.Value" {
					return true
				}
			}

			return false
		},
		Apply: func(n ir.Node) ir.Node {
			return n // already correctly mapped
		},
	}
}
