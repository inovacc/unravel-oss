package adapt

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewEngine(t *testing.T) {
	e := NewEngine(testLogger())

	if e.rules == nil {
		t.Error("expected non-nil rules")
	}

	if len(e.heuristics) == 0 {
		t.Error("expected default heuristics")
	}

	if e.useLLM {
		t.Error("expected LLM disabled by default")
	}
}

func TestAdapt_EmptyModule(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
	}

	result := e.Adapt(context.Background(), mod)

	if result.PackageName != "main" {
		t.Errorf("PackageName = %q, want %q", result.PackageName, "main")
	}
}

func TestAdapt_RAIIHeuristic(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Decls: []ir.Node{
			&ir.ExprStmt{
				Expr: &ir.MethodCallExpr{
					Receiver: &ir.IdentExpr{Name: "file"},
					Method:   "Close",
				},
			},
		},
	}

	result := e.Adapt(context.Background(), mod)

	if len(result.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(result.Decls))
	}

	if _, ok := result.Decls[0].(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt, got %T", result.Decls[0])
	}
}

func TestNeedsLLMFallback(t *testing.T) {
	e := NewEngine(testLogger())

	tests := []struct {
		name string
		node ir.Node
		want bool
	}{
		{
			name: "raw stmt needs fallback",
			node: &ir.RawStmt{Text: "complex code"},
			want: true,
		},
		{
			name: "raw stmt with only comment does not",
			node: &ir.RawStmt{Comment: "just a comment"},
			want: false,
		},
		{
			name: "raw expr needs fallback",
			node: &ir.RawExpr{Text: "complex expr"},
			want: true,
		},
		{
			name: "simple var decl does not",
			node: &ir.VarDecl{Name: "x", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.NeedsLLMFallback(tt.node)
			if got != tt.want {
				t.Errorf("NeedsLLMFallback() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectedLibraries(t *testing.T) {
	e := NewEngine(testLogger())

	includes := []string{"vector", "iostream", "boost/asio.hpp"}
	libs := e.DetectedLibraries(includes)

	if len(libs) == 0 {
		t.Error("expected at least one detected library")
	}
}

func TestAdapt_HeuristicInFuncBody(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "CleanUp",
				Body: []ir.Node{
					&ir.ExprStmt{
						Expr: &ir.MethodCallExpr{
							Receiver: &ir.IdentExpr{Name: "file"},
							Method:   "Close",
						},
					},
				},
			},
		},
	}

	result := e.Adapt(context.Background(), mod)

	fn := result.Decls[0].(*ir.FuncDecl)
	if len(fn.Body) != 1 {
		t.Fatalf("expected 1 body stmt, got %d", len(fn.Body))
	}

	if _, ok := fn.Body[0].(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt in func body, got %T", fn.Body[0])
	}
}

func TestAdapt_HeuristicInIfStmt(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.IfStmt{
				Cond: &ir.IdentExpr{Name: "true"},
				Then: []ir.Node{
					&ir.ExprStmt{
						Expr: &ir.MethodCallExpr{
							Receiver: &ir.IdentExpr{Name: "conn"},
							Method:   "Release",
						},
					},
				},
				Else: []ir.Node{
					&ir.ExprStmt{
						Expr: &ir.MethodCallExpr{
							Receiver: &ir.IdentExpr{Name: "mu"},
							Method:   "Unlock",
						},
					},
				},
			},
		},
	}

	result := e.Adapt(context.Background(), mod)

	ifStmt := result.Decls[0].(*ir.IfStmt)

	if _, ok := ifStmt.Then[0].(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt in Then, got %T", ifStmt.Then[0])
	}

	if _, ok := ifStmt.Else[0].(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt in Else, got %T", ifStmt.Else[0])
	}
}

func TestAdapt_HeuristicInForStmt(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.ForStmt{
				Cond: &ir.IdentExpr{Name: "true"},
				Body: []ir.Node{
					&ir.ExprStmt{
						Expr: &ir.MethodCallExpr{
							Receiver: &ir.IdentExpr{Name: "lock"},
							Method:   "Unlock",
						},
					},
				},
			},
		},
	}

	result := e.Adapt(context.Background(), mod)

	forStmt := result.Decls[0].(*ir.ForStmt)
	if _, ok := forStmt.Body[0].(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt in for body, got %T", forStmt.Body[0])
	}
}

func TestAdapt_HeuristicInRangeStmt(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.RangeStmt{
				Value: "item",
				Range: &ir.IdentExpr{Name: "items"},
				Body: []ir.Node{
					&ir.ExprStmt{
						Expr: &ir.MethodCallExpr{
							Receiver: &ir.IdentExpr{Name: "item"},
							Method:   "Destroy",
						},
					},
				},
			},
		},
	}

	result := e.Adapt(context.Background(), mod)

	rangeStmt := result.Decls[0].(*ir.RangeStmt)
	if _, ok := rangeStmt.Body[0].(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt in range body, got %T", rangeStmt.Body[0])
	}
}

func TestAdapt_HeuristicInSwitchStmt(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.SwitchStmt{
				Tag: &ir.IdentExpr{Name: "x"},
				Cases: []*ir.CaseClause{
					{
						Values: []ir.Expr{&ir.LiteralExpr{Kind: "int", Value: "1"}},
						Body: []ir.Node{
							&ir.ExprStmt{
								Expr: &ir.MethodCallExpr{
									Receiver: &ir.IdentExpr{Name: "r"},
									Method:   "Close",
								},
							},
						},
					},
				},
			},
		},
	}

	result := e.Adapt(context.Background(), mod)

	switchStmt := result.Decls[0].(*ir.SwitchStmt)
	if _, ok := switchStmt.Cases[0].Body[0].(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt in switch case, got %T", switchStmt.Cases[0].Body[0])
	}
}

func TestAdapt_HeuristicInBlock(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.Block{
				Stmts: []ir.Node{
					&ir.ExprStmt{
						Expr: &ir.MethodCallExpr{
							Receiver: &ir.IdentExpr{Name: "db"},
							Method:   "Close",
						},
					},
				},
			},
		},
	}

	result := e.Adapt(context.Background(), mod)

	block := result.Decls[0].(*ir.Block)
	if _, ok := block.Stmts[0].(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt in block, got %T", block.Stmts[0])
	}
}

func TestNewEngine_WithLLM(t *testing.T) {
	e := NewEngine(testLogger(), WithLLM(&mockLLM{}))

	if !e.useLLM {
		t.Error("expected LLM enabled")
	}

	if e.llm == nil {
		t.Error("expected non-nil LLM client")
	}
}

type mockLLM struct{}

func (m *mockLLM) Convert(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func TestNewEngine_WithRuleSet(t *testing.T) {
	rs := NewRuleSet()
	e := NewEngine(testLogger(), WithRuleSet(rs))

	if e.rules != rs {
		t.Error("expected custom rule set")
	}
}

func TestNewEngine_WithCustomHeuristics(t *testing.T) {
	h := []*Heuristic{
		{Name: "custom", Match: func(ir.Node) bool { return false }, Apply: func(n ir.Node) ir.Node { return n }},
	}
	e := NewEngine(testLogger(), WithHeuristics(h))

	if len(e.heuristics) != 1 {
		t.Errorf("expected 1 heuristic, got %d", len(e.heuristics))
	}

	if e.heuristics[0].Name != "custom" {
		t.Errorf("Name = %q, want %q", e.heuristics[0].Name, "custom")
	}
}

func TestNeedsLLMFallback_FuncWithRawBody(t *testing.T) {
	e := NewEngine(testLogger())

	fn := &ir.FuncDecl{
		Name: "Complex",
		Body: []ir.Node{
			&ir.RawStmt{Text: "complex_asm_code"},
		},
	}

	if !e.NeedsLLMFallback(fn) {
		t.Error("expected LLM fallback needed for func with raw body")
	}
}

func TestNeedsLLMFallback_FuncWithCleanBody(t *testing.T) {
	e := NewEngine(testLogger())

	fn := &ir.FuncDecl{
		Name: "Simple",
		Body: []ir.Node{
			&ir.ReturnStmt{Values: []ir.Expr{&ir.LiteralExpr{Kind: "int", Value: "0"}}},
		},
	}

	if e.NeedsLLMFallback(fn) {
		t.Error("expected no LLM fallback for simple func")
	}
}

func TestAdapt_NoHeuristicsMatch(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.VarDecl{Name: "x", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
		},
	}

	result := e.Adapt(context.Background(), mod)

	if len(result.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(result.Decls))
	}

	vd, ok := result.Decls[0].(*ir.VarDecl)
	if !ok {
		t.Fatalf("expected *ir.VarDecl, got %T", result.Decls[0])
	}

	if vd.Name != "x" {
		t.Errorf("Name = %q, want %q", vd.Name, "x")
	}
}

func TestAdapt_TypeDeclWithMethods(t *testing.T) {
	e := NewEngine(testLogger())
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind: ir.TypeDeclStruct,
				Name: "Resource",
				Methods: []*ir.FuncDecl{
					{
						Name: "Cleanup",
						Body: []ir.Node{
							&ir.ExprStmt{
								Expr: &ir.MethodCallExpr{
									Receiver: &ir.IdentExpr{Name: "self"},
									Method:   "Close",
								},
							},
						},
					},
				},
			},
		},
	}

	result := e.Adapt(context.Background(), mod)

	td := result.Decls[0].(*ir.TypeDecl)
	if len(td.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(td.Methods))
	}

	// The Close call in the method body should be transformed to defer
	if _, ok := td.Methods[0].Body[0].(*ir.DeferStmt); !ok {
		t.Errorf("expected DeferStmt in method body, got %T", td.Methods[0].Body[0])
	}
}
