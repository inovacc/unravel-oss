package pipeline

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/bytecode"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// ---------- helpers ----------

func makeOp03(s stmt.Statement) *Op03Node {
	return NewSyntheticOp03Node(0, s)
}

func nodesOf(stmts ...stmt.Statement) []*Op03Node {
	nodes := make([]*Op03Node, len(stmts))
	for i, s := range stmts {
		nodes[i] = NewSyntheticOp03Node(i, s)
	}
	return nodes
}

// ---------- SimplifyExpressions / foldIntArith ----------

func TestFoldIntArith_Add(t *testing.T) {
	// 3 + 4 → 7
	expr := ast.NewArithmeticOperation(
		ast.OpAdd,
		ast.NewIntLiteral(3),
		ast.NewIntLiteral(4),
		types.TypeInt,
	)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)

	ret, ok := nodes[0].Statement.(*stmt.ReturnStatement)
	if !ok {
		t.Fatal("statement should be ReturnStatement")
	}
	lit, ok := ret.Value.(*ast.Literal)
	if !ok {
		t.Fatalf("folded result should be Literal, got %T", ret.Value)
	}
	if lit.IntVal != 7 {
		t.Errorf("3+4 want 7, got %d", lit.IntVal)
	}
}

func TestFoldIntArith_Sub(t *testing.T) {
	expr := ast.NewArithmeticOperation(ast.OpSub, ast.NewIntLiteral(10), ast.NewIntLiteral(3), types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	lit := ret.Value.(*ast.Literal)
	if lit.IntVal != 7 {
		t.Errorf("10-3 want 7, got %d", lit.IntVal)
	}
}

func TestFoldIntArith_Mul(t *testing.T) {
	expr := ast.NewArithmeticOperation(ast.OpMul, ast.NewIntLiteral(6), ast.NewIntLiteral(7), types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	lit := ret.Value.(*ast.Literal)
	if lit.IntVal != 42 {
		t.Errorf("6*7 want 42, got %d", lit.IntVal)
	}
}

func TestFoldIntArith_Div(t *testing.T) {
	expr := ast.NewArithmeticOperation(ast.OpDiv, ast.NewIntLiteral(20), ast.NewIntLiteral(4), types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	lit := ret.Value.(*ast.Literal)
	if lit.IntVal != 5 {
		t.Errorf("20/4 want 5, got %d", lit.IntVal)
	}
}

func TestFoldIntArith_DivByZero_NotFolded(t *testing.T) {
	// Division by zero must NOT be folded (would panic at runtime)
	expr := ast.NewArithmeticOperation(ast.OpDiv, ast.NewIntLiteral(5), ast.NewIntLiteral(0), types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	// Should remain an ArithmeticOperation (not folded)
	if _, ok := ret.Value.(*ast.ArithmeticOperation); !ok {
		t.Error("div by zero should not fold")
	}
}

func TestFoldIntArith_Rem(t *testing.T) {
	expr := ast.NewArithmeticOperation(ast.OpRem, ast.NewIntLiteral(17), ast.NewIntLiteral(5), types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	lit := ret.Value.(*ast.Literal)
	if lit.IntVal != 2 {
		t.Errorf("17%%5 want 2, got %d", lit.IntVal)
	}
}

// ---------- simplifyIdentityArith ----------
// isIntZero/isIntOne use pointer equality against ast.LitIntZero/LitIntOne.
// The identity-operand MUST be the singleton; the non-identity operand must NOT
// be an int literal (otherwise constant folding fires first and the identity rule
// never runs). Use a VarExpression (non-literal) for the variable operand.

// varX returns a simple int-typed VarExpression that is NOT a constant literal.
func varX() ast.Expression {
	lv := ast.NewLocalVariable(5, types.TypeInt)
	return ast.NewVarExpression(lv)
}

func TestIdentityArith_AddZero(t *testing.T) {
	x := varX()
	expr := ast.NewArithmeticOperation(ast.OpAdd, x, ast.LitIntZero, types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != x {
		t.Errorf("x+LitIntZero should simplify to x, got %T", ret.Value)
	}
}

func TestIdentityArith_ZeroAdd(t *testing.T) {
	x := varX()
	expr := ast.NewArithmeticOperation(ast.OpAdd, ast.LitIntZero, x, types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != x {
		t.Errorf("LitIntZero+x should simplify to x, got %T", ret.Value)
	}
}

func TestIdentityArith_SubZero(t *testing.T) {
	x := varX()
	expr := ast.NewArithmeticOperation(ast.OpSub, x, ast.LitIntZero, types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != x {
		t.Errorf("x-LitIntZero should simplify to x, got %T", ret.Value)
	}
}

func TestIdentityArith_MulOne(t *testing.T) {
	x := varX()
	expr := ast.NewArithmeticOperation(ast.OpMul, x, ast.LitIntOne, types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != x {
		t.Errorf("x*LitIntOne should simplify to x, got %T", ret.Value)
	}
}

func TestIdentityArith_OneMul(t *testing.T) {
	x := varX()
	expr := ast.NewArithmeticOperation(ast.OpMul, ast.LitIntOne, x, types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != x {
		t.Errorf("LitIntOne*x should simplify to x, got %T", ret.Value)
	}
}

func TestIdentityArith_DivOne(t *testing.T) {
	x := varX()
	expr := ast.NewArithmeticOperation(ast.OpDiv, x, ast.LitIntOne, types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != x {
		t.Errorf("x/LitIntOne should simplify to x, got %T", ret.Value)
	}
}

func TestIdentityArith_MulZero(t *testing.T) {
	x := varX()
	expr := ast.NewArithmeticOperation(ast.OpMul, x, ast.LitIntZero, types.TypeInt)
	retStmt := stmt.NewReturn(expr)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != ast.LitIntZero {
		t.Errorf("x*LitIntZero should simplify to LitIntZero, got %T %v", ret.Value, ret.Value)
	}
}

// ---------- simplifyExpr: double negation ----------

func TestSimplifyExpr_DoubleNegation(t *testing.T) {
	x := ast.NewIntLiteral(5)
	inner := ast.NewNegationExpression(x)
	outer := ast.NewNegationExpression(inner)
	retStmt := stmt.NewReturn(outer)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != x {
		t.Errorf("!!x should simplify to x")
	}
}

// ---------- simplifyExpr: identity cast removal ----------

func TestSimplifyExpr_IdentityCast(t *testing.T) {
	x := ast.NewIntLiteral(5) // type = TypeInt
	cast := &ast.CastExpression{
		Operand:    x,
		TargetType: types.TypeInt,
		Forced:     false,
	}
	retStmt := stmt.NewReturn(cast)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	// (int)intValue → intValue
	if ret.Value != x {
		t.Errorf("identity cast should be removed, got %T", ret.Value)
	}
}

func TestSimplifyExpr_ForcedCastKept(t *testing.T) {
	x := ast.NewIntLiteral(5)
	cast := &ast.CastExpression{
		Operand:    x,
		TargetType: types.TypeInt,
		Forced:     true,
	}
	retStmt := stmt.NewReturn(cast)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != cast {
		t.Errorf("forced cast should not be removed")
	}
}

// ---------- TernaryExpression simplification ----------

func TestSimplifyExpr_TernaryTrue(t *testing.T) {
	trueExpr := ast.NewIntLiteral(1)
	falseExpr := ast.NewIntLiteral(2)
	tern := &ast.TernaryExpression{
		Condition: ast.LitTrue,
		TrueExpr:  trueExpr,
		FalseExpr: falseExpr,
	}
	retStmt := stmt.NewReturn(tern)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != trueExpr {
		t.Errorf("true ? a : b should give a")
	}
}

func TestSimplifyExpr_TernaryFalse(t *testing.T) {
	trueExpr := ast.NewIntLiteral(1)
	falseExpr := ast.NewIntLiteral(2)
	tern := &ast.TernaryExpression{
		Condition: ast.LitFalse,
		TrueExpr:  trueExpr,
		FalseExpr: falseExpr,
	}
	retStmt := stmt.NewReturn(tern)
	nodes := nodesOf(retStmt)
	SimplifyExpressions(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != falseExpr {
		t.Errorf("false ? a : b should give b")
	}
}

// ---------- SimplifyBooleans ----------

func TestSimplifyBooleans_EqTrue(t *testing.T) {
	// boolVar == true → boolVar
	boolVar := &ast.LocalVariable{Slot: 1, JType: types.TypeBoolean}
	cmp := ast.NewComparisonOperation(ast.CmpEq, boolVar, ast.LitTrue)
	ifStmt := stmt.NewStructuredIf(cmp, stmt.NewNop(), nil)
	nodes := nodesOf(ifStmt)
	SimplifyBooleans(nodes)
	sif := nodes[0].Statement.(*stmt.StructuredIf)
	if sif.Condition != boolVar {
		t.Errorf("boolVar==true should simplify to boolVar")
	}
}

func TestSimplifyBooleans_EqFalse(t *testing.T) {
	// boolVar == false → !boolVar
	boolVar := &ast.LocalVariable{Slot: 1, JType: types.TypeBoolean}
	cmp := ast.NewComparisonOperation(ast.CmpEq, boolVar, ast.LitFalse)
	ifStmt := stmt.NewStructuredIf(cmp, stmt.NewNop(), nil)
	nodes := nodesOf(ifStmt)
	SimplifyBooleans(nodes)
	sif := nodes[0].Statement.(*stmt.StructuredIf)
	if _, ok := sif.Condition.(*ast.NegationExpression); !ok {
		t.Errorf("boolVar==false should simplify to !boolVar, got %T", sif.Condition)
	}
}

func TestSimplifyBooleans_NeTrue(t *testing.T) {
	// boolVar != true → !boolVar
	boolVar := &ast.LocalVariable{Slot: 1, JType: types.TypeBoolean}
	cmp := ast.NewComparisonOperation(ast.CmpNe, boolVar, ast.LitTrue)
	ifStmt := stmt.NewStructuredIf(cmp, stmt.NewNop(), nil)
	nodes := nodesOf(ifStmt)
	SimplifyBooleans(nodes)
	sif := nodes[0].Statement.(*stmt.StructuredIf)
	if _, ok := sif.Condition.(*ast.NegationExpression); !ok {
		t.Errorf("boolVar!=true should simplify to !boolVar, got %T", sif.Condition)
	}
}

func TestSimplifyBooleans_NeFalse(t *testing.T) {
	// boolVar != false → boolVar
	boolVar := &ast.LocalVariable{Slot: 1, JType: types.TypeBoolean}
	cmp := ast.NewComparisonOperation(ast.CmpNe, boolVar, ast.LitFalse)
	ifStmt := stmt.NewStructuredIf(cmp, stmt.NewNop(), nil)
	nodes := nodesOf(ifStmt)
	SimplifyBooleans(nodes)
	sif := nodes[0].Statement.(*stmt.StructuredIf)
	if sif.Condition != boolVar {
		t.Errorf("boolVar!=false should simplify to boolVar")
	}
}

// ---------- RemoveRedundantCasts ----------

func TestRemoveRedundantCasts_Smoke(t *testing.T) {
	// Just verify it runs (delegates to SimplifyExpressions)
	x := ast.NewIntLiteral(3)
	cast := &ast.CastExpression{Operand: x, TargetType: types.TypeInt, Forced: false}
	retStmt := stmt.NewReturn(cast)
	nodes := nodesOf(retStmt)
	RemoveRedundantCasts(nodes)
	ret := nodes[0].Statement.(*stmt.ReturnStatement)
	if ret.Value != x {
		t.Error("redundant cast should be removed")
	}
}

// ---------- RemoveRedundantGotos ----------

func TestRemoveRedundantGotos_RemovesGoto(t *testing.T) {
	// Node 0 has goto targeting offset of node 1
	n0 := NewSyntheticOp03Node(0, stmt.NewGoto(5)) // goto offset 5
	instr1 := makeInstr(5, bytecode.RETURN, nil)
	n1 := &Op03Node{
		Index:     1,
		InstrNode: &InstrNode{Instr: instr1},
		Statement: stmt.NewReturnVoid(),
		BlockIdx:  -1,
	}
	nodes := []*Op03Node{n0, n1}
	RemoveRedundantGotos(nodes)
	if nodes[0].Statement.Kind() != stmt.KindNop {
		t.Errorf("redundant goto should become nop, got %v", nodes[0].Statement.Kind())
	}
}

func TestRemoveRedundantGotos_KeepsNonRedundantGoto(t *testing.T) {
	// goto targeting offset 99, but next node is offset 5
	n0 := NewSyntheticOp03Node(0, stmt.NewGoto(99))
	instr1 := makeInstr(5, bytecode.RETURN, nil)
	n1 := &Op03Node{
		Index:     1,
		InstrNode: &InstrNode{Instr: instr1},
		Statement: stmt.NewReturnVoid(),
		BlockIdx:  -1,
	}
	nodes := []*Op03Node{n0, n1}
	RemoveRedundantGotos(nodes)
	if nodes[0].Statement.Kind() != stmt.KindGoto {
		t.Error("non-redundant goto should be kept")
	}
}

// ---------- RemoveEmptyBlocks ----------

func TestRemoveEmptyBlocks_EmptyBlockBecomesNop(t *testing.T) {
	block := stmt.NewBlock() // empty block
	n := makeOp03(block)
	RemoveEmptyBlocks([]*Op03Node{n})
	if n.Statement.Kind() != stmt.KindNop {
		t.Errorf("empty block should become nop, got %v", n.Statement.Kind())
	}
}

func TestRemoveEmptyBlocks_SingleChildUnwrapped(t *testing.T) {
	ret := stmt.NewReturnVoid()
	block := stmt.NewBlock(ret)
	n := makeOp03(block)
	RemoveEmptyBlocks([]*Op03Node{n})
	if n.Statement.Kind() != stmt.KindReturnVoid {
		t.Errorf("single-statement block should unwrap, got %v", n.Statement.Kind())
	}
}

func TestRemoveEmptyBlocks_MultiChildKept(t *testing.T) {
	block := stmt.NewBlock(stmt.NewReturnVoid(), stmt.NewReturnVoid())
	n := makeOp03(block)
	RemoveEmptyBlocks([]*Op03Node{n})
	if n.Statement.Kind() != stmt.KindBlock {
		t.Errorf("multi-child block should stay Block, got %v", n.Statement.Kind())
	}
}

func TestRemoveEmptyBlocks_StructuredIf_EmptyThenNoElse(t *testing.T) {
	cond := ast.LitTrue
	sif := stmt.NewStructuredIf(cond, stmt.NewNop(), nil)
	n := makeOp03(sif)
	RemoveEmptyBlocks([]*Op03Node{n})
	if n.Statement.Kind() != stmt.KindNop {
		t.Errorf("if with empty then and no else should become nop")
	}
}

// ---------- CollapseLinearBlocks / flattenNestedBlocks ----------

func TestFlattenNestedBlocks_Smoke(t *testing.T) {
	inner := stmt.NewBlock(stmt.NewReturnVoid())
	outer := stmt.NewBlock(inner)
	n := makeOp03(outer)
	CollapseLinearBlocks([]*Op03Node{n})
	block, ok := n.Statement.(*stmt.Block)
	if !ok {
		t.Fatalf("expected Block, got %T", n.Statement)
	}
	if len(block.Stmts) != 1 {
		t.Errorf("want 1 stmt after flatten, got %d", len(block.Stmts))
	}
	if block.Stmts[0].Kind() != stmt.KindReturnVoid {
		t.Error("flattened stmt should be ReturnVoid")
	}
}

func TestCollapseLinearBlocks_NonBlock(t *testing.T) {
	// Non-block statements should be left alone
	ret := stmt.NewReturnVoid()
	n := makeOp03(ret)
	CollapseLinearBlocks([]*Op03Node{n})
	if n.Statement != ret {
		t.Error("non-block statement should not be modified")
	}
}

// ---------- RewriteLambdas ----------

func TestRewriteLambdas_NoLambdas(t *testing.T) {
	// Just a return statement — no crash
	nodes := nodesOf(stmt.NewReturnVoid())
	RewriteLambdas(nodes)
	if nodes[0].Statement.Kind() != stmt.KindReturnVoid {
		t.Error("non-lambda statement should be unchanged")
	}
}

// ---------- RemoveSyntheticBridges ----------

func TestRemoveSyntheticBridges_NoOp(t *testing.T) {
	nodes := nodesOf(stmt.NewReturnVoid())
	RemoveSyntheticBridges(nodes)
	if nodes[0].Statement.Kind() != stmt.KindReturnVoid {
		t.Error("no bridge methods — statement should be unchanged")
	}
}

// ---------- FinalTransforms integration ----------

func TestFinalTransforms_Smoke(t *testing.T) {
	nodes := nodesOf(
		stmt.NewReturnVoid(),
		stmt.NewNop(),
	)
	// Should not panic
	FinalTransforms(nodes)
}
