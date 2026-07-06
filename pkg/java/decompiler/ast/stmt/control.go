package stmt

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// GotoStatement represents an unconditional jump.
type GotoStatement struct {
	TargetOffset int // bytecode offset of target
}

func NewGoto(targetOffset int) *GotoStatement {
	return &GotoStatement{TargetOffset: targetOffset}
}

func (g *GotoStatement) Kind() StmtKind                { return KindGoto }
func (g *GotoStatement) Children() []Statement         { return nil }
func (g *GotoStatement) Expressions() []ast.Expression { return nil }

func (g *GotoStatement) String() string {
	return fmt.Sprintf("goto %d;", g.TargetOffset)
}

// IfStatement represents a conditional branch.
type IfStatement struct {
	Condition    ast.Expression
	TargetOffset int // bytecode offset of branch target
}

func NewIf(condition ast.Expression, targetOffset int) *IfStatement {
	return &IfStatement{Condition: condition, TargetOffset: targetOffset}
}

func (i *IfStatement) Kind() StmtKind        { return KindIf }
func (i *IfStatement) Children() []Statement { return nil }
func (i *IfStatement) Expressions() []ast.Expression {
	return []ast.Expression{i.Condition}
}

func (i *IfStatement) String() string {
	return fmt.Sprintf("if (%s) goto %d;", i.Condition, i.TargetOffset)
}

// SwitchCase represents a single case in a switch statement.
type SwitchCase struct {
	Values       []int32 // empty for default case
	TargetOffset int
	IsDefault    bool
}

// SwitchStatement represents a switch statement (from tableswitch/lookupswitch).
type SwitchStatement struct {
	Value ast.Expression
	Cases []SwitchCase
}

func NewSwitch(value ast.Expression, cases []SwitchCase) *SwitchStatement {
	return &SwitchStatement{Value: value, Cases: cases}
}

func (s *SwitchStatement) Kind() StmtKind        { return KindSwitch }
func (s *SwitchStatement) Children() []Statement { return nil }
func (s *SwitchStatement) Expressions() []ast.Expression {
	return []ast.Expression{s.Value}
}

func (s *SwitchStatement) String() string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "switch (%s) { ", s.Value)
	for _, c := range s.Cases {
		if c.IsDefault {
			_, _ = fmt.Fprintf(&b, "default: goto %d; ", c.TargetOffset)
		} else {
			for _, v := range c.Values {
				_, _ = fmt.Fprintf(&b, "case %d: goto %d; ", v, c.TargetOffset)
			}
		}
	}

	b.WriteByte('}')

	return b.String()
}

// TryStatement represents the start of a try block.
type TryStatement struct {
	BlockID int // identifier for this try block
}

func NewTry(blockID int) *TryStatement {
	return &TryStatement{BlockID: blockID}
}

func (t *TryStatement) Kind() StmtKind                { return KindTry }
func (t *TryStatement) Children() []Statement         { return nil }
func (t *TryStatement) Expressions() []ast.Expression { return nil }

func (t *TryStatement) String() string {
	return fmt.Sprintf("try_%d {", t.BlockID)
}

// CatchStatement represents a catch handler entry point.
type CatchStatement struct {
	BlockID       int            // matching try block ID
	ExceptionType types.JavaType // nil for catch-all (finally)
	ExceptionVar  ast.LValue     // variable holding the caught exception
}

func NewCatch(blockID int, exceptionType types.JavaType, exceptionVar ast.LValue) *CatchStatement {
	return &CatchStatement{
		BlockID:       blockID,
		ExceptionType: exceptionType,
		ExceptionVar:  exceptionVar,
	}
}

func (c *CatchStatement) Kind() StmtKind        { return KindCatch }
func (c *CatchStatement) Children() []Statement { return nil }
func (c *CatchStatement) Expressions() []ast.Expression {
	if c.ExceptionVar != nil {
		return []ast.Expression{c.ExceptionVar}
	}

	return nil
}

func (c *CatchStatement) String() string {
	if c.ExceptionType == nil {
		return fmt.Sprintf("} catch (finally) /* block_%d */ {", c.BlockID)
	}

	return fmt.Sprintf("} catch (%s %s) /* block_%d */ {", c.ExceptionType.Name(), c.ExceptionVar, c.BlockID)
}

// MonitorEnterStatement represents: monitorenter (synchronized block start).
type MonitorEnterStatement struct {
	Object ast.Expression
}

func NewMonitorEnter(object ast.Expression) *MonitorEnterStatement {
	return &MonitorEnterStatement{Object: object}
}

func (m *MonitorEnterStatement) Kind() StmtKind        { return KindMonitorEnter }
func (m *MonitorEnterStatement) Children() []Statement { return nil }
func (m *MonitorEnterStatement) Expressions() []ast.Expression {
	return []ast.Expression{m.Object}
}

func (m *MonitorEnterStatement) String() string {
	return fmt.Sprintf("monitorenter(%s);", m.Object)
}

// MonitorExitStatement represents: monitorexit (synchronized block end).
type MonitorExitStatement struct {
	Object ast.Expression
}

func NewMonitorExit(object ast.Expression) *MonitorExitStatement {
	return &MonitorExitStatement{Object: object}
}

func (m *MonitorExitStatement) Kind() StmtKind        { return KindMonitorExit }
func (m *MonitorExitStatement) Children() []Statement { return nil }
func (m *MonitorExitStatement) Expressions() []ast.Expression {
	return []ast.Expression{m.Object}
}

func (m *MonitorExitStatement) String() string {
	return fmt.Sprintf("monitorexit(%s);", m.Object)
}

// CompoundStatement wraps multiple statements produced from a single instruction.
type CompoundStatement struct {
	Stmts []Statement
}

func NewCompound(stmts ...Statement) *CompoundStatement {
	return &CompoundStatement{Stmts: stmts}
}

func (c *CompoundStatement) Kind() StmtKind                { return KindCompound }
func (c *CompoundStatement) Children() []Statement         { return c.Stmts }
func (c *CompoundStatement) Expressions() []ast.Expression { return nil }

func (c *CompoundStatement) String() string {
	parts := make([]string, len(c.Stmts))
	for i, s := range c.Stmts {
		parts[i] = s.String()
	}

	return strings.Join(parts, " ")
}

// Block represents a sequence of statements.
type Block struct {
	Label string // optional label
	Stmts []Statement
}

func NewBlock(stmts ...Statement) *Block {
	return &Block{Stmts: stmts}
}

func (b *Block) Kind() StmtKind                { return KindBlock }
func (b *Block) Children() []Statement         { return b.Stmts }
func (b *Block) Expressions() []ast.Expression { return nil }

func (b *Block) String() string {
	var sb strings.Builder
	if b.Label != "" {
		sb.WriteString(b.Label)
		sb.WriteString(": ")
	}

	sb.WriteString("{ ")

	for _, s := range b.Stmts {
		sb.WriteString(s.String())
		sb.WriteByte(' ')
	}

	sb.WriteByte('}')

	return sb.String()
}
