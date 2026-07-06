package ast

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// LocalVariable represents a local variable slot in the JVM frame.
type LocalVariable struct {
	Slot  int
	Name  string
	JType types.JavaType
	// Version tracks SSA versions of this variable.
	Version int
}

func NewLocalVariable(slot int, jtype types.JavaType) *LocalVariable {
	return &LocalVariable{
		Slot:  slot,
		Name:  fmt.Sprintf("var%d", slot),
		JType: jtype,
	}
}

func NewNamedLocalVariable(slot int, name string, jtype types.JavaType) *LocalVariable {
	return &LocalVariable{Slot: slot, Name: name, JType: jtype}
}

func (lv *LocalVariable) Type() types.JavaType   { return lv.JType }
func (lv *LocalVariable) Precedence() Precedence { return PrecHighest }
func (lv *LocalVariable) IsSimple() bool         { return true }
func (lv *LocalVariable) Children() []Expression { return nil }
func (lv *LocalVariable) LValueName() string     { return lv.Name }

func (lv *LocalVariable) String() string {
	if lv.Version > 0 {
		return fmt.Sprintf("%s_%d", lv.Name, lv.Version)
	}

	return lv.Name
}

// StackValue represents a value on the JVM operand stack.
// Used during stack simulation before being resolved to concrete expressions.
type StackValue struct {
	Idx   int            // stack position
	JType types.JavaType // inferred type
}

func NewStackValue(idx int, jtype types.JavaType) *StackValue {
	return &StackValue{Idx: idx, JType: jtype}
}

func (sv *StackValue) Type() types.JavaType   { return sv.JType }
func (sv *StackValue) Precedence() Precedence { return PrecHighest }
func (sv *StackValue) IsSimple() bool         { return true }
func (sv *StackValue) Children() []Expression { return nil }
func (sv *StackValue) LValueName() string     { return fmt.Sprintf("stack_%d", sv.Idx) }

func (sv *StackValue) String() string {
	return fmt.Sprintf("stack[%d]", sv.Idx)
}

// VarExpression reads the value of an LValue (variable, field, array element).
type VarExpression struct {
	LVal LValue
}

func NewVarExpression(lv LValue) *VarExpression {
	return &VarExpression{LVal: lv}
}

func (ve *VarExpression) Type() types.JavaType   { return ve.LVal.Type() }
func (ve *VarExpression) Precedence() Precedence { return PrecHighest }
func (ve *VarExpression) IsSimple() bool         { return true }
func (ve *VarExpression) Children() []Expression { return []Expression{ve.LVal} }
func (ve *VarExpression) String() string         { return ve.LVal.String() }
