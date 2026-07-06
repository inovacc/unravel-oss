package ast

import (
	"fmt"
	"math"
	"strconv"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// LiteralKind indicates the type category of a literal.
type LiteralKind int

const (
	LitInt    LiteralKind = iota // int constant
	LitLong                      // long constant
	LitFloat                     // float constant
	LitDouble                    // double constant
	LitString                    // string constant
	LitNull                      // null
	LitClass                     // Class<?> literal
	LitBool                      // boolean (derived from int 0/1)
	LitChar                      // char (derived from int)
	LitByte                      // byte (derived from int)
	LitShort                     // short (derived from int)
)

// Literal represents a constant value expression.
type Literal struct {
	Kind     LiteralKind
	IntVal   int64
	FloatVal float64
	StrVal   string
	TypeVal  types.JavaType // for LitClass
	JType    types.JavaType
}

// Pre-defined literal constants.
var (
	LitIntZero    = NewIntLiteral(0)
	LitIntOne     = NewIntLiteral(1)
	LitIntM1      = NewIntLiteral(-1)
	LitLongZero   = NewLongLiteral(0)
	LitLongOne    = NewLongLiteral(1)
	LitFloatZero  = NewFloatLiteral(0)
	LitDoubleZero = NewDoubleLiteral(0)
	LitTrue       = NewBoolLiteral(true)
	LitFalse      = NewBoolLiteral(false)
	LitNullVal    = &Literal{Kind: LitNull, JType: types.TypeNull}
)

func NewIntLiteral(v int32) *Literal {
	return &Literal{Kind: LitInt, IntVal: int64(v), JType: types.TypeInt}
}

func NewLongLiteral(v int64) *Literal {
	return &Literal{Kind: LitLong, IntVal: v, JType: types.TypeLong}
}

func NewFloatLiteral(v float32) *Literal {
	return &Literal{Kind: LitFloat, FloatVal: float64(v), JType: types.TypeFloat}
}

func NewDoubleLiteral(v float64) *Literal {
	return &Literal{Kind: LitDouble, FloatVal: v, JType: types.TypeDouble}
}

func NewStringLiteral(v string) *Literal {
	return &Literal{Kind: LitString, StrVal: v, JType: types.StringType}
}

func NewBoolLiteral(v bool) *Literal {
	l := &Literal{Kind: LitBool, JType: types.TypeBoolean}
	if v {
		l.IntVal = 1
	}

	return l
}

func NewCharLiteral(v int32) *Literal {
	return &Literal{Kind: LitChar, IntVal: int64(v), JType: types.TypeChar}
}

func NewByteLiteral(v int32) *Literal {
	return &Literal{Kind: LitByte, IntVal: int64(v), JType: types.TypeByte}
}

func NewShortLiteral(v int32) *Literal {
	return &Literal{Kind: LitShort, IntVal: int64(v), JType: types.TypeShort}
}

func NewClassLiteral(t types.JavaType) *Literal {
	return &Literal{Kind: LitClass, TypeVal: t, JType: types.ClassType}
}

func NewNullLiteral() *Literal { return LitNullVal }

// IntLiteralFromOpcode creates a literal for ICONST_0 through ICONST_5.
func IntLiteralFromOpcode(val int32) *Literal {
	switch val {
	case 0:
		return LitIntZero
	case 1:
		return LitIntOne
	case -1:
		return LitIntM1
	default:
		return NewIntLiteral(val)
	}
}

func (l *Literal) Type() types.JavaType   { return l.JType }
func (l *Literal) Precedence() Precedence { return PrecHighest }
func (l *Literal) IsSimple() bool         { return true }
func (l *Literal) Children() []Expression { return nil }

func (l *Literal) BoolValue() bool { return l.IntVal != 0 }

func (l *Literal) String() string {
	switch l.Kind {
	case LitInt:
		return strconv.FormatInt(l.IntVal, 10)
	case LitLong:
		return strconv.FormatInt(l.IntVal, 10) + "L"
	case LitFloat:
		if math.IsInf(l.FloatVal, 1) {
			return "Float.POSITIVE_INFINITY"
		}

		if math.IsInf(l.FloatVal, -1) {
			return "Float.NEGATIVE_INFINITY"
		}

		if math.IsNaN(l.FloatVal) {
			return "Float.NaN"
		}

		return strconv.FormatFloat(l.FloatVal, 'f', -1, 32) + "f"
	case LitDouble:
		if math.IsInf(l.FloatVal, 1) {
			return "Double.POSITIVE_INFINITY"
		}

		if math.IsInf(l.FloatVal, -1) {
			return "Double.NEGATIVE_INFINITY"
		}

		if math.IsNaN(l.FloatVal) {
			return "Double.NaN"
		}

		return strconv.FormatFloat(l.FloatVal, 'f', -1, 64) + "d"
	case LitString:
		return fmt.Sprintf("%q", l.StrVal)
	case LitNull:
		return "null"
	case LitClass:
		return l.TypeVal.Name() + ".class"
	case LitBool:
		if l.IntVal != 0 {
			return "true"
		}

		return "false"
	case LitChar:
		return fmt.Sprintf("'%s'", string(rune(l.IntVal)))
	case LitByte:
		return fmt.Sprintf("(byte)%d", l.IntVal)
	case LitShort:
		return fmt.Sprintf("(short)%d", l.IntVal)
	default:
		return fmt.Sprintf("<literal:%d>", l.Kind)
	}
}
