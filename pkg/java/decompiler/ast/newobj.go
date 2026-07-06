package ast

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// NewObject represents the allocation part of object creation (NEW opcode).
// The constructor call comes separately via invokespecial <init>.
type NewObject struct {
	ClassType types.JavaType
}

func NewNewObject(classType types.JavaType) *NewObject {
	return &NewObject{ClassType: classType}
}

func (n *NewObject) Type() types.JavaType   { return n.ClassType }
func (n *NewObject) Precedence() Precedence { return PrecPostfix }
func (n *NewObject) IsSimple() bool         { return false }
func (n *NewObject) Children() []Expression { return nil }

func (n *NewObject) String() string {
	return fmt.Sprintf("new %s", n.ClassType.Name())
}
