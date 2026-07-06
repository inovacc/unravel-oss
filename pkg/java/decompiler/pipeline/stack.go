package pipeline

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// StackSim simulates the JVM operand stack during bytecode analysis.
type StackSim struct {
	entries []*StackEntry
	nextID  int
}

func NewStackSim() *StackSim {
	return &StackSim{}
}

func (s *StackSim) Depth() int { return len(s.entries) }

func (s *StackSim) Push(value ast.Expression) *StackEntry {
	entry := &StackEntry{
		Value: value,
		Slot:  s.nextID,
	}
	s.nextID++
	s.entries = append(s.entries, entry)

	return entry
}

func (s *StackSim) Pop() (*StackEntry, error) {
	if len(s.entries) == 0 {
		return nil, fmt.Errorf("stack underflow")
	}

	entry := s.entries[len(s.entries)-1]
	s.entries = s.entries[:len(s.entries)-1]

	return entry, nil
}

func (s *StackSim) Peek() (*StackEntry, error) {
	if len(s.entries) == 0 {
		return nil, fmt.Errorf("stack empty")
	}

	return s.entries[len(s.entries)-1], nil
}

// PopN pops n values from the stack, returning them in pop order (top first).
func (s *StackSim) PopN(n int) ([]*StackEntry, error) {
	if len(s.entries) < n {
		return nil, fmt.Errorf("stack underflow: need %d, have %d", n, len(s.entries))
	}

	result := make([]*StackEntry, n)
	for i := range n {
		result[i] = s.entries[len(s.entries)-1-i]
	}

	s.entries = s.entries[:len(s.entries)-n]

	return result, nil
}

// Clone creates a copy of the stack state.
func (s *StackSim) Clone() *StackSim {
	clone := &StackSim{
		entries: make([]*StackEntry, len(s.entries)),
		nextID:  s.nextID,
	}
	copy(clone.entries, s.entries)

	return clone
}

// MethodInfo holds method-level context needed during stack simulation.
type MethodInfo struct {
	ClassName     string
	MethodName    string
	Descriptor    string
	IsStatic      bool
	ReturnType    types.JavaType
	ParamTypes    []types.JavaType
	MaxLocals     int
	MaxStack      int
	LocalVarNames map[int]string // slot → variable name from LocalVariableTable
}

// CPResolver resolves constant pool entries during decompilation.
type CPResolver interface {
	// ResolveClass resolves a class reference (CONSTANT_Class) to a type.
	ResolveClass(index uint16) (types.JavaType, error)

	// ResolveFieldRef resolves a field reference.
	ResolveFieldRef(index uint16) (*ast.FieldRef, error)

	// ResolveMethodRef resolves a method reference.
	ResolveMethodRef(index uint16) (*ast.MethodRef, error)

	// ResolveInterfaceMethodRef resolves an interface method reference.
	ResolveInterfaceMethodRef(index uint16) (*ast.MethodRef, error)

	// ResolveLiteral resolves a constant (LDC) to a literal expression.
	ResolveLiteral(index uint16) (*ast.Literal, error)

	// ResolveInvokeDynamic resolves an invokedynamic call site.
	ResolveInvokeDynamic(index uint16) (*ast.DynamicInvocation, error)

	// ResolveNameAndType resolves a name-and-type descriptor.
	ResolveNameAndType(index uint16) (name string, descriptor string, err error)
}
