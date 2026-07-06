package sig

import "github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"

// ElementType is an ECMA-335 II.23.1.16 ELEMENT_TYPE_* tag.
type ElementType byte

const (
	ETEnd         ElementType = 0x00
	ETVoid        ElementType = 0x01
	ETBoolean     ElementType = 0x02
	ETChar        ElementType = 0x03
	ETI1          ElementType = 0x04
	ETU1          ElementType = 0x05
	ETI2          ElementType = 0x06
	ETU2          ElementType = 0x07
	ETI4          ElementType = 0x08
	ETU4          ElementType = 0x09
	ETI8          ElementType = 0x0a
	ETU8          ElementType = 0x0b
	ETR4          ElementType = 0x0c
	ETR8          ElementType = 0x0d
	ETString      ElementType = 0x0e
	ETPtr         ElementType = 0x0f
	ETByRef       ElementType = 0x10
	ETValueType   ElementType = 0x11
	ETClass       ElementType = 0x12
	ETVar         ElementType = 0x13
	ETArray       ElementType = 0x14
	ETGenericInst ElementType = 0x15
	ETTypedByRef  ElementType = 0x16
	ETI           ElementType = 0x18
	ETU           ElementType = 0x19
	ETObject      ElementType = 0x1c
	ETSZArray     ElementType = 0x1d
	ETMVar        ElementType = 0x1e
)

// Modifier element types skipped before a real type (II.23.2.7).
const (
	etCModReqd ElementType = 0x1f
	etCModOpt  ElementType = 0x20
	etPinned   ElementType = 0x45
	etSentinel ElementType = 0x41
)

// MethodSig is a decoded MethodDef/MethodRef signature (frozen contract).
type MethodSig struct {
	HasThis  bool
	CallConv byte
	Ret      TypeSig
	Params   []TypeSig
}

// TypeSig is one node of the element-type tree (frozen contract).
type TypeSig struct {
	Kind     ElementType  // the ELEMENT_TYPE_* tag
	Elem     *TypeSig     // element/base for PTR/BYREF/SZARRAY/ARRAY/GENERICINST
	Args     []TypeSig    // GENERICINST type arguments
	Token    clrtok.Token // CLASS/VALUETYPE TypeDefOrRef target
	GenIndex uint32       // VAR/MVAR generic-parameter index
	Rank     uint32       // ARRAY rank
}
