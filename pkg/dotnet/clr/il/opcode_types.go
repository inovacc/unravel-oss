/*
Copyright (c) 2026 Security Research
*/
package il

//go:generate go run ./gen

// OperandClass is the inline operand width/kind of an opcode (ECMA-335 III.1.2).
type OperandClass int

const (
	InlineNone OperandClass = iota
	InlineI
	ShortInlineI
	InlineI8
	InlineR
	ShortInlineR
	InlineVar
	ShortInlineVar
	InlineBrTarget
	ShortInlineBrTarget
	InlineSwitch
	InlineMethod
	InlineField
	InlineType
	InlineTok
	InlineString
	InlineSig
)

// Opcode is one IL opcode definition.
type Opcode struct {
	Name     string
	Code     byte
	Prefixed bool // true => two-byte opcode 0xFE <Code>
	Operand  OperandClass
}

var (
	singleByteIdx   [256]*Opcode
	prefixedByteIdx [256]*Opcode
	opcodeIdxInit   bool
)

func buildOpcodeIndex() {
	for i := range opcodeTable {
		op := &opcodeTable[i]
		if op.Prefixed {
			prefixedByteIdx[op.Code] = op
		} else {
			singleByteIdx[op.Code] = op
		}
	}
	opcodeIdxInit = true
}

// lookupOpcode returns the opcode for a (prefixed,code) pair.
func lookupOpcode(prefixed bool, code byte) (Opcode, bool) {
	if !opcodeIdxInit {
		buildOpcodeIndex()
	}
	var op *Opcode
	if prefixed {
		op = prefixedByteIdx[code]
	} else {
		op = singleByteIdx[code]
	}
	if op == nil {
		return Opcode{}, false
	}
	return *op, true
}
