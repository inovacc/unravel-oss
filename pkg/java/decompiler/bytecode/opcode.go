package bytecode

import "fmt"

// Opcode represents a JVM bytecode instruction opcode.
type Opcode uint16

// JVM opcodes (JVMS §6.5). Values match the bytecode encoding.
const (
	NOP             Opcode = 0x00
	ACONST_NULL     Opcode = 0x01
	ICONST_M1       Opcode = 0x02
	ICONST_0        Opcode = 0x03
	ICONST_1        Opcode = 0x04
	ICONST_2        Opcode = 0x05
	ICONST_3        Opcode = 0x06
	ICONST_4        Opcode = 0x07
	ICONST_5        Opcode = 0x08
	LCONST_0        Opcode = 0x09
	LCONST_1        Opcode = 0x0A
	FCONST_0        Opcode = 0x0B
	FCONST_1        Opcode = 0x0C
	FCONST_2        Opcode = 0x0D
	DCONST_0        Opcode = 0x0E
	DCONST_1        Opcode = 0x0F
	BIPUSH          Opcode = 0x10
	SIPUSH          Opcode = 0x11
	LDC             Opcode = 0x12
	LDC_W           Opcode = 0x13
	LDC2_W          Opcode = 0x14
	ILOAD           Opcode = 0x15
	LLOAD           Opcode = 0x16
	FLOAD           Opcode = 0x17
	DLOAD           Opcode = 0x18
	ALOAD           Opcode = 0x19
	ILOAD_0         Opcode = 0x1A
	ILOAD_1         Opcode = 0x1B
	ILOAD_2         Opcode = 0x1C
	ILOAD_3         Opcode = 0x1D
	LLOAD_0         Opcode = 0x1E
	LLOAD_1         Opcode = 0x1F
	LLOAD_2         Opcode = 0x20
	LLOAD_3         Opcode = 0x21
	FLOAD_0         Opcode = 0x22
	FLOAD_1         Opcode = 0x23
	FLOAD_2         Opcode = 0x24
	FLOAD_3         Opcode = 0x25
	DLOAD_0         Opcode = 0x26
	DLOAD_1         Opcode = 0x27
	DLOAD_2         Opcode = 0x28
	DLOAD_3         Opcode = 0x29
	ALOAD_0         Opcode = 0x2A
	ALOAD_1         Opcode = 0x2B
	ALOAD_2         Opcode = 0x2C
	ALOAD_3         Opcode = 0x2D
	IALOAD          Opcode = 0x2E
	LALOAD          Opcode = 0x2F
	FALOAD          Opcode = 0x30
	DALOAD          Opcode = 0x31
	AALOAD          Opcode = 0x32
	BALOAD          Opcode = 0x33
	CALOAD          Opcode = 0x34
	SALOAD          Opcode = 0x35
	ISTORE          Opcode = 0x36
	LSTORE          Opcode = 0x37
	FSTORE          Opcode = 0x38
	DSTORE          Opcode = 0x39
	ASTORE          Opcode = 0x3A
	ISTORE_0        Opcode = 0x3B
	ISTORE_1        Opcode = 0x3C
	ISTORE_2        Opcode = 0x3D
	ISTORE_3        Opcode = 0x3E
	LSTORE_0        Opcode = 0x3F
	LSTORE_1        Opcode = 0x40
	LSTORE_2        Opcode = 0x41
	LSTORE_3        Opcode = 0x42
	FSTORE_0        Opcode = 0x43
	FSTORE_1        Opcode = 0x44
	FSTORE_2        Opcode = 0x45
	FSTORE_3        Opcode = 0x46
	DSTORE_0        Opcode = 0x47
	DSTORE_1        Opcode = 0x48
	DSTORE_2        Opcode = 0x49
	DSTORE_3        Opcode = 0x4A
	ASTORE_0        Opcode = 0x4B
	ASTORE_1        Opcode = 0x4C
	ASTORE_2        Opcode = 0x4D
	ASTORE_3        Opcode = 0x4E
	IASTORE         Opcode = 0x4F
	LASTORE         Opcode = 0x50
	FASTORE         Opcode = 0x51
	DASTORE         Opcode = 0x52
	AASTORE         Opcode = 0x53
	BASTORE         Opcode = 0x54
	CASTORE         Opcode = 0x55
	SASTORE         Opcode = 0x56
	POP             Opcode = 0x57
	POP2            Opcode = 0x58
	DUP             Opcode = 0x59
	DUP_X1          Opcode = 0x5A
	DUP_X2          Opcode = 0x5B
	DUP2            Opcode = 0x5C
	DUP2_X1         Opcode = 0x5D
	DUP2_X2         Opcode = 0x5E
	SWAP            Opcode = 0x5F
	IADD            Opcode = 0x60
	LADD            Opcode = 0x61
	FADD            Opcode = 0x62
	DADD            Opcode = 0x63
	ISUB            Opcode = 0x64
	LSUB            Opcode = 0x65
	FSUB            Opcode = 0x66
	DSUB            Opcode = 0x67
	IMUL            Opcode = 0x68
	LMUL            Opcode = 0x69
	FMUL            Opcode = 0x6A
	DMUL            Opcode = 0x6B
	IDIV            Opcode = 0x6C
	LDIV            Opcode = 0x6D
	FDIV            Opcode = 0x6E
	DDIV            Opcode = 0x6F
	IREM            Opcode = 0x70
	LREM            Opcode = 0x71
	FREM            Opcode = 0x72
	DREM            Opcode = 0x73
	INEG            Opcode = 0x74
	LNEG            Opcode = 0x75
	FNEG            Opcode = 0x76
	DNEG            Opcode = 0x77
	ISHL            Opcode = 0x78
	LSHL            Opcode = 0x79
	ISHR            Opcode = 0x7A
	LSHR            Opcode = 0x7B
	IUSHR           Opcode = 0x7C
	LUSHR           Opcode = 0x7D
	IAND            Opcode = 0x7E
	LAND            Opcode = 0x7F
	IOR             Opcode = 0x80
	LOR             Opcode = 0x81
	IXOR            Opcode = 0x82
	LXOR            Opcode = 0x83
	IINC            Opcode = 0x84
	I2L             Opcode = 0x85
	I2F             Opcode = 0x86
	I2D             Opcode = 0x87
	L2I             Opcode = 0x88
	L2F             Opcode = 0x89
	L2D             Opcode = 0x8A
	F2I             Opcode = 0x8B
	F2L             Opcode = 0x8C
	F2D             Opcode = 0x8D
	D2I             Opcode = 0x8E
	D2L             Opcode = 0x8F
	D2F             Opcode = 0x90
	I2B             Opcode = 0x91
	I2C             Opcode = 0x92
	I2S             Opcode = 0x93
	LCMP            Opcode = 0x94
	FCMPL           Opcode = 0x95
	FCMPG           Opcode = 0x96
	DCMPL           Opcode = 0x97
	DCMPG           Opcode = 0x98
	IFEQ            Opcode = 0x99
	IFNE            Opcode = 0x9A
	IFLT            Opcode = 0x9B
	IFGE            Opcode = 0x9C
	IFGT            Opcode = 0x9D
	IFLE            Opcode = 0x9E
	IF_ICMPEQ       Opcode = 0x9F
	IF_ICMPNE       Opcode = 0xA0
	IF_ICMPLT       Opcode = 0xA1
	IF_ICMPGE       Opcode = 0xA2
	IF_ICMPGT       Opcode = 0xA3
	IF_ICMPLE       Opcode = 0xA4
	IF_ACMPEQ       Opcode = 0xA5
	IF_ACMPNE       Opcode = 0xA6
	GOTO            Opcode = 0xA7
	JSR             Opcode = 0xA8
	RET             Opcode = 0xA9
	TABLESWITCH     Opcode = 0xAA
	LOOKUPSWITCH    Opcode = 0xAB
	IRETURN         Opcode = 0xAC
	LRETURN         Opcode = 0xAD
	FRETURN         Opcode = 0xAE
	DRETURN         Opcode = 0xAF
	ARETURN         Opcode = 0xB0
	RETURN          Opcode = 0xB1
	GETSTATIC       Opcode = 0xB2
	PUTSTATIC       Opcode = 0xB3
	GETFIELD        Opcode = 0xB4
	PUTFIELD        Opcode = 0xB5
	INVOKEVIRTUAL   Opcode = 0xB6
	INVOKESPECIAL   Opcode = 0xB7
	INVOKESTATIC    Opcode = 0xB8
	INVOKEINTERFACE Opcode = 0xB9
	INVOKEDYNAMIC   Opcode = 0xBA
	NEW             Opcode = 0xBB
	NEWARRAY        Opcode = 0xBC
	ANEWARRAY       Opcode = 0xBD
	ARRAYLENGTH     Opcode = 0xBE
	ATHROW          Opcode = 0xBF
	CHECKCAST       Opcode = 0xC0
	INSTANCEOF      Opcode = 0xC1
	MONITORENTER    Opcode = 0xC2
	MONITOREXIT     Opcode = 0xC3
	WIDE            Opcode = 0xC4
	MULTIANEWARRAY  Opcode = 0xC5
	IFNULL          Opcode = 0xC6
	IFNONNULL       Opcode = 0xC7
	GOTO_W          Opcode = 0xC8
	JSR_W           Opcode = 0xC9

	// Synthetic opcodes used internally by the decompiler (not real JVM opcodes).
	FAKE_TRY   Opcode = 0x100
	FAKE_CATCH Opcode = 0x101
)

// StackType represents the computational type category of values on the JVM operand stack.
type StackType uint8

const (
	StackInt                StackType = iota // Category 1: boolean, byte, char, short, int
	StackFloat                               // Category 1: float
	StackRef                                 // Category 1: reference
	StackReturnAddress                       // Category 1: returnAddress (JSR/RET)
	StackReturnAddressOrRef                  // Category 1: returnAddress or ref (astore)
	StackLong                                // Category 2: long
	StackDouble                              // Category 2: double
	StackVoid                                // Not a stack value
)

// ComputationCategory returns the JVM computation category (1 or 2).
// Long and double are category 2 (occupy two stack slots); all others are category 1.
func (s StackType) ComputationCategory() int {
	switch s {
	case StackLong, StackDouble:
		return 2
	case StackVoid:
		return 0
	default:
		return 1
	}
}

func (s StackType) String() string {
	switch s {
	case StackInt:
		return "int"
	case StackFloat:
		return "float"
	case StackRef:
		return "reference"
	case StackReturnAddress:
		return "returnAddress"
	case StackReturnAddressOrRef:
		return "returnAddress|ref"
	case StackLong:
		return "long"
	case StackDouble:
		return "double"
	case StackVoid:
		return "void"
	default:
		return fmt.Sprintf("StackType(%d)", s)
	}
}

// OpcodeInfo holds the static properties of a JVM opcode.
type OpcodeInfo struct {
	Op          Opcode
	Name        string
	OperandSize int         // Size of operands in bytes (after opcode byte). -1 = variable length.
	StackPop    []StackType // Stack types consumed (nil = dynamic, depends on CP or stack)
	StackPush   []StackType // Stack types produced (nil = dynamic)
	NoThrow     bool        // If true, this instruction cannot throw.
}

// IsJump returns true if this opcode is a branch or jump instruction.
func (info *OpcodeInfo) IsJump() bool {
	switch info.Op {
	case GOTO, GOTO_W, JSR, JSR_W,
		IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE,
		IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
		IF_ACMPEQ, IF_ACMPNE,
		IFNULL, IFNONNULL,
		TABLESWITCH, LOOKUPSWITCH:
		return true
	default:
		return false
	}
}

// IsReturn returns true if this opcode is a return instruction.
func (info *OpcodeInfo) IsReturn() bool {
	switch info.Op {
	case IRETURN, LRETURN, FRETURN, DRETURN, ARETURN, RETURN:
		return true
	default:
		return false
	}
}

// IsStore returns true if this opcode stores a value to a local variable.
func (info *OpcodeInfo) IsStore() bool {
	switch info.Op {
	case ISTORE, LSTORE, FSTORE, DSTORE, ASTORE,
		ISTORE_0, ISTORE_1, ISTORE_2, ISTORE_3,
		LSTORE_0, LSTORE_1, LSTORE_2, LSTORE_3,
		FSTORE_0, FSTORE_1, FSTORE_2, FSTORE_3,
		DSTORE_0, DSTORE_1, DSTORE_2, DSTORE_3,
		ASTORE_0, ASTORE_1, ASTORE_2, ASTORE_3:
		return true
	default:
		return false
	}
}

// IsLoad returns true if this opcode loads a value from a local variable.
func (info *OpcodeInfo) IsLoad() bool {
	switch info.Op {
	case ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
		ILOAD_0, ILOAD_1, ILOAD_2, ILOAD_3,
		LLOAD_0, LLOAD_1, LLOAD_2, LLOAD_3,
		FLOAD_0, FLOAD_1, FLOAD_2, FLOAD_3,
		DLOAD_0, DLOAD_1, DLOAD_2, DLOAD_3,
		ALOAD_0, ALOAD_1, ALOAD_2, ALOAD_3:
		return true
	default:
		return false
	}
}

// IsInvoke returns true if this opcode is a method invocation.
func (info *OpcodeInfo) IsInvoke() bool {
	switch info.Op {
	case INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC, INVOKEINTERFACE, INVOKEDYNAMIC:
		return true
	default:
		return false
	}
}

// opcodeTable is the master lookup table from byte value to OpcodeInfo.
var opcodeTable [256]*OpcodeInfo

// syntheticOpcodeTable holds the synthetic (non-JVM) opcodes.
var syntheticOpcodeTable = map[Opcode]*OpcodeInfo{}

func init() {
	type def struct {
		op      Opcode
		name    string
		operand int
		pop     []StackType
		push    []StackType
		noThrow bool
	}

	s := func(types ...StackType) []StackType { return types }
	none := []StackType{}

	defs := []def{
		{NOP, "nop", 0, none, none, true},
		{ACONST_NULL, "aconst_null", 0, none, s(StackRef), true},
		{ICONST_M1, "iconst_m1", 0, none, s(StackInt), true},
		{ICONST_0, "iconst_0", 0, none, s(StackInt), true},
		{ICONST_1, "iconst_1", 0, none, s(StackInt), true},
		{ICONST_2, "iconst_2", 0, none, s(StackInt), true},
		{ICONST_3, "iconst_3", 0, none, s(StackInt), true},
		{ICONST_4, "iconst_4", 0, none, s(StackInt), true},
		{ICONST_5, "iconst_5", 0, none, s(StackInt), true},
		{LCONST_0, "lconst_0", 0, none, s(StackLong), true},
		{LCONST_1, "lconst_1", 0, none, s(StackLong), true},
		{FCONST_0, "fconst_0", 0, none, s(StackFloat), true},
		{FCONST_1, "fconst_1", 0, none, s(StackFloat), true},
		{FCONST_2, "fconst_2", 0, none, s(StackFloat), true},
		{DCONST_0, "dconst_0", 0, none, s(StackDouble), true},
		{DCONST_1, "dconst_1", 0, none, s(StackDouble), true},
		{BIPUSH, "bipush", 1, none, s(StackInt), true},
		{SIPUSH, "sipush", 2, none, s(StackInt), true},
		{LDC, "ldc", 1, nil, nil, true},       // dynamic: depends on CP entry type
		{LDC_W, "ldc_w", 2, nil, nil, true},   // dynamic
		{LDC2_W, "ldc2_w", 2, nil, nil, true}, // dynamic
		{ILOAD, "iload", 1, none, s(StackInt), true},
		{LLOAD, "lload", 1, none, s(StackLong), true},
		{FLOAD, "fload", 1, none, s(StackFloat), true},
		{DLOAD, "dload", 1, none, s(StackDouble), true},
		{ALOAD, "aload", 1, none, s(StackRef), true},
		{ILOAD_0, "iload_0", 0, none, s(StackInt), true},
		{ILOAD_1, "iload_1", 0, none, s(StackInt), true},
		{ILOAD_2, "iload_2", 0, none, s(StackInt), true},
		{ILOAD_3, "iload_3", 0, none, s(StackInt), true},
		{LLOAD_0, "lload_0", 0, none, s(StackLong), true},
		{LLOAD_1, "lload_1", 0, none, s(StackLong), true},
		{LLOAD_2, "lload_2", 0, none, s(StackLong), true},
		{LLOAD_3, "lload_3", 0, none, s(StackLong), true},
		{FLOAD_0, "fload_0", 0, none, s(StackFloat), true},
		{FLOAD_1, "fload_1", 0, none, s(StackFloat), true},
		{FLOAD_2, "fload_2", 0, none, s(StackFloat), true},
		{FLOAD_3, "fload_3", 0, none, s(StackFloat), true},
		{DLOAD_0, "dload_0", 0, none, s(StackDouble), true},
		{DLOAD_1, "dload_1", 0, none, s(StackDouble), true},
		{DLOAD_2, "dload_2", 0, none, s(StackDouble), true},
		{DLOAD_3, "dload_3", 0, none, s(StackDouble), true},
		{ALOAD_0, "aload_0", 0, none, s(StackRef), true},
		{ALOAD_1, "aload_1", 0, none, s(StackRef), true},
		{ALOAD_2, "aload_2", 0, none, s(StackRef), true},
		{ALOAD_3, "aload_3", 0, none, s(StackRef), true},
		{IALOAD, "iaload", 0, s(StackRef, StackInt), s(StackInt), false},
		{LALOAD, "laload", 0, s(StackRef, StackInt), s(StackLong), false},
		{FALOAD, "faload", 0, s(StackRef, StackInt), s(StackFloat), false},
		{DALOAD, "daload", 0, s(StackRef, StackInt), s(StackDouble), false},
		{AALOAD, "aaload", 0, s(StackRef, StackInt), s(StackRef), false},
		{BALOAD, "baload", 0, s(StackRef, StackInt), s(StackInt), false},
		{CALOAD, "caload", 0, s(StackRef, StackInt), s(StackInt), false},
		{SALOAD, "saload", 0, s(StackRef, StackInt), s(StackInt), false},
		{ISTORE, "istore", 1, s(StackInt), none, true},
		{LSTORE, "lstore", 1, s(StackLong), none, true},
		{FSTORE, "fstore", 1, s(StackFloat), none, true},
		{DSTORE, "dstore", 1, s(StackDouble), none, true},
		{ASTORE, "astore", 1, s(StackReturnAddressOrRef), none, true},
		{ISTORE_0, "istore_0", 0, s(StackInt), none, true},
		{ISTORE_1, "istore_1", 0, s(StackInt), none, true},
		{ISTORE_2, "istore_2", 0, s(StackInt), none, true},
		{ISTORE_3, "istore_3", 0, s(StackInt), none, true},
		{LSTORE_0, "lstore_0", 0, s(StackLong), none, true},
		{LSTORE_1, "lstore_1", 0, s(StackLong), none, true},
		{LSTORE_2, "lstore_2", 0, s(StackLong), none, true},
		{LSTORE_3, "lstore_3", 0, s(StackLong), none, true},
		{FSTORE_0, "fstore_0", 0, s(StackFloat), none, true},
		{FSTORE_1, "fstore_1", 0, s(StackFloat), none, true},
		{FSTORE_2, "fstore_2", 0, s(StackFloat), none, true},
		{FSTORE_3, "fstore_3", 0, s(StackFloat), none, true},
		{DSTORE_0, "dstore_0", 0, s(StackDouble), none, true},
		{DSTORE_1, "dstore_1", 0, s(StackDouble), none, true},
		{DSTORE_2, "dstore_2", 0, s(StackDouble), none, true},
		{DSTORE_3, "dstore_3", 0, s(StackDouble), none, true},
		{ASTORE_0, "astore_0", 0, s(StackReturnAddressOrRef), none, true},
		{ASTORE_1, "astore_1", 0, s(StackReturnAddressOrRef), none, true},
		{ASTORE_2, "astore_2", 0, s(StackReturnAddressOrRef), none, true},
		{ASTORE_3, "astore_3", 0, s(StackReturnAddressOrRef), none, true},
		{IASTORE, "iastore", 0, s(StackRef, StackInt, StackInt), none, false},
		{LASTORE, "lastore", 0, s(StackRef, StackInt, StackLong), none, false},
		{FASTORE, "fastore", 0, s(StackRef, StackInt, StackFloat), none, false},
		{DASTORE, "dastore", 0, s(StackRef, StackInt, StackDouble), none, false},
		{AASTORE, "aastore", 0, s(StackRef, StackInt, StackRef), none, false},
		{BASTORE, "bastore", 0, s(StackRef, StackInt, StackInt), none, false},
		{CASTORE, "castore", 0, s(StackRef, StackInt, StackInt), none, false},
		{SASTORE, "sastore", 0, s(StackRef, StackInt, StackInt), none, false},
		{POP, "pop", 0, nil, nil, false},   // dynamic
		{POP2, "pop2", 0, nil, nil, false}, // dynamic
		{DUP, "dup", 0, nil, nil, false},   // dynamic
		{DUP_X1, "dup_x1", 0, nil, nil, false},
		{DUP_X2, "dup_x2", 0, nil, nil, false},
		{DUP2, "dup2", 0, nil, nil, false},
		{DUP2_X1, "dup2_x1", 0, nil, nil, false},
		{DUP2_X2, "dup2_x2", 0, nil, nil, false},
		{SWAP, "swap", 0, nil, nil, false},
		{IADD, "iadd", 0, s(StackInt, StackInt), s(StackInt), true},
		{LADD, "ladd", 0, s(StackLong, StackLong), s(StackLong), true},
		{FADD, "fadd", 0, s(StackFloat, StackFloat), s(StackFloat), false},
		{DADD, "dadd", 0, s(StackDouble, StackDouble), s(StackDouble), false},
		{ISUB, "isub", 0, s(StackInt, StackInt), s(StackInt), false},
		{LSUB, "lsub", 0, s(StackLong, StackLong), s(StackLong), false},
		{FSUB, "fsub", 0, s(StackFloat, StackFloat), s(StackFloat), false},
		{DSUB, "dsub", 0, s(StackDouble, StackDouble), s(StackDouble), false},
		{IMUL, "imul", 0, s(StackInt, StackInt), s(StackInt), false},
		{LMUL, "lmul", 0, s(StackLong, StackLong), s(StackLong), false},
		{FMUL, "fmul", 0, s(StackFloat, StackFloat), s(StackFloat), false},
		{DMUL, "dmul", 0, s(StackDouble, StackDouble), s(StackDouble), false},
		{IDIV, "idiv", 0, s(StackInt, StackInt), s(StackInt), false},
		{LDIV, "ldiv", 0, s(StackLong, StackLong), s(StackLong), false},
		{FDIV, "fdiv", 0, s(StackFloat, StackFloat), s(StackFloat), false},
		{DDIV, "ddiv", 0, s(StackDouble, StackDouble), s(StackDouble), true},
		{IREM, "irem", 0, s(StackInt, StackInt), s(StackInt), false},
		{LREM, "lrem", 0, s(StackLong, StackLong), s(StackLong), false},
		{FREM, "frem", 0, s(StackFloat, StackFloat), s(StackFloat), false},
		{DREM, "drem", 0, s(StackDouble, StackDouble), s(StackDouble), true},
		{INEG, "ineg", 0, s(StackInt), s(StackInt), true},
		{LNEG, "lneg", 0, s(StackLong), s(StackLong), false},
		{FNEG, "fneg", 0, s(StackFloat), s(StackFloat), false},
		{DNEG, "dneg", 0, s(StackDouble), s(StackDouble), true},
		{ISHL, "ishl", 0, s(StackInt, StackInt), s(StackInt), true},
		{LSHL, "lshl", 0, s(StackLong, StackInt), s(StackLong), false},
		{ISHR, "ishr", 0, s(StackInt, StackInt), s(StackInt), true},
		{LSHR, "lshr", 0, s(StackLong, StackInt), s(StackLong), false},
		{IUSHR, "iushr", 0, s(StackInt, StackInt), s(StackInt), false},
		{LUSHR, "lushr", 0, s(StackLong, StackInt), s(StackLong), false},
		{IAND, "iand", 0, s(StackInt, StackInt), s(StackInt), true},
		{LAND, "land", 0, s(StackLong, StackLong), s(StackLong), false},
		{IOR, "ior", 0, s(StackInt, StackInt), s(StackInt), true},
		{LOR, "lor", 0, s(StackLong, StackLong), s(StackLong), false},
		{IXOR, "ixor", 0, s(StackInt, StackInt), s(StackInt), false},
		{LXOR, "lxor", 0, s(StackLong, StackLong), s(StackLong), false},
		{IINC, "iinc", 2, none, none, false},
		{I2L, "i2l", 0, s(StackInt), s(StackLong), true},
		{I2F, "i2f", 0, s(StackInt), s(StackFloat), false},
		{I2D, "i2d", 0, s(StackInt), s(StackDouble), false},
		{L2I, "l2i", 0, s(StackLong), s(StackInt), true},
		{L2F, "l2f", 0, s(StackLong), s(StackFloat), true},
		{L2D, "l2d", 0, s(StackLong), s(StackDouble), true},
		{F2I, "f2i", 0, s(StackFloat), s(StackInt), false},
		{F2L, "f2l", 0, s(StackFloat), s(StackLong), false},
		{F2D, "f2d", 0, s(StackFloat), s(StackDouble), false},
		{D2I, "d2i", 0, s(StackDouble), s(StackInt), false},
		{D2L, "d2l", 0, s(StackDouble), s(StackLong), false},
		{D2F, "d2f", 0, s(StackDouble), s(StackFloat), false},
		{I2B, "i2b", 0, s(StackInt), s(StackInt), false},
		{I2C, "i2c", 0, s(StackInt), s(StackInt), false},
		{I2S, "i2s", 0, s(StackInt), s(StackInt), true},
		{LCMP, "lcmp", 0, s(StackLong, StackLong), s(StackInt), true},
		{FCMPL, "fcmpl", 0, s(StackFloat, StackFloat), s(StackInt), false},
		{FCMPG, "fcmpg", 0, s(StackFloat, StackFloat), s(StackInt), false},
		{DCMPL, "dcmpl", 0, s(StackDouble, StackDouble), s(StackInt), false},
		{DCMPG, "dcmpg", 0, s(StackDouble, StackDouble), s(StackInt), false},
		{IFEQ, "ifeq", 2, s(StackInt), none, true},
		{IFNE, "ifne", 2, s(StackInt), none, true},
		{IFLT, "iflt", 2, s(StackInt), none, true},
		{IFGE, "ifge", 2, s(StackInt), none, true},
		{IFGT, "ifgt", 2, s(StackInt), none, true},
		{IFLE, "ifle", 2, s(StackInt), none, true},
		{IF_ICMPEQ, "if_icmpeq", 2, s(StackInt, StackInt), none, true},
		{IF_ICMPNE, "if_icmpne", 2, s(StackInt, StackInt), none, true},
		{IF_ICMPLT, "if_icmplt", 2, s(StackInt, StackInt), none, true},
		{IF_ICMPGE, "if_icmpge", 2, s(StackInt, StackInt), none, true},
		{IF_ICMPGT, "if_icmpgt", 2, s(StackInt, StackInt), none, true},
		{IF_ICMPLE, "if_icmple", 2, s(StackInt, StackInt), none, true},
		{IF_ACMPEQ, "if_acmpeq", 2, s(StackRef, StackRef), none, false},
		{IF_ACMPNE, "if_acmpne", 2, s(StackRef, StackRef), none, false},
		{GOTO, "goto", 2, none, none, true},
		{JSR, "jsr", 2, none, s(StackReturnAddress), false},
		{RET, "ret", 1, none, none, false},
		{TABLESWITCH, "tableswitch", -1, s(StackInt), none, false},
		{LOOKUPSWITCH, "lookupswitch", -1, s(StackInt), none, false},
		{IRETURN, "ireturn", 0, s(StackInt), none, true},
		{LRETURN, "lreturn", 0, s(StackLong), none, true},
		{FRETURN, "freturn", 0, s(StackFloat), none, true},
		{DRETURN, "dreturn", 0, s(StackDouble), none, false},
		{ARETURN, "areturn", 0, s(StackRef), none, true},
		{RETURN, "return", 0, none, none, true},
		{GETSTATIC, "getstatic", 2, nil, nil, false},         // dynamic
		{PUTSTATIC, "putstatic", 2, nil, nil, false},         // dynamic
		{GETFIELD, "getfield", 2, nil, nil, false},           // dynamic
		{PUTFIELD, "putfield", 2, nil, nil, false},           // dynamic
		{INVOKEVIRTUAL, "invokevirtual", 2, nil, nil, false}, // dynamic
		{INVOKESPECIAL, "invokespecial", 2, nil, nil, false}, // dynamic
		{INVOKESTATIC, "invokestatic", 2, nil, nil, false},   // dynamic
		{INVOKEINTERFACE, "invokeinterface", 4, nil, nil, false},
		{INVOKEDYNAMIC, "invokedynamic", 4, nil, nil, false},
		{NEW, "new", 2, none, s(StackRef), false},
		{NEWARRAY, "newarray", 1, s(StackInt), s(StackRef), false},
		{ANEWARRAY, "anewarray", 2, s(StackInt), s(StackRef), false},
		{ARRAYLENGTH, "arraylength", 0, s(StackRef), s(StackInt), false},
		{ATHROW, "athrow", 0, s(StackRef), s(StackRef), false},
		{CHECKCAST, "checkcast", 2, s(StackRef), s(StackRef), false},
		{INSTANCEOF, "instanceof", 2, s(StackRef), s(StackInt), false},
		{MONITORENTER, "monitorenter", 0, s(StackRef), none, false},
		{MONITOREXIT, "monitorexit", 0, s(StackRef), none, false},
		{WIDE, "wide", -1, nil, nil, false},
		{MULTIANEWARRAY, "multianewarray", 3, nil, nil, false}, // dynamic pop count
		{IFNULL, "ifnull", 2, s(StackRef), none, true},
		{IFNONNULL, "ifnonnull", 2, s(StackRef), none, true},
		{GOTO_W, "goto_w", 4, none, none, true},
		{JSR_W, "jsr_w", 4, none, s(StackReturnAddress), false},
	}

	for _, d := range defs {
		info := &OpcodeInfo{
			Op:          d.op,
			Name:        d.name,
			OperandSize: d.operand,
			StackPop:    d.pop,
			StackPush:   d.push,
			NoThrow:     d.noThrow,
		}
		if d.op < 0x100 {
			opcodeTable[d.op] = info
		}
	}

	// Synthetic opcodes
	syntheticOpcodeTable[FAKE_TRY] = &OpcodeInfo{Op: FAKE_TRY, Name: "fake_try", OperandSize: 0, StackPop: none, StackPush: none}
	syntheticOpcodeTable[FAKE_CATCH] = &OpcodeInfo{Op: FAKE_CATCH, Name: "fake_catch", OperandSize: 0, StackPop: none, StackPush: s(StackRef)}
}

// LookupOpcode returns the OpcodeInfo for the given byte value.
func LookupOpcode(b byte) (*OpcodeInfo, error) {
	info := opcodeTable[b]
	if info == nil {
		return nil, fmt.Errorf("unknown opcode 0x%02X", b)
	}

	return info, nil
}

// LookupSyntheticOpcode returns the OpcodeInfo for a synthetic (non-JVM) opcode.
func LookupSyntheticOpcode(op Opcode) (*OpcodeInfo, error) {
	info, ok := syntheticOpcodeTable[op]
	if !ok {
		return nil, fmt.Errorf("unknown synthetic opcode 0x%04X", op)
	}

	return info, nil
}

// LookupOp returns the OpcodeInfo for the given Opcode value.
func LookupOp(op Opcode) *OpcodeInfo {
	if op < 0x100 {
		return opcodeTable[op]
	}

	return syntheticOpcodeTable[op]
}

func (op Opcode) String() string {
	if op < 0x100 {
		info := opcodeTable[op]
		if info != nil {
			return info.Name
		}
	}

	info, ok := syntheticOpcodeTable[op]
	if ok {
		return info.Name
	}

	return fmt.Sprintf("opcode(0x%02X)", uint16(op))
}

// NewArrayType represents the type argument for the newarray instruction.
type NewArrayType uint8

const (
	ArrayTypeBoolean NewArrayType = 4
	ArrayTypeChar    NewArrayType = 5
	ArrayTypeFloat   NewArrayType = 6
	ArrayTypeDouble  NewArrayType = 7
	ArrayTypeByte    NewArrayType = 8
	ArrayTypeShort   NewArrayType = 9
	ArrayTypeInt     NewArrayType = 10
	ArrayTypeLong    NewArrayType = 11
)

func (t NewArrayType) String() string {
	switch t {
	case ArrayTypeBoolean:
		return "boolean"
	case ArrayTypeChar:
		return "char"
	case ArrayTypeFloat:
		return "float"
	case ArrayTypeDouble:
		return "double"
	case ArrayTypeByte:
		return "byte"
	case ArrayTypeShort:
		return "short"
	case ArrayTypeInt:
		return "int"
	case ArrayTypeLong:
		return "long"
	default:
		return fmt.Sprintf("array_type(%d)", t)
	}
}
