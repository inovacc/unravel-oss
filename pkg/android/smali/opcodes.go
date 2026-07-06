/*
Copyright (c) 2026 Security Research
*/
package smali

// Format describes how a Dalvik instruction encodes its operands.
type Format int

const (
	Fmt10x  Format = iota // op
	Fmt12x                // op vA, vB               (4-bit regs)
	Fmt11n                // op vA, #+B               (4-bit reg, 4-bit literal)
	Fmt11x                // op vAA                   (8-bit reg)
	Fmt10t                // op +AA                   (8-bit offset)
	Fmt20t                // op +AAAA                 (16-bit offset)
	Fmt22x                // op vAA, vBBBB            (8+16-bit regs)
	Fmt21t                // op vAA, +BBBB            (8-bit reg, 16-bit offset)
	Fmt21s                // op vAA, #+BBBB           (8-bit reg, 16-bit literal)
	Fmt21h                // op vAA, #+BBBB0000[0000] (high 16/48 literal)
	Fmt21c                // op vAA, type/string/field@BBBB
	Fmt23x                // op vAA, vBB, vCC         (8-bit regs)
	Fmt22b                // op vAA, vBB, #+CC        (8+8-bit reg, 8-bit literal)
	Fmt22t                // op vA, vB, +CCCC         (4-bit regs, 16-bit offset)
	Fmt22s                // op vA, vB, #+CCCC        (4-bit regs, 16-bit literal)
	Fmt22c                // op vA, vB, type/field@CCCC
	Fmt30t                // op +AAAAAAAA             (32-bit offset)
	Fmt32x                // op vAAAA, vBBBB          (16-bit regs)
	Fmt31i                // op vAA, #+BBBBBBBB       (32-bit literal)
	Fmt31t                // op vAA, +BBBBBBBB        (32-bit offset)
	Fmt31c                // op vAA, string@BBBBBBBB
	Fmt35c                // op {vC..vG}, type/meth@BBBB (invoke/filled-new-array)
	Fmt3rc                // op {vCCCC..v(CCCC+AA-1)}, type/meth@BBBB (range)
	Fmt51l                // op vAA, #+BBBBBBBBBBBBBBBB (64-bit literal)
	Fmt45cc               // op {vC..vG}, meth@BBBB, proto@HHHH
	Fmt4rcc               // op {vCCCC..}, meth@BBBB, proto@HHHH
	FmtUnknown
)

// RefKind describes what an instruction's constant-pool index references.
type RefKind int

const (
	RefNone   RefKind = iota
	RefString         // string_id
	RefType           // type_id
	RefField          // field_id
	RefMethod         // method_id
	RefProto          // proto_id
)

// OpcodeInfo describes a single Dalvik opcode.
type OpcodeInfo struct {
	Mnemonic string
	Format   Format
	Ref      RefKind
	Width    int // in 16-bit code units
}

// Opcodes maps Dalvik opcode byte to its info.
// Covers all 256 Dalvik opcodes defined in the Android source.
var Opcodes [256]OpcodeInfo

func init() {
	// Fill with unknown first
	for i := range Opcodes {
		Opcodes[i] = OpcodeInfo{Mnemonic: "nop", Format: FmtUnknown, Width: 1}
	}

	set := func(op byte, mnem string, fmt Format, ref RefKind, width int) {
		Opcodes[op] = OpcodeInfo{Mnemonic: mnem, Format: fmt, Ref: ref, Width: width}
	}

	// 00-0d: misc
	set(0x00, "nop", Fmt10x, RefNone, 1)
	set(0x01, "move", Fmt12x, RefNone, 1)
	set(0x02, "move/from16", Fmt22x, RefNone, 2)
	set(0x03, "move/16", Fmt32x, RefNone, 3)
	set(0x04, "move-wide", Fmt12x, RefNone, 1)
	set(0x05, "move-wide/from16", Fmt22x, RefNone, 2)
	set(0x06, "move-wide/16", Fmt32x, RefNone, 3)
	set(0x07, "move-object", Fmt12x, RefNone, 1)
	set(0x08, "move-object/from16", Fmt22x, RefNone, 2)
	set(0x09, "move-object/16", Fmt32x, RefNone, 3)
	set(0x0a, "move-result", Fmt11x, RefNone, 1)
	set(0x0b, "move-result-wide", Fmt11x, RefNone, 1)
	set(0x0c, "move-result-object", Fmt11x, RefNone, 1)
	set(0x0d, "move-exception", Fmt11x, RefNone, 1)

	// 0e-11: return
	set(0x0e, "return-void", Fmt10x, RefNone, 1)
	set(0x0f, "return", Fmt11x, RefNone, 1)
	set(0x10, "return-wide", Fmt11x, RefNone, 1)
	set(0x11, "return-object", Fmt11x, RefNone, 1)

	// 12-1f: const
	set(0x12, "const/4", Fmt11n, RefNone, 1)
	set(0x13, "const/16", Fmt21s, RefNone, 2)
	set(0x14, "const", Fmt31i, RefNone, 3)
	set(0x15, "const/high16", Fmt21h, RefNone, 2)
	set(0x16, "const-wide/16", Fmt21s, RefNone, 2)
	set(0x17, "const-wide/32", Fmt31i, RefNone, 3)
	set(0x18, "const-wide", Fmt51l, RefNone, 5)
	set(0x19, "const-wide/high16", Fmt21h, RefNone, 2)
	set(0x1a, "const-string", Fmt21c, RefString, 2)
	set(0x1b, "const-string/jumbo", Fmt31c, RefString, 3)
	set(0x1c, "const-class", Fmt21c, RefType, 2)

	// 1d-1f: monitor, check-cast, instance-of
	set(0x1d, "monitor-enter", Fmt11x, RefNone, 1)
	set(0x1e, "monitor-exit", Fmt11x, RefNone, 1)
	set(0x1f, "check-cast", Fmt21c, RefType, 2)
	set(0x20, "instance-of", Fmt22c, RefType, 2)

	// 21-25: array
	set(0x21, "array-length", Fmt12x, RefNone, 1)
	set(0x22, "new-instance", Fmt21c, RefType, 2)
	set(0x23, "new-array", Fmt22c, RefType, 2)
	set(0x24, "filled-new-array", Fmt35c, RefType, 3)
	set(0x25, "filled-new-array/range", Fmt3rc, RefType, 3)

	// 26: fill-array-data
	set(0x26, "fill-array-data", Fmt31t, RefNone, 3)

	// 27: throw
	set(0x27, "throw", Fmt11x, RefNone, 1)

	// 28-2a: goto
	set(0x28, "goto", Fmt10t, RefNone, 1)
	set(0x29, "goto/16", Fmt20t, RefNone, 2)
	set(0x2a, "goto/32", Fmt30t, RefNone, 3)

	// 2b-2c: switch
	set(0x2b, "packed-switch", Fmt31t, RefNone, 3)
	set(0x2c, "sparse-switch", Fmt31t, RefNone, 3)

	// 2d-31: cmpX
	set(0x2d, "cmpl-float", Fmt23x, RefNone, 2)
	set(0x2e, "cmpg-float", Fmt23x, RefNone, 2)
	set(0x2f, "cmpl-double", Fmt23x, RefNone, 2)
	set(0x30, "cmpg-double", Fmt23x, RefNone, 2)
	set(0x31, "cmp-long", Fmt23x, RefNone, 2)

	// 32-37: if-test vA, vB
	set(0x32, "if-eq", Fmt22t, RefNone, 2)
	set(0x33, "if-ne", Fmt22t, RefNone, 2)
	set(0x34, "if-lt", Fmt22t, RefNone, 2)
	set(0x35, "if-ge", Fmt22t, RefNone, 2)
	set(0x36, "if-gt", Fmt22t, RefNone, 2)
	set(0x37, "if-le", Fmt22t, RefNone, 2)

	// 38-3d: if-testz vAA
	set(0x38, "if-eqz", Fmt21t, RefNone, 2)
	set(0x39, "if-nez", Fmt21t, RefNone, 2)
	set(0x3a, "if-ltz", Fmt21t, RefNone, 2)
	set(0x3b, "if-gez", Fmt21t, RefNone, 2)
	set(0x3c, "if-gtz", Fmt21t, RefNone, 2)
	set(0x3d, "if-lez", Fmt21t, RefNone, 2)

	// 44-51: aget/aput
	for i := byte(0x44); i <= 0x4a; i++ {
		names := []string{"aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short"}
		set(i, names[i-0x44], Fmt23x, RefNone, 2)
	}
	for i := byte(0x4b); i <= 0x51; i++ {
		names := []string{"aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short"}
		set(i, names[i-0x4b], Fmt23x, RefNone, 2)
	}

	// 52-5f: iget/iput
	for i := byte(0x52); i <= 0x58; i++ {
		names := []string{"iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short"}
		set(i, names[i-0x52], Fmt22c, RefField, 2)
	}
	for i := byte(0x59); i <= 0x5f; i++ {
		names := []string{"iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char", "iput-short"}
		set(i, names[i-0x59], Fmt22c, RefField, 2)
	}

	// 60-6d: sget/sput
	for i := byte(0x60); i <= 0x66; i++ {
		names := []string{"sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short"}
		set(i, names[i-0x60], Fmt21c, RefField, 2)
	}
	for i := byte(0x67); i <= 0x6d; i++ {
		names := []string{"sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char", "sput-short"}
		set(i, names[i-0x67], Fmt21c, RefField, 2)
	}

	// 6e-72: invoke
	set(0x6e, "invoke-virtual", Fmt35c, RefMethod, 3)
	set(0x6f, "invoke-super", Fmt35c, RefMethod, 3)
	set(0x70, "invoke-direct", Fmt35c, RefMethod, 3)
	set(0x71, "invoke-static", Fmt35c, RefMethod, 3)
	set(0x72, "invoke-interface", Fmt35c, RefMethod, 3)

	// 74-78: invoke/range
	set(0x74, "invoke-virtual/range", Fmt3rc, RefMethod, 3)
	set(0x75, "invoke-super/range", Fmt3rc, RefMethod, 3)
	set(0x76, "invoke-direct/range", Fmt3rc, RefMethod, 3)
	set(0x77, "invoke-static/range", Fmt3rc, RefMethod, 3)
	set(0x78, "invoke-interface/range", Fmt3rc, RefMethod, 3)

	// 7b-8f: unary ops
	unaryOps := []string{
		"neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double",
		"int-to-long", "int-to-float", "int-to-double",
		"long-to-int", "long-to-float", "long-to-double",
		"float-to-int", "float-to-long", "float-to-double",
		"double-to-int", "double-to-long", "double-to-float",
		"int-to-byte", "int-to-char", "int-to-short",
	}
	for i, name := range unaryOps {
		set(byte(0x7b+i), name, Fmt12x, RefNone, 1)
	}

	// 90-af: binary ops (23x)
	binOps := []string{
		"add-int", "sub-int", "mul-int", "div-int", "rem-int",
		"and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
		"add-long", "sub-long", "mul-long", "div-long", "rem-long",
		"and-long", "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
		"add-float", "sub-float", "mul-float", "div-float", "rem-float",
		"add-double", "sub-double", "mul-double", "div-double", "rem-double",
	}
	for i, name := range binOps {
		set(byte(0x90+i), name, Fmt23x, RefNone, 2)
	}

	// b0-cf: binary ops /2addr (12x)
	binOps2addr := []string{
		"add-int/2addr", "sub-int/2addr", "mul-int/2addr", "div-int/2addr", "rem-int/2addr",
		"and-int/2addr", "or-int/2addr", "xor-int/2addr", "shl-int/2addr", "shr-int/2addr", "ushr-int/2addr",
		"add-long/2addr", "sub-long/2addr", "mul-long/2addr", "div-long/2addr", "rem-long/2addr",
		"and-long/2addr", "or-long/2addr", "xor-long/2addr", "shl-long/2addr", "shr-long/2addr", "ushr-long/2addr",
		"add-float/2addr", "sub-float/2addr", "mul-float/2addr", "div-float/2addr", "rem-float/2addr",
		"add-double/2addr", "sub-double/2addr", "mul-double/2addr", "div-double/2addr", "rem-double/2addr",
	}
	for i, name := range binOps2addr {
		set(byte(0xb0+i), name, Fmt12x, RefNone, 1)
	}

	// d0-d7: binary ops /lit16 (22s)
	litOps16 := []string{
		"add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16",
		"rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16",
	}
	for i, name := range litOps16 {
		set(byte(0xd0+i), name, Fmt22s, RefNone, 2)
	}

	// d8-e2: binary ops /lit8 (22b)
	litOps8 := []string{
		"add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8",
		"rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8",
		"shl-int/lit8", "shr-int/lit8", "ushr-int/lit8",
	}
	for i, name := range litOps8 {
		set(byte(0xd8+i), name, Fmt22b, RefNone, 2)
	}

	// fa-fb: invoke-polymorphic (DEX 038+)
	set(0xfa, "invoke-polymorphic", Fmt45cc, RefMethod, 4)
	set(0xfb, "invoke-polymorphic/range", Fmt4rcc, RefMethod, 4)

	// fc-fd: invoke-custom (DEX 038+)
	set(0xfc, "invoke-custom", Fmt35c, RefMethod, 3)
	set(0xfd, "invoke-custom/range", Fmt3rc, RefMethod, 3)

	// fe-ff: const-method-handle/type (DEX 039+)
	set(0xfe, "const-method-handle", Fmt21c, RefMethod, 2)
	set(0xff, "const-method-type", Fmt21c, RefProto, 2)
}
