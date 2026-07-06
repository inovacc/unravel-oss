/*
Copyright (c) 2026 Security Research
*/
package smali

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

// AccessFlag constants for Dalvik classes/methods/fields.
const (
	AccPublic       = 0x0001
	AccPrivate      = 0x0002
	AccProtected    = 0x0004
	AccStatic       = 0x0008
	AccFinal        = 0x0010
	AccSynchronized = 0x0020
	AccVolatile     = 0x0040 // field
	AccBridge       = 0x0040 // method
	AccTransient    = 0x0080 // field
	AccVarargs      = 0x0080 // method
	AccNative       = 0x0100
	AccInterface    = 0x0200
	AccAbstract     = 0x0400
	AccStrictfp     = 0x0800
	AccSynthetic    = 0x1000
	AccAnnotation   = 0x2000
	AccEnum         = 0x4000
	AccConstructor  = 0x10000
	AccDeclSync     = 0x20000
)

// Instruction represents a decoded Dalvik instruction.
type Instruction struct {
	Offset  uint32 // byte offset in code_item insns array (in 16-bit units)
	Opcode  byte
	Info    OpcodeInfo
	Raw     []uint16 // raw 16-bit code units
	Operand string   // formatted operand string
}

// MethodCode holds the disassembled instructions for a method.
type MethodCode struct {
	ClassName    string
	MethodName   string
	Descriptor   string
	AccessFlags  uint32
	Registers    uint16
	InsSize      uint16
	OutsSize     uint16
	Instructions []Instruction
	TryBlocks    []TryBlock
}

// TryBlock describes an exception handler range.
type TryBlock struct {
	StartAddr  uint32
	InsnCount  uint16
	HandlerOff uint16
	Handlers   []CatchHandler
}

// CatchHandler describes a single catch clause.
type CatchHandler struct {
	TypeIdx   int    // -1 for catch-all
	TypeName  string // resolved type name
	HandlerPC uint32
}

// DisassembleResult holds all disassembled methods from a DEX file.
type DisassembleResult struct {
	DexFile *dex.DexFile
	Methods []MethodCode
}

// Disassemble reads all class_data_items from a DEX file and disassembles
// the bytecode of every method into Smali instructions.
func Disassemble(r io.ReaderAt, size int64, dexFile *dex.DexFile) (*DisassembleResult, error) {
	result := &DisassembleResult{DexFile: dexFile}

	for _, cls := range dexFile.Classes {
		if cls.ClassDataOff == 0 {
			continue
		}

		methods, err := readClassData(r, size, cls, dexFile)
		if err != nil {
			// Non-fatal: skip classes with parse errors
			continue
		}
		result.Methods = append(result.Methods, methods...)
	}

	return result, nil
}

// readClassData reads the class_data_item at the given offset and
// decodes all method bytecodes.
func readClassData(r io.ReaderAt, size int64, cls dex.ClassDef, dexFile *dex.DexFile) ([]MethodCode, error) {
	// Read raw bytes starting from ClassDataOff
	buf := make([]byte, 4096)
	n, err := r.ReadAt(buf, int64(cls.ClassDataOff))
	if err != nil && n == 0 {
		return nil, err
	}
	buf = buf[:n]

	pos := 0

	// Read ULEB128 counts
	staticFieldsSize, pos := readULEB128(buf, pos)
	instanceFieldsSize, pos := readULEB128(buf, pos)
	directMethodsSize, pos := readULEB128(buf, pos)
	virtualMethodsSize, pos := readULEB128(buf, pos)

	// Skip fields
	var fieldIdx uint32
	for range staticFieldsSize {
		diff, p := readULEB128(buf, pos)
		pos = p
		fieldIdx += diff
		_, pos = readULEB128(buf, pos) // access_flags
	}
	fieldIdx = 0
	for range instanceFieldsSize {
		diff, p := readULEB128(buf, pos)
		pos = p
		fieldIdx += diff
		_, pos = readULEB128(buf, pos) // access_flags
	}

	var methods []MethodCode

	// Read direct methods
	var methodIdx uint32
	for range directMethodsSize {
		diff, p := readULEB128(buf, pos)
		pos = p
		methodIdx += diff
		accessFlags, p := readULEB128(buf, pos)
		pos = p
		codeOff, p := readULEB128(buf, pos)
		pos = p

		if codeOff != 0 {
			mc, err := readCodeItem(r, size, codeOff, cls.ClassName, methodIdx, accessFlags, dexFile)
			if err == nil {
				methods = append(methods, mc)
			}
		}
	}

	// Read virtual methods
	methodIdx = 0
	for range virtualMethodsSize {
		diff, p := readULEB128(buf, pos)
		pos = p
		methodIdx += diff
		accessFlags, p := readULEB128(buf, pos)
		pos = p
		codeOff, p := readULEB128(buf, pos)
		pos = p

		if codeOff != 0 {
			mc, err := readCodeItem(r, size, codeOff, cls.ClassName, methodIdx, accessFlags, dexFile)
			if err == nil {
				methods = append(methods, mc)
			}
		}
	}

	return methods, nil
}

// readCodeItem reads and disassembles a code_item structure.
func readCodeItem(r io.ReaderAt, size int64, codeOff uint32, className string, methodIdx, accessFlags uint32, dexFile *dex.DexFile) (MethodCode, error) {
	mc := MethodCode{
		ClassName:   className,
		AccessFlags: accessFlags,
	}
	if int(methodIdx) < len(dexFile.Methods) {
		mc.MethodName = dexFile.Methods[methodIdx].Name
	} else {
		mc.MethodName = fmt.Sprintf("method_%d", methodIdx)
	}

	// code_item header: 16 bytes
	// registers_size (u16), ins_size (u16), outs_size (u16), tries_size (u16), debug_info_off (u32), insns_size (u32)
	var header struct {
		RegistersSize uint16
		InsSize       uint16
		OutsSize      uint16
		TriesSize     uint16
		DebugInfoOff  uint32
		InsnsSize     uint32
	}

	hdrBuf := make([]byte, 16)
	if _, err := r.ReadAt(hdrBuf, int64(codeOff)); err != nil {
		return mc, err
	}
	header.RegistersSize = binary.LittleEndian.Uint16(hdrBuf[0:2])
	header.InsSize = binary.LittleEndian.Uint16(hdrBuf[2:4])
	header.OutsSize = binary.LittleEndian.Uint16(hdrBuf[4:6])
	header.TriesSize = binary.LittleEndian.Uint16(hdrBuf[6:8])
	header.DebugInfoOff = binary.LittleEndian.Uint32(hdrBuf[8:12])
	header.InsnsSize = binary.LittleEndian.Uint32(hdrBuf[12:16])

	mc.Registers = header.RegistersSize
	mc.InsSize = header.InsSize
	mc.OutsSize = header.OutsSize

	if header.InsnsSize == 0 {
		return mc, nil
	}

	// Cap instruction read at 64KB to avoid excessive memory
	insnBytes := min(int(header.InsnsSize)*2, 65536)

	insns := make([]byte, insnBytes)
	if _, err := r.ReadAt(insns, int64(codeOff)+16); err != nil {
		return mc, err
	}

	// Decode instructions
	mc.Instructions = decodeInstructions(insns, dexFile)

	return mc, nil
}

// decodeInstructions decodes a byte slice of Dalvik instructions.
func decodeInstructions(insns []byte, dexFile *dex.DexFile) []Instruction {
	var result []Instruction
	// Convert to uint16 array
	units := make([]uint16, len(insns)/2)
	for i := 0; i+1 < len(insns); i += 2 {
		units[i/2] = binary.LittleEndian.Uint16(insns[i : i+2])
	}

	offset := uint32(0)
	for offset < uint32(len(units)) {
		op := byte(units[offset] & 0xFF)
		info := Opcodes[op]

		width := info.Width
		if width <= 0 || int(offset)+width > len(units) {
			// Unknown or truncated
			result = append(result, Instruction{
				Offset: offset,
				Opcode: op,
				Info:   info,
				Raw:    []uint16{units[offset]},
			})
			offset++
			continue
		}

		raw := units[offset : offset+uint32(width)]
		insn := Instruction{
			Offset: offset,
			Opcode: op,
			Info:   info,
			Raw:    raw,
		}
		insn.Operand = formatOperand(info, raw, dexFile)

		result = append(result, insn)
		offset += uint32(width)
	}

	return result
}

// formatOperand creates a human-readable operand string for an instruction.
func formatOperand(info OpcodeInfo, raw []uint16, dexFile *dex.DexFile) string {
	if len(raw) == 0 {
		return ""
	}

	unit0 := raw[0]
	a := (unit0 >> 8) & 0xFF
	b4hi := (unit0 >> 12) & 0xF
	a4lo := (unit0 >> 8) & 0xF

	switch info.Format {
	case Fmt10x:
		return ""
	case Fmt12x:
		return fmt.Sprintf("v%d, v%d", a4lo, b4hi)
	case Fmt11n:
		lit := int8(b4hi<<4) >> 4 // sign-extend 4-bit
		return fmt.Sprintf("v%d, #int %d", a4lo, lit)
	case Fmt11x:
		return fmt.Sprintf("v%d", a)
	case Fmt10t:
		off := int8(a)
		return fmt.Sprintf("%+d", off)
	case Fmt20t:
		if len(raw) < 2 {
			return ""
		}
		return fmt.Sprintf("%+d", int16(raw[1]))
	case Fmt22x:
		if len(raw) < 2 {
			return ""
		}
		return fmt.Sprintf("v%d, v%d", a, raw[1])
	case Fmt21t:
		if len(raw) < 2 {
			return ""
		}
		return fmt.Sprintf("v%d, %+d", a, int16(raw[1]))
	case Fmt21s:
		if len(raw) < 2 {
			return ""
		}
		return fmt.Sprintf("v%d, #int %d", a, int16(raw[1]))
	case Fmt21h:
		if len(raw) < 2 {
			return ""
		}
		return fmt.Sprintf("v%d, #int %d", a, int32(int16(raw[1]))<<16)
	case Fmt21c:
		if len(raw) < 2 {
			return ""
		}
		ref := resolveRef(info.Ref, int(raw[1]), dexFile)
		return fmt.Sprintf("v%d, %s", a, ref)
	case Fmt23x:
		if len(raw) < 2 {
			return ""
		}
		bb := raw[1] & 0xFF
		cc := (raw[1] >> 8) & 0xFF
		return fmt.Sprintf("v%d, v%d, v%d", a, bb, cc)
	case Fmt22b:
		if len(raw) < 2 {
			return ""
		}
		bb := raw[1] & 0xFF
		cc := int8(raw[1] >> 8)
		return fmt.Sprintf("v%d, v%d, #int %d", a, bb, cc)
	case Fmt22t:
		if len(raw) < 2 {
			return ""
		}
		return fmt.Sprintf("v%d, v%d, %+d", a4lo, b4hi, int16(raw[1]))
	case Fmt22s:
		if len(raw) < 2 {
			return ""
		}
		return fmt.Sprintf("v%d, v%d, #int %d", a4lo, b4hi, int16(raw[1]))
	case Fmt22c:
		if len(raw) < 2 {
			return ""
		}
		ref := resolveRef(info.Ref, int(raw[1]), dexFile)
		return fmt.Sprintf("v%d, v%d, %s", a4lo, b4hi, ref)
	case Fmt30t:
		if len(raw) < 3 {
			return ""
		}
		off := int32(raw[1]) | int32(raw[2])<<16
		return fmt.Sprintf("%+d", off)
	case Fmt32x:
		if len(raw) < 3 {
			return ""
		}
		return fmt.Sprintf("v%d, v%d", raw[1], raw[2])
	case Fmt31i:
		if len(raw) < 3 {
			return ""
		}
		val := int32(raw[1]) | int32(raw[2])<<16
		return fmt.Sprintf("v%d, #int %d", a, val)
	case Fmt31t:
		if len(raw) < 3 {
			return ""
		}
		off := int32(raw[1]) | int32(raw[2])<<16
		return fmt.Sprintf("v%d, %+d", a, off)
	case Fmt31c:
		if len(raw) < 3 {
			return ""
		}
		idx := int(raw[1]) | int(raw[2])<<16
		ref := resolveRef(info.Ref, idx, dexFile)
		return fmt.Sprintf("v%d, %s", a, ref)
	case Fmt35c:
		return format35c(raw, info.Ref, dexFile)
	case Fmt3rc:
		return format3rc(raw, a, info.Ref, dexFile)
	case Fmt51l:
		if len(raw) < 5 {
			return ""
		}
		val := int64(raw[1]) | int64(raw[2])<<16 | int64(raw[3])<<32 | int64(raw[4])<<48
		return fmt.Sprintf("v%d, #long %d", a, val)
	}

	return ""
}

func format35c(raw []uint16, refKind RefKind, dexFile *dex.DexFile) string {
	if len(raw) < 3 {
		return ""
	}
	a := min(
		// arg count (0-5)
		(raw[0]>>12)&0xF, 5)
	methodIdx := int(raw[1])
	ref := resolveRef(refKind, methodIdx, dexFile)

	regs := make([]string, 0, a)
	if a > 0 {
		// C, D, E, F, G packed into raw[2] and raw[0] bits
		bits := uint32(raw[2]) | (uint32(raw[0]>>8)&0xF)<<16
		regNames := [5]string{
			fmt.Sprintf("v%d", bits&0xF),
			fmt.Sprintf("v%d", (bits>>4)&0xF),
			fmt.Sprintf("v%d", (bits>>8)&0xF),
			fmt.Sprintf("v%d", (bits>>12)&0xF),
			fmt.Sprintf("v%d", (bits>>16)&0xF),
		}
		for i := range a {
			regs = append(regs, regNames[i])
		}
	}

	return fmt.Sprintf("{%s}, %s", strings.Join(regs, ", "), ref)
}

func format3rc(raw []uint16, a uint16, refKind RefKind, dexFile *dex.DexFile) string {
	if len(raw) < 3 {
		return ""
	}
	methodIdx := int(raw[1])
	startReg := raw[2]
	ref := resolveRef(refKind, methodIdx, dexFile)

	if a == 0 {
		return fmt.Sprintf("{}, %s", ref)
	}
	if a == 1 {
		return fmt.Sprintf("{v%d}, %s", startReg, ref)
	}
	return fmt.Sprintf("{v%d .. v%d}, %s", startReg, startReg+a-1, ref)
}

func resolveRef(kind RefKind, idx int, dexFile *dex.DexFile) string {
	switch kind {
	case RefString:
		if idx >= 0 && idx < len(dexFile.Strings) {
			return fmt.Sprintf("%q", dexFile.Strings[idx])
		}
		return fmt.Sprintf("string@%04x", idx)
	case RefType:
		if idx >= 0 && idx < len(dexFile.Types) {
			return dexFile.Types[idx]
		}
		return fmt.Sprintf("type@%04x", idx)
	case RefField:
		if idx >= 0 && idx < len(dexFile.Fields) {
			f := dexFile.Fields[idx]
			return fmt.Sprintf("%s->%s:%s", f.ClassName, f.Name, f.TypeName)
		}
		return fmt.Sprintf("field@%04x", idx)
	case RefMethod:
		if idx >= 0 && idx < len(dexFile.Methods) {
			m := dexFile.Methods[idx]
			return fmt.Sprintf("%s->%s", m.ClassName, m.Name)
		}
		return fmt.Sprintf("method@%04x", idx)
	case RefProto:
		return fmt.Sprintf("proto@%04x", idx)
	}
	return fmt.Sprintf("@%04x", idx)
}

func readULEB128(buf []byte, pos int) (uint32, int) {
	var result uint32
	var shift uint
	for pos < len(buf) {
		b := buf[pos]
		pos++
		result |= uint32(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result, pos
}

// AccessFlagsToString converts access flags to Smali access modifiers.
func AccessFlagsToString(flags uint32, forClass bool) string {
	var parts []string
	if flags&AccPublic != 0 {
		parts = append(parts, "public")
	}
	if flags&AccPrivate != 0 {
		parts = append(parts, "private")
	}
	if flags&AccProtected != 0 {
		parts = append(parts, "protected")
	}
	if flags&AccStatic != 0 {
		parts = append(parts, "static")
	}
	if flags&AccFinal != 0 {
		parts = append(parts, "final")
	}
	if forClass {
		if flags&AccInterface != 0 {
			parts = append(parts, "interface")
		}
		if flags&AccAbstract != 0 {
			parts = append(parts, "abstract")
		}
		if flags&AccAnnotation != 0 {
			parts = append(parts, "annotation")
		}
		if flags&AccEnum != 0 {
			parts = append(parts, "enum")
		}
	} else {
		if flags&AccSynchronized != 0 {
			parts = append(parts, "synchronized")
		}
		if flags&AccNative != 0 {
			parts = append(parts, "native")
		}
		if flags&AccAbstract != 0 {
			parts = append(parts, "abstract")
		}
		if flags&AccSynthetic != 0 {
			parts = append(parts, "synthetic")
		}
		if flags&AccConstructor != 0 {
			parts = append(parts, "constructor")
		}
	}
	return strings.Join(parts, " ")
}
