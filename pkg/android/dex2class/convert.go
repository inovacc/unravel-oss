/*
Copyright (c) 2026 Security Research
*/
package dex2class

import (
	"encoding/binary"
	"io"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

// classData mirrors the class_data_item structure from the DEX format.
type classData struct {
	staticFields   []encodedField
	instanceFields []encodedField
	directMethods  []encodedMethod
	virtualMethods []encodedMethod
}

type encodedField struct {
	fieldIdx    uint32
	accessFlags uint32
}

type encodedMethod struct {
	methodIdx   uint32
	accessFlags uint32
	codeOff     uint32
}

// codeItem holds a parsed code_item from the DEX file.
type codeItem struct {
	registersSize uint16
	insSize       uint16
	outsSize      uint16
	triesSize     uint16
	insnsSize     uint32
	insns         []byte
}

// readClassDataItem reads a class_data_item from the DEX file at the given offset.
func readClassDataItem(r io.ReaderAt, off uint32) (*classData, error) {
	buf := make([]byte, 8192)
	n, err := r.ReadAt(buf, int64(off))
	if err != nil && n == 0 {
		return nil, err
	}
	buf = buf[:n]

	pos := 0
	cd := &classData{}

	staticFieldsSize, pos := readULEB128(buf, pos)
	instanceFieldsSize, pos := readULEB128(buf, pos)
	directMethodsSize, pos := readULEB128(buf, pos)
	virtualMethodsSize, pos := readULEB128(buf, pos)

	// Read static fields
	var fieldIdx uint32
	for range staticFieldsSize {
		diff, p := readULEB128(buf, pos)
		pos = p
		fieldIdx += diff
		af, p := readULEB128(buf, pos)
		pos = p
		cd.staticFields = append(cd.staticFields, encodedField{fieldIdx: fieldIdx, accessFlags: af})
	}

	// Read instance fields
	fieldIdx = 0
	for range instanceFieldsSize {
		diff, p := readULEB128(buf, pos)
		pos = p
		fieldIdx += diff
		af, p := readULEB128(buf, pos)
		pos = p
		cd.instanceFields = append(cd.instanceFields, encodedField{fieldIdx: fieldIdx, accessFlags: af})
	}

	// Read direct methods
	var methodIdx uint32
	for range directMethodsSize {
		diff, p := readULEB128(buf, pos)
		pos = p
		methodIdx += diff
		af, p := readULEB128(buf, pos)
		pos = p
		co, p := readULEB128(buf, pos)
		pos = p
		cd.directMethods = append(cd.directMethods, encodedMethod{methodIdx: methodIdx, accessFlags: af, codeOff: co})
	}

	// Read virtual methods
	methodIdx = 0
	for range virtualMethodsSize {
		diff, p := readULEB128(buf, pos)
		pos = p
		methodIdx += diff
		af, p := readULEB128(buf, pos)
		pos = p
		co, p := readULEB128(buf, pos)
		pos = p
		cd.virtualMethods = append(cd.virtualMethods, encodedMethod{methodIdx: methodIdx, accessFlags: af, codeOff: co})
	}

	return cd, nil
}

// readCodeItem reads the code_item header and instruction bytes.
func readCodeItem(r io.ReaderAt, off uint32) (*codeItem, error) {
	hdr := make([]byte, 16)
	if _, err := r.ReadAt(hdr, int64(off)); err != nil {
		return nil, err
	}

	ci := &codeItem{
		registersSize: binary.LittleEndian.Uint16(hdr[0:2]),
		insSize:       binary.LittleEndian.Uint16(hdr[2:4]),
		outsSize:      binary.LittleEndian.Uint16(hdr[4:6]),
		triesSize:     binary.LittleEndian.Uint16(hdr[6:8]),
		insnsSize:     binary.LittleEndian.Uint32(hdr[12:16]),
	}

	if ci.insnsSize == 0 {
		return ci, nil
	}

	insnBytes := min(int(ci.insnsSize)*2, 65536)

	ci.insns = make([]byte, insnBytes)
	if _, err := r.ReadAt(ci.insns, int64(off)+16); err != nil {
		return nil, err
	}

	return ci, nil
}

// converter translates Dalvik instructions to JVM bytecode.
type converter struct {
	cw       *classWriter
	dexFile  *dex.DexFile
	code     []byte
	maxStack int
}

// newConverter creates a converter for a single method.
func newConverter(cw *classWriter, dexFile *dex.DexFile) *converter {
	return &converter{
		cw:      cw,
		dexFile: dexFile,
	}
}

// translate converts Dalvik register-based bytecode to JVM stack-based bytecode.
func (c *converter) translate(insns []byte, registersSize uint16) []byte {
	c.code = nil
	c.maxStack = 1 // minimum stack depth

	// Convert insn bytes to uint16 array
	units := make([]uint16, len(insns)/2)
	for i := 0; i+1 < len(insns); i += 2 {
		units[i/2] = binary.LittleEndian.Uint16(insns[i : i+2])
	}

	offset := 0
	for offset < len(units) {
		op := byte(units[offset] & 0xFF)
		width := dalvikWidth(op)
		if width <= 0 || offset+width > len(units) {
			offset++
			continue
		}

		raw := units[offset : offset+width]
		c.translateInsn(op, raw, registersSize)
		offset += width
	}

	return c.code
}

// translateInsn converts a single Dalvik instruction to JVM bytecode.
func (c *converter) translateInsn(op byte, raw []uint16, regs uint16) {
	unit0 := raw[0]
	a := int(unit0>>8) & 0xFF  // 8-bit register A
	a4 := int(unit0>>8) & 0xF  // 4-bit register A
	b4 := int(unit0>>12) & 0xF // 4-bit register B

	switch {
	// nop
	case op == 0x00:
		c.emit(jvmNop)

	// move vA, vB (12x)
	case op == 0x01:
		c.emitLoad(b4)
		c.emitStore(a4)

	// move/from16 vAA, vBBBB (22x)
	case op == 0x02 && len(raw) >= 2:
		c.emitLoad(int(raw[1]))
		c.emitStore(a)

	// move-object vA, vB (12x)
	case op == 0x07:
		c.emitALoad(b4)
		c.emitAStore(a4)

	// move-object/from16 vAA, vBBBB
	case op == 0x08 && len(raw) >= 2:
		c.emitALoad(int(raw[1]))
		c.emitAStore(a)

	// move-result vAA — previous invoke left result on stack, store it
	case op == 0x0a || op == 0x0b || op == 0x0c:
		c.emitStore(a)

	// return-void
	case op == 0x0e:
		c.emit(jvmReturn)

	// return vAA
	case op == 0x0f:
		c.emitLoad(a)
		c.emit(jvmIReturn)
		c.trackStack(2)

	// return-wide vAA
	case op == 0x10:
		c.emitLoad(a)
		c.emit(jvmLReturn)
		c.trackStack(2)

	// return-object vAA
	case op == 0x11:
		c.emitALoad(a)
		c.emit(jvmAReturn)
		c.trackStack(2)

	// const/4 vA, #+B (11n)
	case op == 0x12:
		lit := int8(b4<<4) >> 4 // sign-extend 4-bit
		c.emitIntConst(int32(lit))
		c.emitStore(a4)
		c.trackStack(2)

	// const/16 vAA, #+BBBB (21s)
	case op == 0x13 && len(raw) >= 2:
		c.emitIntConst(int32(int16(raw[1])))
		c.emitStore(a)
		c.trackStack(2)

	// const vAA, #+BBBBBBBB (31i)
	case op == 0x14 && len(raw) >= 3:
		val := int32(raw[1]) | int32(raw[2])<<16
		c.emitIntConst(val)
		c.emitStore(a)
		c.trackStack(2)

	// const/high16 vAA, #+BBBB0000 (21h)
	case op == 0x15 && len(raw) >= 2:
		val := int32(int16(raw[1])) << 16
		c.emitIntConst(val)
		c.emitStore(a)
		c.trackStack(2)

	// const-string vAA, string@BBBB (21c)
	case op == 0x1a && len(raw) >= 2:
		strIdx := int(raw[1])
		str := ""
		if strIdx < len(c.dexFile.Strings) {
			str = c.dexFile.Strings[strIdx]
		}
		cpIdx := c.cw.addString(str)
		if cpIdx <= 255 {
			c.emit(jvmLdc)
			c.emit(byte(cpIdx))
		} else {
			c.emit(jvmLdcW)
			c.emitU2(cpIdx)
		}
		c.emitAStore(a)
		c.trackStack(2)

	// const-class vAA, type@BBBB
	case op == 0x1c && len(raw) >= 2:
		typeIdx := int(raw[1])
		typeName := "java/lang/Object"
		if typeIdx < len(c.dexFile.Types) {
			typeName = dexTypeToInternal(c.dexFile.Types[typeIdx])
		}
		cpIdx := c.cw.addClass(typeName)
		c.emit(jvmLdcW)
		c.emitU2(cpIdx)
		c.emitAStore(a)
		c.trackStack(2)

	// monitor-enter vAA
	case op == 0x1d:
		c.emitALoad(a)
		c.emit(jvmMonitorEnter)
		c.trackStack(2)

	// monitor-exit vAA
	case op == 0x1e:
		c.emitALoad(a)
		c.emit(jvmMonitorExit)
		c.trackStack(2)

	// check-cast vAA, type@BBBB
	case op == 0x1f && len(raw) >= 2:
		typeIdx := int(raw[1])
		typeName := "java/lang/Object"
		if typeIdx < len(c.dexFile.Types) {
			typeName = dexTypeToInternal(c.dexFile.Types[typeIdx])
		}
		cpIdx := c.cw.addClass(typeName)
		c.emitALoad(a)
		c.emit(jvmCheckCast)
		c.emitU2(cpIdx)
		c.emitAStore(a)
		c.trackStack(2)

	// instance-of vA, vB, type@CCCC
	case op == 0x20 && len(raw) >= 2:
		typeIdx := int(raw[1])
		typeName := "java/lang/Object"
		if typeIdx < len(c.dexFile.Types) {
			typeName = dexTypeToInternal(c.dexFile.Types[typeIdx])
		}
		cpIdx := c.cw.addClass(typeName)
		c.emitALoad(b4)
		c.emit(jvmInstanceOf)
		c.emitU2(cpIdx)
		c.emitStore(a4)
		c.trackStack(2)

	// array-length vA, vB
	case op == 0x21:
		c.emitALoad(b4)
		c.emit(jvmArrayLength)
		c.emitStore(a4)
		c.trackStack(2)

	// new-instance vAA, type@BBBB
	// In Dalvik, new-instance allocates then a later invoke-direct calls <init>.
	// In JVM, the pattern is: new → dup → args → invokespecial <init> → astore.
	// We emit: new → dup → astore. The astore stores the dup'd ref, leaving
	// the original on the stack for the decompiler to see new+<init> together.
	// However, since the <init> invoke may be many instructions later,
	// we store immediately and let the decompiler handle it.
	case op == 0x22 && len(raw) >= 2:
		typeIdx := int(raw[1])
		typeName := "java/lang/Object"
		if typeIdx < len(c.dexFile.Types) {
			typeName = dexTypeToInternal(c.dexFile.Types[typeIdx])
		}
		cpIdx := c.cw.addClass(typeName)
		c.emit(jvmNew)
		c.emitU2(cpIdx)
		c.emit(jvmDup)
		c.emitAStore(a)
		c.trackStack(3)

	// throw vAA
	case op == 0x27:
		c.emitALoad(a)
		c.emit(jvmAThrow)
		c.trackStack(2)

	// goto +AA (10t)
	case op == 0x28:
		off := int8(a)
		// In JVM, goto takes a 2-byte signed offset relative to the goto instruction
		// We emit a placeholder since we'd need a proper label system for real offsets
		c.emit(jvmGoto)
		c.emitU2(uint16(int16(off) * 2)) // rough approximation

	// if-eq vA, vB, +CCCC (22t)
	case op >= 0x32 && op <= 0x37 && len(raw) >= 2:
		c.emitLoad(a4)
		c.emitLoad(b4)
		jvmOp := jvmIfICmpEq + byte(op-0x32)
		c.emit(jvmOp)
		c.emitU2(uint16(int16(raw[1]) * 2))
		c.trackStack(3)

	// if-eqz vAA, +BBBB (21t)
	case op >= 0x38 && op <= 0x3d && len(raw) >= 2:
		c.emitLoad(a)
		jvmOp := jvmIfEq + byte(op-0x38)
		c.emit(jvmOp)
		c.emitU2(uint16(int16(raw[1]) * 2))
		c.trackStack(2)

	// iget vA, vB, field@CCCC
	case op >= 0x52 && op <= 0x58 && len(raw) >= 2:
		fieldIdx := int(raw[1])
		className, fieldName, fieldType := c.resolveField(fieldIdx)
		cpIdx := c.cw.addFieldRef(className, fieldName, fieldType)
		c.emitALoad(b4)
		c.emit(jvmGetField)
		c.emitU2(cpIdx)
		c.emitStore(a4)
		c.trackStack(2)

	// iput vA, vB, field@CCCC
	case op >= 0x59 && op <= 0x5f && len(raw) >= 2:
		fieldIdx := int(raw[1])
		className, fieldName, fieldType := c.resolveField(fieldIdx)
		cpIdx := c.cw.addFieldRef(className, fieldName, fieldType)
		c.emitALoad(b4)
		c.emitLoad(a4)
		c.emit(jvmPutField)
		c.emitU2(cpIdx)
		c.trackStack(3)

	// sget vAA, field@BBBB
	case op >= 0x60 && op <= 0x66 && len(raw) >= 2:
		fieldIdx := int(raw[1])
		className, fieldName, fieldType := c.resolveField(fieldIdx)
		cpIdx := c.cw.addFieldRef(className, fieldName, fieldType)
		c.emit(jvmGetStatic)
		c.emitU2(cpIdx)
		c.emitStore(a)
		c.trackStack(2)

	// sput vAA, field@BBBB
	case op >= 0x67 && op <= 0x6d && len(raw) >= 2:
		fieldIdx := int(raw[1])
		className, fieldName, fieldType := c.resolveField(fieldIdx)
		cpIdx := c.cw.addFieldRef(className, fieldName, fieldType)
		c.emitLoad(a)
		c.emit(jvmPutStatic)
		c.emitU2(cpIdx)
		c.trackStack(2)

	// invoke-virtual {vC, vD, ...}, meth@BBBB (35c)
	case op == 0x6e && len(raw) >= 3:
		c.translateInvoke(raw, jvmInvokeVirtual)

	// invoke-super {vC, vD, ...}, meth@BBBB
	case op == 0x6f && len(raw) >= 3:
		c.translateInvoke(raw, jvmInvokeSpecial)

	// invoke-direct {vC, vD, ...}, meth@BBBB
	case op == 0x70 && len(raw) >= 3:
		c.translateInvoke(raw, jvmInvokeSpecial)

	// invoke-static {vC, vD, ...}, meth@BBBB
	case op == 0x71 && len(raw) >= 3:
		c.translateInvokeStatic(raw)

	// invoke-interface {vC, vD, ...}, meth@BBBB
	case op == 0x72 && len(raw) >= 3:
		c.translateInvokeInterface(raw)

	// neg-int vA, vB
	case op == 0x7b:
		c.emitLoad(b4)
		c.emit(jvmINeg)
		c.emitStore(a4)
		c.trackStack(2)

	// int-to-long vA, vB
	case op == 0x81:
		c.emitLoad(b4)
		c.emit(jvmI2L)
		c.emitStore(a4)
		c.trackStack(2)

	// int-to-float vA, vB
	case op == 0x82:
		c.emitLoad(b4)
		c.emit(jvmI2F)
		c.emitStore(a4)
		c.trackStack(2)

	// int-to-double vA, vB
	case op == 0x83:
		c.emitLoad(b4)
		c.emit(jvmI2D)
		c.emitStore(a4)
		c.trackStack(2)

	// long-to-int vA, vB
	case op == 0x84:
		c.emitLoad(b4)
		c.emit(jvmL2I)
		c.emitStore(a4)
		c.trackStack(2)

	// int-to-byte vA, vB
	case op == 0x8d:
		c.emitLoad(b4)
		c.emit(jvmI2B)
		c.emitStore(a4)
		c.trackStack(2)

	// int-to-char vA, vB
	case op == 0x8e:
		c.emitLoad(b4)
		c.emit(jvmI2C)
		c.emitStore(a4)
		c.trackStack(2)

	// int-to-short vA, vB
	case op == 0x8f:
		c.emitLoad(b4)
		c.emit(jvmI2S)
		c.emitStore(a4)
		c.trackStack(2)

	// add-int vAA, vBB, vCC (23x)
	case op >= 0x90 && op <= 0x9a && len(raw) >= 2:
		bb := int(raw[1] & 0xFF)
		cc := int(raw[1] >> 8)
		c.emitLoad(bb)
		c.emitLoad(cc)
		c.emitBinOp(op - 0x90)
		c.emitStore(a)
		c.trackStack(3)

	// add-int/2addr vA, vB (12x)
	case op >= 0xb0 && op <= 0xba:
		c.emitLoad(a4)
		c.emitLoad(b4)
		c.emitBinOp(op - 0xb0)
		c.emitStore(a4)
		c.trackStack(3)

	// add-int/lit16 vA, vB, #+CCCC
	case op >= 0xd0 && op <= 0xd7 && len(raw) >= 2:
		c.emitLoad(b4)
		c.emitIntConst(int32(int16(raw[1])))
		c.emitBinOp(op - 0xd0) // same int op mapping
		c.emitStore(a4)
		c.trackStack(3)

	// add-int/lit8 vAA, vBB, #+CC
	case op >= 0xd8 && op <= 0xe2 && len(raw) >= 2:
		bb := int(raw[1] & 0xFF)
		cc := int8(raw[1] >> 8)
		c.emitLoad(bb)
		c.emitIntConst(int32(cc))
		c.emitBinOp(op - 0xd8)
		c.emitStore(a)
		c.trackStack(3)

	default:
		// Unhandled opcode: emit nop
		c.emit(jvmNop)
	}
}

// emitBinOp emits the JVM instruction for a binary int operation (offset from add-int).
func (c *converter) emitBinOp(delta byte) {
	// Map: 0=add, 1=sub, 2=mul, 3=div, 4=rem, 5=and, 6=or, 7=xor, 8=shl, 9=shr, 10=ushr
	ops := []byte{jvmIAdd, jvmISub, jvmIMul, jvmIDiv, jvmIRem, jvmIAnd, jvmIOr, jvmIXor, jvmIShl, jvmIShr, jvmIUShr}
	idx := int(delta)
	if idx >= 0 && idx < len(ops) {
		c.emit(ops[idx])
	} else {
		c.emit(jvmNop)
	}
}

// translateInvoke handles invoke-virtual, invoke-super, invoke-direct (35c format).
func (c *converter) translateInvoke(raw []uint16, jvmOp byte) {
	argCount := int((raw[0] >> 12) & 0xF)
	methodIdx := int(raw[1])

	className, methodName, desc := c.resolveMethod(methodIdx)
	cpIdx := c.cw.addMethodRef(className, methodName, desc)

	// Push registers onto stack
	regs := decode35cRegs(raw, argCount)
	for _, r := range regs {
		c.emitALoad(r)
	}

	c.emit(jvmOp)
	c.emitU2(cpIdx)
	c.trackStack(argCount + 1)
}

// translateInvokeStatic handles invoke-static (35c format).
func (c *converter) translateInvokeStatic(raw []uint16) {
	argCount := int((raw[0] >> 12) & 0xF)
	methodIdx := int(raw[1])

	className, methodName, desc := c.resolveMethod(methodIdx)
	cpIdx := c.cw.addMethodRef(className, methodName, desc)

	regs := decode35cRegs(raw, argCount)
	for _, r := range regs {
		c.emitALoad(r)
	}

	c.emit(jvmInvokeStatic)
	c.emitU2(cpIdx)
	c.trackStack(argCount + 1)
}

// translateInvokeInterface handles invoke-interface (35c format).
func (c *converter) translateInvokeInterface(raw []uint16) {
	argCount := int((raw[0] >> 12) & 0xF)
	methodIdx := int(raw[1])

	className, methodName, desc := c.resolveMethod(methodIdx)

	// For invokeinterface, we use CONSTANT_InterfaceMethodref
	classIdx := c.cw.addClass(className)
	ntIdx := c.cw.addNameAndType(methodName, desc)
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:], classIdx)
	binary.BigEndian.PutUint16(data[2:], ntIdx)
	c.cw.pool = append(c.cw.pool, cpEntry{tag: cpIfaceRef, data: data})
	cpIdx := uint16(len(c.cw.pool) - 1)

	regs := decode35cRegs(raw, argCount)
	for _, r := range regs {
		c.emitALoad(r)
	}

	c.emit(jvmInvokeIface)
	c.emitU2(cpIdx)
	c.emit(byte(argCount)) // nargs
	c.emit(0)              // must be zero
	c.trackStack(argCount + 1)
}

// decode35cRegs extracts the register indices from a 35c-format instruction.
func decode35cRegs(raw []uint16, count int) []int {
	if count == 0 || len(raw) < 3 {
		return nil
	}
	bits := uint32(raw[2]) | (uint32(raw[0]>>8)&0xF)<<16
	regs := make([]int, 0, count)
	regValues := [5]int{
		int(bits & 0xF),
		int((bits >> 4) & 0xF),
		int((bits >> 8) & 0xF),
		int((bits >> 12) & 0xF),
		int((bits >> 16) & 0xF),
	}
	for i := 0; i < count && i < 5; i++ {
		regs = append(regs, regValues[i])
	}
	return regs
}

// resolveMethod returns the JVM internal class name, method name, and descriptor.
func (c *converter) resolveMethod(methodIdx int) (string, string, string) {
	if methodIdx >= 0 && methodIdx < len(c.dexFile.Methods) {
		m := c.dexFile.Methods[methodIdx]
		className := dexTypeToInternal(m.ClassName)
		desc := m.Descriptor
		if desc == "" {
			desc = resolveMethodDescriptor(m.Name)
		}
		return className, m.Name, desc
	}
	return "java/lang/Object", "unknown", "()V"
}

// resolveField returns the JVM internal class name, field name, and field type descriptor.
func (c *converter) resolveField(fieldIdx int) (string, string, string) {
	if fieldIdx >= 0 && fieldIdx < len(c.dexFile.Fields) {
		f := c.dexFile.Fields[fieldIdx]
		className := dexTypeToInternal(f.ClassName)
		fieldType := dexTypeToDescriptor(f.TypeName)
		return className, f.Name, fieldType
	}
	return "java/lang/Object", "unknown", "Ljava/lang/Object;"
}

// emit appends a single byte to the output.
func (c *converter) emit(b byte) {
	c.code = append(c.code, b)
}

// emitU2 appends a big-endian 16-bit value.
func (c *converter) emitU2(v uint16) {
	c.code = append(c.code, byte(v>>8), byte(v))
}

// emitLoad emits iload for a register (treating as int by default).
func (c *converter) emitLoad(reg int) {
	c.emit(jvmILoad)
	c.emit(byte(reg))
	c.trackStack(1)
}

// emitStore emits istore for a register.
func (c *converter) emitStore(reg int) {
	c.emit(jvmIStore)
	c.emit(byte(reg))
}

// emitALoad emits aload for a register (object reference).
func (c *converter) emitALoad(reg int) {
	c.emit(jvmALoad)
	c.emit(byte(reg))
	c.trackStack(1)
}

// emitAStore emits astore for a register (object reference).
func (c *converter) emitAStore(reg int) {
	c.emit(jvmAStore)
	c.emit(byte(reg))
}

// emitIntConst emits the most compact JVM instruction for an integer constant.
func (c *converter) emitIntConst(val int32) {
	switch {
	case val >= -1 && val <= 5:
		c.emit(byte(jvmIConst0 + val)) // iconst_m1 .. iconst_5
	case val >= -128 && val <= 127:
		c.emit(jvmBiPush)
		c.emit(byte(val))
	case val >= -32768 && val <= 32767:
		c.emit(jvmSiPush)
		c.emitU2(uint16(val))
	default:
		cpIdx := c.cw.addInteger(val)
		if cpIdx <= 255 {
			c.emit(jvmLdc)
			c.emit(byte(cpIdx))
		} else {
			c.emit(jvmLdcW)
			c.emitU2(cpIdx)
		}
	}
	c.trackStack(1)
}

// trackStack updates maxStack if needed.
func (c *converter) trackStack(depth int) {
	if depth > c.maxStack {
		c.maxStack = depth
	}
}

// dalvikWidth returns the instruction width in 16-bit units for common opcodes.
func dalvikWidth(op byte) int {
	switch {
	// 10x, 12x, 11n, 11x, 10t (1 unit)
	case op == 0x00, op == 0x01, op == 0x04, op == 0x07:
		return 1
	case op >= 0x0a && op <= 0x0e:
		return 1
	case op == 0x0f, op == 0x10, op == 0x11:
		return 1
	case op == 0x12:
		return 1
	case op == 0x1d, op == 0x1e:
		return 1
	case op == 0x21:
		return 1
	case op == 0x27:
		return 1
	case op == 0x28:
		return 1
	case op >= 0x7b && op <= 0x8f:
		return 1
	case op >= 0xb0 && op <= 0xcf:
		return 1

	// 2 units
	case op == 0x02, op == 0x05, op == 0x08:
		return 2
	case op == 0x13, op == 0x15, op == 0x16, op == 0x19:
		return 2
	case op == 0x1a, op == 0x1c:
		return 2
	case op == 0x1f, op == 0x20:
		return 2
	case op == 0x22:
		return 2
	case op == 0x29:
		return 2
	case op >= 0x2d && op <= 0x37:
		return 2
	case op >= 0x38 && op <= 0x3d:
		return 2
	case op >= 0x44 && op <= 0x51:
		return 2
	case op >= 0x52 && op <= 0x6d:
		return 2
	case op >= 0x90 && op <= 0xaf:
		return 2
	case op >= 0xd0 && op <= 0xe2:
		return 2

	// 3 units
	case op == 0x03, op == 0x06, op == 0x09:
		return 3
	case op == 0x14, op == 0x17:
		return 3
	case op == 0x1b:
		return 3
	case op == 0x23, op == 0x24, op == 0x25, op == 0x26:
		return 3
	case op == 0x2a, op == 0x2b, op == 0x2c:
		return 3
	case op >= 0x6e && op <= 0x72:
		return 3
	case op >= 0x74 && op <= 0x78:
		return 3

	// 5 units
	case op == 0x18:
		return 5

	default:
		return 1
	}
}

// readULEB128 reads a ULEB128-encoded value from buf at pos.
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
