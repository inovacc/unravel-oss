package bytecode

import (
	"encoding/binary"
	"fmt"
)

// Instruction represents a single decoded JVM bytecode instruction.
type Instruction struct {
	Offset  int    // Byte offset in the Code attribute bytecode array
	Op      Opcode // The opcode
	Operand []byte // Raw operand bytes (nil for zero-operand instructions)
	Wide    bool   // True if this instruction was prefixed by wide
	Length  int    // Total instruction length in bytes (opcode + operands)
}

// LocalIndex returns the local variable index for load/store/iinc/ret instructions.
func (inst *Instruction) LocalIndex() uint16 {
	switch inst.Op {
	// Implicit index 0
	case ILOAD_0, LLOAD_0, FLOAD_0, DLOAD_0, ALOAD_0,
		ISTORE_0, LSTORE_0, FSTORE_0, DSTORE_0, ASTORE_0:
		return 0
	// Implicit index 1
	case ILOAD_1, LLOAD_1, FLOAD_1, DLOAD_1, ALOAD_1,
		ISTORE_1, LSTORE_1, FSTORE_1, DSTORE_1, ASTORE_1:
		return 1
	// Implicit index 2
	case ILOAD_2, LLOAD_2, FLOAD_2, DLOAD_2, ALOAD_2,
		ISTORE_2, LSTORE_2, FSTORE_2, DSTORE_2, ASTORE_2:
		return 2
	// Implicit index 3
	case ILOAD_3, LLOAD_3, FLOAD_3, DLOAD_3, ALOAD_3,
		ISTORE_3, LSTORE_3, FSTORE_3, DSTORE_3, ASTORE_3:
		return 3
	default:
		if inst.Wide && len(inst.Operand) >= 2 {
			return binary.BigEndian.Uint16(inst.Operand[:2])
		}

		if len(inst.Operand) >= 1 {
			return uint16(inst.Operand[0])
		}

		return 0
	}
}

// BranchOffset returns the branch offset for conditional/unconditional jump instructions.
func (inst *Instruction) BranchOffset() int32 {
	switch inst.Op {
	case GOTO_W, JSR_W:
		if len(inst.Operand) >= 4 {
			return int32(binary.BigEndian.Uint32(inst.Operand[:4]))
		}
	default:
		if len(inst.Operand) >= 2 {
			return int32(int16(binary.BigEndian.Uint16(inst.Operand[:2])))
		}
	}

	return 0
}

// BranchTarget returns the absolute bytecode target address.
func (inst *Instruction) BranchTarget() int {
	return inst.Offset + int(inst.BranchOffset())
}

// CPIndex returns the constant pool index for instructions that reference the constant pool.
func (inst *Instruction) CPIndex() uint16 {
	switch inst.Op {
	case LDC:
		if len(inst.Operand) >= 1 {
			return uint16(inst.Operand[0])
		}
	default:
		if len(inst.Operand) >= 2 {
			return binary.BigEndian.Uint16(inst.Operand[:2])
		}
	}

	return 0
}

// ImmediateByte returns the signed byte immediate for bipush.
func (inst *Instruction) ImmediateByte() int8 {
	if len(inst.Operand) >= 1 {
		return int8(inst.Operand[0])
	}

	return 0
}

// ImmediateShort returns the signed short immediate for sipush.
func (inst *Instruction) ImmediateShort() int16 {
	if len(inst.Operand) >= 2 {
		return int16(binary.BigEndian.Uint16(inst.Operand[:2]))
	}

	return 0
}

// IIncValue returns the increment value for iinc instructions.
func (inst *Instruction) IIncValue() int16 {
	if inst.Wide && len(inst.Operand) >= 4 {
		return int16(binary.BigEndian.Uint16(inst.Operand[2:4]))
	}

	if len(inst.Operand) >= 2 {
		return int16(int8(inst.Operand[1]))
	}

	return 0
}

// NewArrayElementType returns the element type for newarray instructions.
func (inst *Instruction) NewArrayElementType() NewArrayType {
	if len(inst.Operand) >= 1 {
		return NewArrayType(inst.Operand[0])
	}

	return 0
}

// MultiANewArrayDimensions returns the number of dimensions for multianewarray.
func (inst *Instruction) MultiANewArrayDimensions() uint8 {
	if len(inst.Operand) >= 3 {
		return inst.Operand[2]
	}

	return 0
}

// SwitchEntry represents a single case in a tableswitch or lookupswitch.
type SwitchEntry struct {
	Values []int32 // Case values (nil entry = default)
	Target int     // Absolute bytecode target
}

// TableSwitchInfo holds decoded tableswitch data.
type TableSwitchInfo struct {
	Default int           // Absolute target for default case
	Low     int32         // Lowest case value
	High    int32         // Highest case value
	Targets []int         // Absolute targets for each case (index = value - low)
	Entries []SwitchEntry // Merged entries with values grouped by target
}

// LookupSwitchInfo holds decoded lookupswitch data.
type LookupSwitchInfo struct {
	Default int           // Absolute target for default case
	Pairs   []LookupPair  // match-offset pairs
	Entries []SwitchEntry // Merged entries with values grouped by target
}

// LookupPair is a match value + target pair in a lookupswitch.
type LookupPair struct {
	Match  int32
	Target int
}

// DecodeTableSwitch decodes a tableswitch instruction from raw bytecode.
func DecodeTableSwitch(bytecode []byte, instrOffset int) (*TableSwitchInfo, error) {
	// Padding: skip to next 4-byte aligned offset after the opcode byte
	padStart := instrOffset + 1
	padding := (4 - (padStart % 4)) % 4
	pos := padStart + padding - instrOffset // relative to instruction start

	if pos+12 > len(bytecode) {
		return nil, fmt.Errorf("tableswitch: truncated at offset %d", instrOffset)
	}

	// Read using big-endian from the raw data relative to instruction start
	// But we receive just the operand bytes, so we need the raw data starting from operand
	// Actually let's use the full bytecode slice starting at instrOffset
	data := bytecode[instrOffset:]
	off := 1 + padding // skip opcode + padding

	if off+12 > len(data) {
		return nil, fmt.Errorf("tableswitch: truncated header at offset %d", instrOffset)
	}

	defaultOff := int32(binary.BigEndian.Uint32(data[off:]))
	low := int32(binary.BigEndian.Uint32(data[off+4:]))
	high := int32(binary.BigEndian.Uint32(data[off+8:]))
	off += 12

	count := int(high - low + 1)
	if count < 0 || off+count*4 > len(data) {
		return nil, fmt.Errorf("tableswitch: invalid range low=%d high=%d at offset %d", low, high, instrOffset)
	}

	info := &TableSwitchInfo{
		Default: instrOffset + int(defaultOff),
		Low:     low,
		High:    high,
		Targets: make([]int, count),
	}

	targetMap := map[int][]int32{}

	for i := range count {
		target := int32(binary.BigEndian.Uint32(data[off:]))
		off += 4
		absTarget := instrOffset + int(target)
		info.Targets[i] = absTarget

		val := low + int32(i)
		if absTarget != info.Default {
			targetMap[absTarget] = append(targetMap[absTarget], val)
		}
	}

	// Default entry
	info.Entries = append(info.Entries, SwitchEntry{Values: nil, Target: info.Default})
	for target, vals := range targetMap {
		info.Entries = append(info.Entries, SwitchEntry{Values: vals, Target: target})
	}

	return info, nil
}

// DecodeLookupSwitch decodes a lookupswitch instruction from raw bytecode.
func DecodeLookupSwitch(bytecode []byte, instrOffset int) (*LookupSwitchInfo, error) {
	padStart := instrOffset + 1
	padding := (4 - (padStart % 4)) % 4

	data := bytecode[instrOffset:]
	off := 1 + padding

	if off+8 > len(data) {
		return nil, fmt.Errorf("lookupswitch: truncated header at offset %d", instrOffset)
	}

	defaultOff := int32(binary.BigEndian.Uint32(data[off:]))
	npairs := int32(binary.BigEndian.Uint32(data[off+4:]))
	off += 8

	if npairs < 0 || off+int(npairs)*8 > len(data) {
		return nil, fmt.Errorf("lookupswitch: invalid npairs=%d at offset %d", npairs, instrOffset)
	}

	info := &LookupSwitchInfo{
		Default: instrOffset + int(defaultOff),
		Pairs:   make([]LookupPair, npairs),
	}

	targetMap := map[int][]int32{}

	for i := range npairs {
		match := int32(binary.BigEndian.Uint32(data[off:]))
		target := int32(binary.BigEndian.Uint32(data[off+4:]))
		off += 8
		absTarget := instrOffset + int(target)

		info.Pairs[i] = LookupPair{Match: match, Target: absTarget}
		if absTarget != info.Default {
			targetMap[absTarget] = append(targetMap[absTarget], match)
		}
	}

	info.Entries = append(info.Entries, SwitchEntry{Values: nil, Target: info.Default})
	for target, vals := range targetMap {
		info.Entries = append(info.Entries, SwitchEntry{Values: vals, Target: target})
	}

	return info, nil
}

// TableSwitchLength returns the total byte length of a tableswitch instruction.
func TableSwitchLength(instrOffset int) (int, error) {
	padStart := instrOffset + 1
	padding := (4 - (padStart % 4)) % 4
	// 1 (opcode) + padding + 4 (default) + 4 (low) + 4 (high) + 4*(high-low+1) offsets
	// We need the actual bytecode to read low/high, so this version just returns the header size.
	// The full calculation needs data; see DecodeInstructions for the actual usage.
	return 1 + padding + 12, nil // minimum; caller must add 4*(high-low+1)
}

// DecodeTableSwitchInstr decodes tableswitch data from an already-decoded instruction.
// The instruction's Offset is used for padding calculation and target resolution.
func DecodeTableSwitchInstr(inst *Instruction) (*TableSwitchInfo, error) {
	if inst.Op != TABLESWITCH {
		return nil, fmt.Errorf("not a tableswitch instruction")
	}
	// Padding in operand: the operand starts at offset+1, so padding aligns
	// to the next 4-byte boundary from (offset+1).
	padStart := inst.Offset + 1
	padding := (4 - (padStart % 4)) % 4

	operand := inst.Operand
	if padding+12 > len(operand) {
		return nil, fmt.Errorf("tableswitch: truncated header")
	}

	defaultOff := int32(binary.BigEndian.Uint32(operand[padding:]))
	low := int32(binary.BigEndian.Uint32(operand[padding+4:]))
	high := int32(binary.BigEndian.Uint32(operand[padding+8:]))
	pos := padding + 12

	count := int(high - low + 1)
	if count < 0 || pos+count*4 > len(operand) {
		return nil, fmt.Errorf("tableswitch: invalid range low=%d high=%d", low, high)
	}

	info := &TableSwitchInfo{
		Default: inst.Offset + int(defaultOff),
		Low:     low,
		High:    high,
		Targets: make([]int, count),
	}

	targetMap := map[int][]int32{}

	for i := range count {
		target := int32(binary.BigEndian.Uint32(operand[pos:]))
		pos += 4
		absTarget := inst.Offset + int(target)
		info.Targets[i] = absTarget

		val := low + int32(i)
		if absTarget != info.Default {
			targetMap[absTarget] = append(targetMap[absTarget], val)
		}
	}

	info.Entries = append(info.Entries, SwitchEntry{Values: nil, Target: info.Default})
	for target, vals := range targetMap {
		info.Entries = append(info.Entries, SwitchEntry{Values: vals, Target: target})
	}

	return info, nil
}

// DecodeLookupSwitchInstr decodes lookupswitch data from an already-decoded instruction.
func DecodeLookupSwitchInstr(inst *Instruction) (*LookupSwitchInfo, error) {
	if inst.Op != LOOKUPSWITCH {
		return nil, fmt.Errorf("not a lookupswitch instruction")
	}

	padStart := inst.Offset + 1
	padding := (4 - (padStart % 4)) % 4

	operand := inst.Operand
	if padding+8 > len(operand) {
		return nil, fmt.Errorf("lookupswitch: truncated header")
	}

	defaultOff := int32(binary.BigEndian.Uint32(operand[padding:]))
	npairs := int32(binary.BigEndian.Uint32(operand[padding+4:]))
	pos := padding + 8

	if npairs < 0 || pos+int(npairs)*8 > len(operand) {
		return nil, fmt.Errorf("lookupswitch: invalid npairs=%d", npairs)
	}

	info := &LookupSwitchInfo{
		Default: inst.Offset + int(defaultOff),
		Pairs:   make([]LookupPair, npairs),
	}

	targetMap := map[int][]int32{}

	for i := range npairs {
		match := int32(binary.BigEndian.Uint32(operand[pos:]))
		target := int32(binary.BigEndian.Uint32(operand[pos+4:]))
		pos += 8
		absTarget := inst.Offset + int(target)

		info.Pairs[i] = LookupPair{Match: match, Target: absTarget}
		if absTarget != info.Default {
			targetMap[absTarget] = append(targetMap[absTarget], match)
		}
	}

	info.Entries = append(info.Entries, SwitchEntry{Values: nil, Target: info.Default})
	for target, vals := range targetMap {
		info.Entries = append(info.Entries, SwitchEntry{Values: vals, Target: target})
	}

	return info, nil
}

func (inst *Instruction) String() string {
	info := opcodeTable[inst.Op]

	name := "?"
	if info != nil {
		name = info.Name
	} else if inst.Op >= 0x100 {
		if si, ok := syntheticOpcodeTable[inst.Op]; ok {
			name = si.Name
		}
	}

	if inst.Wide {
		name = "wide " + name
	}

	return fmt.Sprintf("%4d: %s", inst.Offset, name)
}
