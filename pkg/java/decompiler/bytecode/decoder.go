package bytecode

import (
	"encoding/binary"
	"fmt"
)

// DecodeInstructions decodes all instructions from a bytecode byte array.
// The bytecode parameter should be the raw Code attribute bytecode.
func DecodeInstructions(bytecode []byte) ([]*Instruction, error) {
	var instrs []*Instruction

	pos := 0

	for pos < len(bytecode) {
		inst, err := decodeInstruction(bytecode, pos)
		if err != nil {
			return nil, fmt.Errorf("at offset %d: %w", pos, err)
		}

		instrs = append(instrs, inst)
		pos += inst.Length
	}

	return instrs, nil
}

func decodeInstruction(bytecode []byte, offset int) (*Instruction, error) {
	if offset >= len(bytecode) {
		return nil, fmt.Errorf("unexpected end of bytecode")
	}

	opByte := bytecode[offset]
	op := Opcode(opByte)

	switch op {
	case WIDE:
		return decodeWide(bytecode, offset)
	case TABLESWITCH:
		return decodeTableSwitchInstr(bytecode, offset)
	case LOOKUPSWITCH:
		return decodeLookupSwitchInstr(bytecode, offset)
	}

	info := opcodeTable[opByte]
	if info == nil {
		return nil, fmt.Errorf("unknown opcode 0x%02X", opByte)
	}

	operandSize := info.OperandSize
	totalLen := 1 + operandSize

	if offset+totalLen > len(bytecode) {
		return nil, fmt.Errorf("operands truncated for %s", info.Name)
	}

	var operand []byte
	if operandSize > 0 {
		operand = make([]byte, operandSize)
		copy(operand, bytecode[offset+1:offset+1+operandSize])
	}

	return &Instruction{
		Offset:  offset,
		Op:      op,
		Operand: operand,
		Length:  totalLen,
	}, nil
}

func decodeWide(bytecode []byte, offset int) (*Instruction, error) {
	if offset+2 > len(bytecode) {
		return nil, fmt.Errorf("wide: truncated")
	}

	subOp := Opcode(bytecode[offset+1])
	switch subOp {
	case IINC:
		// wide iinc: wide(1) + iinc(1) + index(2) + const(2) = 6 bytes
		if offset+6 > len(bytecode) {
			return nil, fmt.Errorf("wide iinc: truncated")
		}

		operand := make([]byte, 4)
		copy(operand, bytecode[offset+2:offset+6])

		return &Instruction{
			Offset:  offset,
			Op:      IINC,
			Operand: operand,
			Wide:    true,
			Length:  6,
		}, nil

	case ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
		ISTORE, LSTORE, FSTORE, DSTORE, ASTORE, RET:
		// wide load/store/ret: wide(1) + op(1) + index(2) = 4 bytes
		if offset+4 > len(bytecode) {
			return nil, fmt.Errorf("wide %s: truncated", subOp)
		}

		operand := make([]byte, 2)
		copy(operand, bytecode[offset+2:offset+4])

		return &Instruction{
			Offset:  offset,
			Op:      subOp,
			Operand: operand,
			Wide:    true,
			Length:  4,
		}, nil

	default:
		return nil, fmt.Errorf("wide: invalid sub-opcode 0x%02X", uint8(subOp))
	}
}

func decodeTableSwitchInstr(bytecode []byte, offset int) (*Instruction, error) {
	padStart := offset + 1
	padding := (4 - (padStart % 4)) % 4
	headerStart := 1 + padding

	if offset+headerStart+12 > len(bytecode) {
		return nil, fmt.Errorf("tableswitch: truncated header")
	}

	data := bytecode[offset:]
	low := int32(binary.BigEndian.Uint32(data[headerStart+4:]))
	high := int32(binary.BigEndian.Uint32(data[headerStart+8:]))

	count := int(high - low + 1)
	if count < 0 {
		return nil, fmt.Errorf("tableswitch: invalid range low=%d high=%d", low, high)
	}

	// SEC: cap before multiplication to prevent ~8 GiB make on crafted class files.
	const maxTableSwitchEntries = 1 << 20 // 1 M entries; real JVM methods never approach this
	if count > maxTableSwitchEntries {
		return nil, fmt.Errorf("tableswitch: unreasonable entry count %d (max %d)", count, maxTableSwitchEntries)
	}

	totalLen := headerStart + 12 + count*4
	if offset+totalLen > len(bytecode) {
		return nil, fmt.Errorf("tableswitch: truncated offsets")
	}

	operand := make([]byte, totalLen-1) // everything after the opcode byte
	copy(operand, bytecode[offset+1:offset+totalLen])

	return &Instruction{
		Offset:  offset,
		Op:      TABLESWITCH,
		Operand: operand,
		Length:  totalLen,
	}, nil
}

func decodeLookupSwitchInstr(bytecode []byte, offset int) (*Instruction, error) {
	padStart := offset + 1
	padding := (4 - (padStart % 4)) % 4
	headerStart := 1 + padding

	if offset+headerStart+8 > len(bytecode) {
		return nil, fmt.Errorf("lookupswitch: truncated header")
	}

	data := bytecode[offset:]

	npairs := int32(binary.BigEndian.Uint32(data[headerStart+4:]))
	if npairs < 0 {
		return nil, fmt.Errorf("lookupswitch: invalid npairs=%d", npairs)
	}

	// SEC: cap before multiplication to prevent ~17 GiB make on crafted class files.
	const maxLookupSwitchPairs = 1 << 20 // 1 M pairs; no real method ever has this many
	if npairs > maxLookupSwitchPairs {
		return nil, fmt.Errorf("lookupswitch: unreasonable npairs %d (max %d)", npairs, maxLookupSwitchPairs)
	}

	totalLen := headerStart + 8 + int(npairs)*8
	if offset+totalLen > len(bytecode) {
		return nil, fmt.Errorf("lookupswitch: truncated pairs")
	}

	operand := make([]byte, totalLen-1)
	copy(operand, bytecode[offset+1:offset+totalLen])

	return &Instruction{
		Offset:  offset,
		Op:      LOOKUPSWITCH,
		Operand: operand,
		Length:  totalLen,
	}, nil
}
