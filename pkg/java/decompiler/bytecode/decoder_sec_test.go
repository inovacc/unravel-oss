package bytecode

import (
	"testing"
)

// makeTableswitchBytecode builds a TABLESWITCH instruction with the given low/high values.
// Alignment padding is computed for offset 0.
func makeTableswitchBytecode(low, high int32) []byte {
	// opcode at offset 0; padding to align to 4 bytes: (4 - (1%4))%4 = 3 bytes
	padding := (4 - (1 % 4)) % 4
	headerStart := 1 + padding
	hdr := make([]byte, headerStart+12)
	hdr[0] = byte(TABLESWITCH)
	// default offset (4 bytes at headerStart)
	putInt32BE(hdr[headerStart:], 0)
	// low
	putInt32BE(hdr[headerStart+4:], low)
	// high
	putInt32BE(hdr[headerStart+8:], high)
	return hdr
}

func makeLookupSwitchBytecode(npairs int32) []byte {
	padding := (4 - (1 % 4)) % 4
	headerStart := 1 + padding
	hdr := make([]byte, headerStart+8)
	hdr[0] = byte(LOOKUPSWITCH)
	// default offset
	putInt32BE(hdr[headerStart:], 0)
	// npairs
	putInt32BE(hdr[headerStart+4:], npairs)
	return hdr
}

func putInt32BE(b []byte, v int32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// TestTableSwitch_UnreasonableCount verifies the cap rejects a bomb-sized entry count.
func TestTableSwitch_UnreasonableCount(t *testing.T) {
	// low=0x80000001, high=0x7FFFFFFF → count = 2^31-1 ≈ 2.1 billion
	bc := makeTableswitchBytecode(int32(-2147483647), int32(0x7FFFFFFF))
	_, err := decodeTableSwitchInstr(bc, 0)
	if err == nil {
		t.Fatal("expected error for huge tableswitch count, got nil")
	}
}

// TestTableSwitch_ReasonableCount verifies a small legitimate table switch still works.
func TestTableSwitch_ReasonableCount(t *testing.T) {
	// low=0, high=2 → count=3; provide 3 offset slots (4 bytes each) + header
	padding := (4 - (1 % 4)) % 4
	headerStart := 1 + padding
	count := 3
	totalLen := headerStart + 12 + count*4
	bc := make([]byte, totalLen)
	bc[0] = byte(TABLESWITCH)
	putInt32BE(bc[headerStart:], 0)   // default
	putInt32BE(bc[headerStart+4:], 0) // low=0
	putInt32BE(bc[headerStart+8:], 2) // high=2
	// 3 offsets already zeroed
	instr, err := decodeTableSwitchInstr(bc, 0)
	if err != nil {
		t.Fatalf("unexpected error for small tableswitch: %v", err)
	}
	if instr.Length != totalLen {
		t.Errorf("unexpected length: got %d want %d", instr.Length, totalLen)
	}
}

// TestLookupSwitch_UnreasonableNPairs verifies the cap rejects a bomb-sized npairs.
func TestLookupSwitch_UnreasonableNPairs(t *testing.T) {
	bc := makeLookupSwitchBytecode(0x7FFFFFFF)
	_, err := decodeLookupSwitchInstr(bc, 0)
	if err == nil {
		t.Fatal("expected error for huge lookupswitch npairs, got nil")
	}
}

// TestLookupSwitch_ReasonableNPairs verifies a legitimate lookupswitch still works.
func TestLookupSwitch_ReasonableNPairs(t *testing.T) {
	padding := (4 - (1 % 4)) % 4
	headerStart := 1 + padding
	npairs := int32(2)
	totalLen := headerStart + 8 + int(npairs)*8
	bc := make([]byte, totalLen)
	bc[0] = byte(LOOKUPSWITCH)
	putInt32BE(bc[headerStart:], 0)        // default
	putInt32BE(bc[headerStart+4:], npairs) // npairs=2
	// 2 match/offset pairs already zeroed
	instr, err := decodeLookupSwitchInstr(bc, 0)
	if err != nil {
		t.Fatalf("unexpected error for small lookupswitch: %v", err)
	}
	if instr.Length != totalLen {
		t.Errorf("unexpected length: got %d want %d", instr.Length, totalLen)
	}
}
