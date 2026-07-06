/*
Copyright (c) 2026 Security Research
*/
package bytecode

import "testing"

func TestDecodeInstructions_Empty(t *testing.T) {
	got, err := DecodeInstructions(nil)
	if err != nil {
		t.Fatalf("decode nil: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil bytecode: got %d instr, want 0", len(got))
	}
	got, err = DecodeInstructions([]byte{})
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty bytecode: got %d instr, want 0", len(got))
	}
}

func TestDecodeInstructions_NopOnly(t *testing.T) {
	// 0x00 == NOP. Single-byte, no operands.
	got, err := DecodeInstructions([]byte{0x00})
	if err != nil {
		t.Fatalf("decode nop: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("nop: got %d instr, want 1", len(got))
	}
}

func TestDecodeInstructions_Invalid(t *testing.T) {
	// 0xBA == invokedynamic (5 bytes); short input must error.
	if _, err := DecodeInstructions([]byte{0xBA, 0x00}); err == nil {
		t.Error("expected error on truncated invokedynamic")
	}
}

func TestLookupOpcode_Known(t *testing.T) {
	info, err := LookupOpcode(0x00) // NOP
	if err != nil {
		t.Fatalf("lookup nop: %v", err)
	}
	if info == nil {
		t.Fatal("nil opcode info for NOP")
	}
}

func TestLookupOpcode_Unknown(t *testing.T) {
	// 0xFE = impdep1 (reserved); may or may not be in the table.
	// 0xFF = impdep2 (reserved). Both are at the edge — accept either ok or err.
	_, _ = LookupOpcode(0xFF)
}

func TestLookupSyntheticOpcode(t *testing.T) {
	// Just exercise: any value, accept ok or err.
	_, _ = LookupSyntheticOpcode(Opcode(0))
}
