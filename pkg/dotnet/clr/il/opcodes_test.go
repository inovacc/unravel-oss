/*
Copyright (c) 2026 Security Research
*/
package il

import "testing"

// TestOpcodeOneWidth asserts every opcode maps to exactly one operand class —
// a transcription error (two rows for one byte, or a phantom operand class)
// fails CI. This is the canary the spec mandates (Must-fix #5).
func TestOpcodeOneWidth(t *testing.T) {
	seenSingle := map[byte]Opcode{}
	seenPrefixed := map[byte]Opcode{}
	for _, op := range opcodeTable {
		if op.Name == "" {
			continue
		}
		var bucket map[byte]Opcode
		if op.Prefixed {
			bucket = seenPrefixed
		} else {
			bucket = seenSingle
		}
		if prev, dup := bucket[op.Code]; dup {
			t.Fatalf("duplicate opcode byte prefixed=%v %#x: %q and %q", op.Prefixed, op.Code, prev.Name, op.Name)
		}
		bucket[op.Code] = op
		if op.Operand < InlineNone || op.Operand > InlineSig {
			t.Fatalf("opcode %q has out-of-range operand class %d (phantom?)", op.Name, op.Operand)
		}
	}
}

func TestOpcodeKnownEntries(t *testing.T) {
	cases := []struct {
		prefixed bool
		code     byte
		name     string
		operand  OperandClass
	}{
		{false, 0x00, "nop", InlineNone},
		{false, 0x2A, "ret", InlineNone},
		{false, 0x28, "call", InlineMethod},
		{false, 0x6F, "callvirt", InlineMethod},
		{false, 0x72, "ldstr", InlineString},
		{false, 0x73, "newobj", InlineMethod},
		{false, 0x7B, "ldfld", InlineField},
		{false, 0x45, "switch", InlineSwitch},
		{false, 0x20, "ldc.i4", InlineI},
		{false, 0x21, "ldc.i8", InlineI8},
		{false, 0x2B, "br.s", ShortInlineBrTarget},
		{true, 0x06, "ldftn", InlineMethod},
	}
	for _, c := range cases {
		got, ok := lookupOpcode(c.prefixed, c.code)
		if !ok {
			t.Fatalf("opcode prefixed=%v %#x not found", c.prefixed, c.code)
		}
		if got.Name != c.name || got.Operand != c.operand {
			t.Errorf("opcode %#x = (%q,%d), want (%q,%d)", c.code, got.Name, got.Operand, c.name, c.operand)
		}
	}
}
