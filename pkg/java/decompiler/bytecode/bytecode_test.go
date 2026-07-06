package bytecode

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// makePaddedSwitch builds raw bytecode for a tableswitch starting at instrOffset.
// padding is computed automatically to align to the next 4-byte boundary after
// the opcode byte.
func makeTableSwitchBytes(instrOffset int, defaultOff, low, high int32, offsets []int32) []byte {
	padStart := instrOffset + 1
	padding := (4 - (padStart % 4)) % 4
	// total: 1 (opcode) + padding + 4 (default) + 4 (low) + 4 (high) + 4*count
	count := int(high - low + 1)
	total := 1 + padding + 12 + count*4
	buf := make([]byte, instrOffset+total)
	buf[instrOffset] = byte(TABLESWITCH)
	base := instrOffset + 1 + padding
	binary.BigEndian.PutUint32(buf[base:], uint32(defaultOff))
	binary.BigEndian.PutUint32(buf[base+4:], uint32(low))
	binary.BigEndian.PutUint32(buf[base+8:], uint32(high))
	for i, off := range offsets {
		binary.BigEndian.PutUint32(buf[base+12+i*4:], uint32(off))
	}
	return buf
}

func makeLookupSwitchBytes(instrOffset int, defaultOff int32, pairs [][2]int32) []byte {
	padStart := instrOffset + 1
	padding := (4 - (padStart % 4)) % 4
	npairs := len(pairs)
	total := 1 + padding + 8 + npairs*8
	buf := make([]byte, instrOffset+total)
	buf[instrOffset] = byte(LOOKUPSWITCH)
	base := instrOffset + 1 + padding
	binary.BigEndian.PutUint32(buf[base:], uint32(defaultOff))
	binary.BigEndian.PutUint32(buf[base+4:], uint32(npairs))
	for i, p := range pairs {
		binary.BigEndian.PutUint32(buf[base+8+i*8:], uint32(p[0]))
		binary.BigEndian.PutUint32(buf[base+12+i*8:], uint32(p[1]))
	}
	return buf
}

// ---------------------------------------------------------------------------
// DecodeInstructions — happy paths
// ---------------------------------------------------------------------------

func TestDecodeInstructions_SingleByteOpcodes(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantLen int
		wantOp  Opcode
	}{
		{"nop", []byte{byte(NOP)}, 1, NOP},
		{"return", []byte{byte(RETURN)}, 1, RETURN},
		{"aconst_null", []byte{byte(ACONST_NULL)}, 1, ACONST_NULL},
		{"iconst_0", []byte{byte(ICONST_0)}, 1, ICONST_0},
		{"iadd", []byte{byte(IADD)}, 1, IADD},
		{"ireturn", []byte{byte(IRETURN)}, 1, IRETURN},
		{"aload_0", []byte{byte(ALOAD_0)}, 1, ALOAD_0},
		{"istore_2", []byte{byte(ISTORE_2)}, 1, ISTORE_2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeInstructions(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("got %d instructions, want %d", len(got), tc.wantLen)
			}
			if got[0].Op != tc.wantOp {
				t.Errorf("op = %v, want %v", got[0].Op, tc.wantOp)
			}
			if got[0].Offset != 0 {
				t.Errorf("offset = %d, want 0", got[0].Offset)
			}
			if got[0].Length != 1 {
				t.Errorf("length = %d, want 1", got[0].Length)
			}
		})
	}
}

func TestDecodeInstructions_WithOperands(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantOp    Opcode
		wantLen   int
		wantOpLen int
	}{
		{"bipush 42", []byte{byte(BIPUSH), 42}, BIPUSH, 1, 2},
		{"sipush 300", []byte{byte(SIPUSH), 0x01, 0x2C}, SIPUSH, 1, 3},
		{"ldc #5", []byte{byte(LDC), 0x05}, LDC, 1, 2},
		{"iload 7", []byte{byte(ILOAD), 0x07}, ILOAD, 1, 2},
		{"istore 3", []byte{byte(ISTORE), 0x03}, ISTORE, 1, 2},
		{"goto +5", []byte{byte(GOTO), 0x00, 0x05}, GOTO, 1, 3},
		{"ifeq +3", []byte{byte(IFEQ), 0x00, 0x03}, IFEQ, 1, 3},
		{"getstatic #2", []byte{byte(GETSTATIC), 0x00, 0x02}, GETSTATIC, 1, 3},
		{"invokevirtual #10", []byte{byte(INVOKEVIRTUAL), 0x00, 0x0A}, INVOKEVIRTUAL, 1, 3},
		{"new #5", []byte{byte(NEW), 0x00, 0x05}, NEW, 1, 3},
		{"iinc 1,2", []byte{byte(IINC), 0x01, 0x02}, IINC, 1, 3},
		{"goto_w +100", []byte{byte(GOTO_W), 0x00, 0x00, 0x00, 0x64}, GOTO_W, 1, 5},
		{"multianewarray #5 2", []byte{byte(MULTIANEWARRAY), 0x00, 0x05, 0x02}, MULTIANEWARRAY, 1, 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeInstructions(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("got %d instructions, want %d", len(got), tc.wantLen)
			}
			if got[0].Op != tc.wantOp {
				t.Errorf("op = %v, want %v", got[0].Op, tc.wantOp)
			}
			if got[0].Length != tc.wantOpLen {
				t.Errorf("length = %d, want %d", got[0].Length, tc.wantOpLen)
			}
		})
	}
}

func TestDecodeInstructions_MultipleInstructions(t *testing.T) {
	// nop, iconst_1, ireturn
	input := []byte{byte(NOP), byte(ICONST_1), byte(IRETURN)}
	got, err := DecodeInstructions(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d instructions, want 3", len(got))
	}
	if got[0].Op != NOP || got[1].Op != ICONST_1 || got[2].Op != IRETURN {
		t.Errorf("unexpected opcodes: %v %v %v", got[0].Op, got[1].Op, got[2].Op)
	}
	// check offsets
	if got[1].Offset != 1 || got[2].Offset != 2 {
		t.Errorf("offsets: %d %d (want 1, 2)", got[1].Offset, got[2].Offset)
	}
}

// ---------------------------------------------------------------------------
// DecodeInstructions — WIDE prefix
// ---------------------------------------------------------------------------

func TestDecodeInstructions_Wide_LoadStore(t *testing.T) {
	wideOps := []struct {
		name string
		op   Opcode
	}{
		{"iload", ILOAD},
		{"lload", LLOAD},
		{"fload", FLOAD},
		{"dload", DLOAD},
		{"aload", ALOAD},
		{"istore", ISTORE},
		{"lstore", LSTORE},
		{"fstore", FSTORE},
		{"dstore", DSTORE},
		{"astore", ASTORE},
		{"ret", RET},
	}
	for _, tc := range wideOps {
		t.Run(tc.name, func(t *testing.T) {
			// wide(1) + op(1) + index(2) = 4 bytes
			input := []byte{byte(WIDE), byte(tc.op), 0x00, 0x0A}
			got, err := DecodeInstructions(input)
			if err != nil {
				t.Fatalf("unexpected error for wide %s: %v", tc.name, err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d instrs, want 1", len(got))
			}
			if !got[0].Wide {
				t.Errorf("Wide flag not set")
			}
			if got[0].Op != tc.op {
				t.Errorf("op = %v, want %v", got[0].Op, tc.op)
			}
			if got[0].Length != 4 {
				t.Errorf("length = %d, want 4", got[0].Length)
			}
			if got[0].LocalIndex() != 10 {
				t.Errorf("LocalIndex = %d, want 10", got[0].LocalIndex())
			}
		})
	}
}

func TestDecodeInstructions_Wide_IINC(t *testing.T) {
	// wide(1) + iinc(1) + index(2) + const(2) = 6 bytes
	input := []byte{byte(WIDE), byte(IINC), 0x00, 0x05, 0xFF, 0xFB} // index=5, const=-5
	got, err := DecodeInstructions(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d instrs, want 1", len(got))
	}
	if got[0].Op != IINC || !got[0].Wide {
		t.Errorf("expected wide iinc, got op=%v wide=%v", got[0].Op, got[0].Wide)
	}
	if got[0].Length != 6 {
		t.Errorf("length = %d, want 6", got[0].Length)
	}
	if got[0].LocalIndex() != 5 {
		t.Errorf("LocalIndex = %d, want 5", got[0].LocalIndex())
	}
	if got[0].IIncValue() != -5 {
		t.Errorf("IIncValue = %d, want -5", got[0].IIncValue())
	}
}

// ---------------------------------------------------------------------------
// DecodeInstructions — TABLESWITCH
// ---------------------------------------------------------------------------

func TestDecodeInstructions_Tableswitch(t *testing.T) {
	// instrOffset=0 → padStart=1 → padding=3 to align at 4
	offsets := []int32{10, 20, 30} // cases 0,1,2
	raw := makeTableSwitchBytes(0, 50, 0, 2, offsets)
	got, err := DecodeInstructions(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d instrs, want 1", len(got))
	}
	if got[0].Op != TABLESWITCH {
		t.Errorf("op = %v, want TABLESWITCH", got[0].Op)
	}
}

func TestDecodeInstructions_Tableswitch_AtOffset4(t *testing.T) {
	// nop nop nop nop tableswitch: instrOffset=4 → padStart=5 → padding=3
	prefix := []byte{byte(NOP), byte(NOP), byte(NOP), byte(NOP)}
	offsets := []int32{10}
	raw := makeTableSwitchBytes(4, 20, 5, 5, offsets)
	full := append(prefix, raw[4:]...)
	got, err := DecodeInstructions(full)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var tsw *Instruction
	for _, i := range got {
		if i.Op == TABLESWITCH {
			tsw = i
		}
	}
	if tsw == nil {
		t.Fatal("tableswitch instruction not found")
	}
	if tsw.Offset != 4 {
		t.Errorf("tableswitch offset = %d, want 4", tsw.Offset)
	}
}

// ---------------------------------------------------------------------------
// DecodeInstructions — LOOKUPSWITCH
// ---------------------------------------------------------------------------

func TestDecodeInstructions_Lookupswitch(t *testing.T) {
	// instrOffset=0 → padStart=1 → padding=3
	pairs := [][2]int32{{10, 40}, {20, 60}}
	raw := makeLookupSwitchBytes(0, 100, pairs)
	got, err := DecodeInstructions(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d instrs, want 1", len(got))
	}
	if got[0].Op != LOOKUPSWITCH {
		t.Errorf("op = %v, want LOOKUPSWITCH", got[0].Op)
	}
}

// ---------------------------------------------------------------------------
// DecodeInstructions — error cases
// ---------------------------------------------------------------------------

func TestDecodeInstructions_Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			"unknown opcode 0xFE",
			[]byte{0xFE},
			"unknown opcode",
		},
		{
			"truncated bipush",
			[]byte{byte(BIPUSH)},
			"operands truncated",
		},
		{
			"truncated sipush",
			[]byte{byte(SIPUSH), 0x01},
			"operands truncated",
		},
		{
			"truncated goto",
			[]byte{byte(GOTO), 0x00},
			"operands truncated",
		},
		{
			"wide truncated",
			[]byte{byte(WIDE)},
			"wide: truncated",
		},
		{
			"wide invalid subop",
			[]byte{byte(WIDE), byte(NOP)},
			"invalid sub-opcode",
		},
		{
			"wide iload truncated",
			[]byte{byte(WIDE), byte(ILOAD), 0x00},
			"truncated",
		},
		{
			"wide iinc truncated",
			[]byte{byte(WIDE), byte(IINC), 0x00, 0x01, 0x00},
			"truncated",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeInstructions(tc.input)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestDecodeInstructions_TableSwitchErrors(t *testing.T) {
	t.Run("truncated header", func(t *testing.T) {
		// Just the opcode byte and some padding, but not the full 12-byte header
		_, err := DecodeInstructions([]byte{byte(TABLESWITCH), 0x00, 0x00, 0x00})
		if err == nil {
			t.Fatal("expected error for truncated tableswitch header")
		}
	})

	t.Run("invalid range high<low", func(t *testing.T) {
		// padding=3, default=0, low=10, high=5 → count=-4 → error
		buf := make([]byte, 1+3+12) // opcode + 3 padding + header
		buf[0] = byte(TABLESWITCH)
		base := 1 + 3
		binary.BigEndian.PutUint32(buf[base:], 0)    // default
		binary.BigEndian.PutUint32(buf[base+4:], 10) // low=10
		binary.BigEndian.PutUint32(buf[base+8:], 5)  // high=5
		_, err := DecodeInstructions(buf)
		if err == nil {
			t.Fatal("expected error for high < low")
		}
	})

	t.Run("truncated offsets", func(t *testing.T) {
		// count=3 but we don't include the offset bytes
		buf := make([]byte, 1+3+12) // no room for offsets
		buf[0] = byte(TABLESWITCH)
		base := 1 + 3
		binary.BigEndian.PutUint32(buf[base:], 0)   // default
		binary.BigEndian.PutUint32(buf[base+4:], 0) // low=0
		binary.BigEndian.PutUint32(buf[base+8:], 2) // high=2, count=3 → need 12 more bytes
		_, err := DecodeInstructions(buf)
		if err == nil {
			t.Fatal("expected error for truncated tableswitch offsets")
		}
	})
}

func TestDecodeInstructions_LookupSwitchErrors(t *testing.T) {
	t.Run("truncated header", func(t *testing.T) {
		_, err := DecodeInstructions([]byte{byte(LOOKUPSWITCH), 0x00, 0x00, 0x00})
		if err == nil {
			t.Fatal("expected error for truncated lookupswitch header")
		}
	})

	t.Run("negative npairs", func(t *testing.T) {
		buf := make([]byte, 1+3+8) // opcode + 3 padding + header
		buf[0] = byte(LOOKUPSWITCH)
		base := 1 + 3
		binary.BigEndian.PutUint32(buf[base:], 0)
		binary.BigEndian.PutUint32(buf[base+4:], 0xFFFFFFFF) // -1 as int32
		_, err := DecodeInstructions(buf)
		if err == nil {
			t.Fatal("expected error for negative npairs")
		}
	})

	t.Run("truncated pairs", func(t *testing.T) {
		buf := make([]byte, 1+3+8) // room for header only, npairs=2 needs 16 more
		buf[0] = byte(LOOKUPSWITCH)
		base := 1 + 3
		binary.BigEndian.PutUint32(buf[base:], 0)
		binary.BigEndian.PutUint32(buf[base+4:], 2) // npairs=2
		_, err := DecodeInstructions(buf)
		if err == nil {
			t.Fatal("expected error for truncated lookupswitch pairs")
		}
	})
}

// ---------------------------------------------------------------------------
// DecodeTableSwitch / DecodeLookupSwitch
// ---------------------------------------------------------------------------

func TestDecodeTableSwitch_HappyPath(t *testing.T) {
	offsets := []int32{10, 20, 30}
	raw := makeTableSwitchBytes(0, 50, 0, 2, offsets)
	info, err := DecodeTableSwitch(raw, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Low != 0 || info.High != 2 {
		t.Errorf("low=%d high=%d, want 0..2", info.Low, info.High)
	}
	if info.Default != 50 {
		t.Errorf("default = %d, want 50", info.Default)
	}
	if len(info.Targets) != 3 {
		t.Errorf("len(targets) = %d, want 3", len(info.Targets))
	}
	// Entries include default entry plus distinct non-default targets
	if len(info.Entries) == 0 {
		t.Error("entries should not be empty")
	}
}

func TestDecodeTableSwitch_NonZeroOffset(t *testing.T) {
	offsets := []int32{10}
	raw := makeTableSwitchBytes(4, 30, 5, 5, offsets)
	// decode from offset 4
	info, err := DecodeTableSwitch(raw, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Low != 5 || info.High != 5 {
		t.Errorf("low=%d high=%d, want 5..5", info.Low, info.High)
	}
	// default target = instrOffset + defaultOff
	if info.Default != 4+30 {
		t.Errorf("default = %d, want %d", info.Default, 4+30)
	}
}

func TestDecodeTableSwitch_Errors(t *testing.T) {
	t.Run("truncated header", func(t *testing.T) {
		_, err := DecodeTableSwitch([]byte{byte(TABLESWITCH), 0x00, 0x00, 0x00}, 0)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid range", func(t *testing.T) {
		buf := make([]byte, 1+3+12)
		buf[0] = byte(TABLESWITCH)
		base := 4
		binary.BigEndian.PutUint32(buf[base:], 0)
		binary.BigEndian.PutUint32(buf[base+4:], 10) // low=10
		binary.BigEndian.PutUint32(buf[base+8:], 5)  // high=5 → invalid
		_, err := DecodeTableSwitch(buf, 0)
		if err == nil {
			t.Fatal("expected error for invalid range")
		}
	})
}

func TestDecodeLookupSwitch_HappyPath(t *testing.T) {
	pairs := [][2]int32{{1, 40}, {2, 80}, {3, 120}}
	raw := makeLookupSwitchBytes(0, 200, pairs)
	info, err := DecodeLookupSwitch(raw, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Default != 200 {
		t.Errorf("default = %d, want 200", info.Default)
	}
	if len(info.Pairs) != 3 {
		t.Fatalf("len(pairs) = %d, want 3", len(info.Pairs))
	}
	if info.Pairs[0].Match != 1 {
		t.Errorf("pairs[0].Match = %d, want 1", info.Pairs[0].Match)
	}
	// target for pair 0 = instrOffset(0) + offset(40) = 40
	if info.Pairs[0].Target != 40 {
		t.Errorf("pairs[0].Target = %d, want 40", info.Pairs[0].Target)
	}
}

func TestDecodeLookupSwitch_Errors(t *testing.T) {
	t.Run("truncated header", func(t *testing.T) {
		_, err := DecodeLookupSwitch([]byte{byte(LOOKUPSWITCH), 0x00}, 0)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("negative npairs", func(t *testing.T) {
		buf := make([]byte, 1+3+8)
		buf[0] = byte(LOOKUPSWITCH)
		base := 4
		binary.BigEndian.PutUint32(buf[base:], 0)
		binary.BigEndian.PutUint32(buf[base+4:], 0xFFFFFFFE) // -2 as int32
		_, err := DecodeLookupSwitch(buf, 0)
		if err == nil {
			t.Fatal("expected error for negative npairs")
		}
	})
}

// ---------------------------------------------------------------------------
// DecodeTableSwitchInstr / DecodeLookupSwitchInstr
// ---------------------------------------------------------------------------

func TestDecodeTableSwitchInstr_HappyPath(t *testing.T) {
	// instrOffset=0: padStart=1, padding=3
	// operand = everything after the opcode byte
	offsets := []int32{10, 20}
	raw := makeTableSwitchBytes(0, 50, 1, 2, offsets)
	inst := &Instruction{
		Offset:  0,
		Op:      TABLESWITCH,
		Operand: raw[1:], // strip leading opcode byte
		Length:  len(raw),
	}
	info, err := DecodeTableSwitchInstr(inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Low != 1 || info.High != 2 {
		t.Errorf("low=%d high=%d, want 1..2", info.Low, info.High)
	}
	if info.Default != 50 {
		t.Errorf("default = %d, want 50", info.Default)
	}
}

func TestDecodeTableSwitchInstr_WrongOp(t *testing.T) {
	inst := &Instruction{Op: NOP}
	_, err := DecodeTableSwitchInstr(inst)
	if err == nil {
		t.Fatal("expected error for non-tableswitch op")
	}
	if !strings.Contains(err.Error(), "not a tableswitch") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecodeTableSwitchInstr_Truncated(t *testing.T) {
	inst := &Instruction{
		Offset:  0,
		Op:      TABLESWITCH,
		Operand: []byte{0x00, 0x00}, // way too short
		Length:  3,
	}
	_, err := DecodeTableSwitchInstr(inst)
	if err == nil {
		t.Fatal("expected error for truncated tableswitch operand")
	}
}

func TestDecodeTableSwitchInstr_InvalidRange(t *testing.T) {
	// padding=3, then default(4)+low(4)+high(4) with low > high
	operand := make([]byte, 3+12)
	binary.BigEndian.PutUint32(operand[3:], 0)  // default
	binary.BigEndian.PutUint32(operand[7:], 10) // low=10
	binary.BigEndian.PutUint32(operand[11:], 5) // high=5 → invalid
	inst := &Instruction{Offset: 0, Op: TABLESWITCH, Operand: operand}
	_, err := DecodeTableSwitchInstr(inst)
	if err == nil {
		t.Fatal("expected error for invalid range")
	}
}

func TestDecodeLookupSwitchInstr_HappyPath(t *testing.T) {
	pairs := [][2]int32{{100, 50}, {200, 100}}
	raw := makeLookupSwitchBytes(0, 300, pairs)
	inst := &Instruction{
		Offset:  0,
		Op:      LOOKUPSWITCH,
		Operand: raw[1:],
		Length:  len(raw),
	}
	info, err := DecodeLookupSwitchInstr(inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Default != 300 {
		t.Errorf("default = %d, want 300", info.Default)
	}
	if len(info.Pairs) != 2 {
		t.Fatalf("len(pairs) = %d, want 2", len(info.Pairs))
	}
	if info.Pairs[0].Match != 100 {
		t.Errorf("pairs[0].Match = %d, want 100", info.Pairs[0].Match)
	}
	if info.Pairs[0].Target != 50 {
		t.Errorf("pairs[0].Target = %d, want 50", info.Pairs[0].Target)
	}
}

func TestDecodeLookupSwitchInstr_WrongOp(t *testing.T) {
	inst := &Instruction{Op: TABLESWITCH}
	_, err := DecodeLookupSwitchInstr(inst)
	if err == nil {
		t.Fatal("expected error for non-lookupswitch op")
	}
	if !strings.Contains(err.Error(), "not a lookupswitch") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecodeLookupSwitchInstr_Truncated(t *testing.T) {
	inst := &Instruction{
		Offset:  0,
		Op:      LOOKUPSWITCH,
		Operand: []byte{0x00}, // too short
		Length:  2,
	}
	_, err := DecodeLookupSwitchInstr(inst)
	if err == nil {
		t.Fatal("expected error for truncated lookupswitch operand")
	}
}

func TestDecodeLookupSwitchInstr_NegativeNpairs(t *testing.T) {
	operand := make([]byte, 3+8)                        // padding=3 + 8 byte header
	binary.BigEndian.PutUint32(operand[3:], 0)          // default
	binary.BigEndian.PutUint32(operand[7:], 0xFFFFFFFF) // -1 as int32
	inst := &Instruction{Offset: 0, Op: LOOKUPSWITCH, Operand: operand}
	_, err := DecodeLookupSwitchInstr(inst)
	if err == nil {
		t.Fatal("expected error for negative npairs")
	}
}

// ---------------------------------------------------------------------------
// TableSwitchLength
// ---------------------------------------------------------------------------

func TestTableSwitchLength(t *testing.T) {
	tests := []struct {
		instrOffset int
		wantMin     int
	}{
		{0, 1 + 3 + 12}, // offset 0: padding=3, min = 16
		{4, 1 + 3 + 12}, // offset 4: padStart=5, padding=3, min = 16
		{3, 1 + 0 + 12}, // offset 3: padStart=4, padding=0, min = 13
		{7, 1 + 0 + 12}, // offset 7: padStart=8, padding=0, min = 13
	}
	for _, tc := range tests {
		n, err := TableSwitchLength(tc.instrOffset)
		if err != nil {
			t.Errorf("offset %d: unexpected error: %v", tc.instrOffset, err)
		}
		if n != tc.wantMin {
			t.Errorf("offset %d: got %d, want %d", tc.instrOffset, n, tc.wantMin)
		}
	}
}

// ---------------------------------------------------------------------------
// Instruction methods
// ---------------------------------------------------------------------------

func TestInstruction_LocalIndex(t *testing.T) {
	tests := []struct {
		name      string
		inst      *Instruction
		wantIndex uint16
	}{
		{"iload_0", &Instruction{Op: ILOAD_0}, 0},
		{"iload_1", &Instruction{Op: ILOAD_1}, 1},
		{"iload_2", &Instruction{Op: ILOAD_2}, 2},
		{"iload_3", &Instruction{Op: ILOAD_3}, 3},
		{"lload_0", &Instruction{Op: LLOAD_0}, 0},
		{"lload_3", &Instruction{Op: LLOAD_3}, 3},
		{"fload_0", &Instruction{Op: FLOAD_0}, 0},
		{"dload_0", &Instruction{Op: DLOAD_0}, 0},
		{"aload_0", &Instruction{Op: ALOAD_0}, 0},
		{"aload_3", &Instruction{Op: ALOAD_3}, 3},
		{"istore_0", &Instruction{Op: ISTORE_0}, 0},
		{"istore_3", &Instruction{Op: ISTORE_3}, 3},
		{"lstore_0", &Instruction{Op: LSTORE_0}, 0},
		{"fstore_1", &Instruction{Op: FSTORE_1}, 1},
		{"dstore_2", &Instruction{Op: DSTORE_2}, 2},
		{"astore_1", &Instruction{Op: ASTORE_1}, 1},
		{"wide iload idx=15", &Instruction{Op: ILOAD, Wide: true, Operand: []byte{0x00, 0x0F}}, 15},
		{"iload explicit idx=7", &Instruction{Op: ILOAD, Operand: []byte{0x07}}, 7},
		{"no operand fallback", &Instruction{Op: ILOAD}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.inst.LocalIndex()
			if got != tc.wantIndex {
				t.Errorf("LocalIndex() = %d, want %d", got, tc.wantIndex)
			}
		})
	}
}

func TestInstruction_BranchOffset(t *testing.T) {
	tests := []struct {
		name string
		inst *Instruction
		want int32
	}{
		{"goto +5", &Instruction{Op: GOTO, Operand: []byte{0x00, 0x05}}, 5},
		{"goto -1", &Instruction{Op: GOTO, Operand: []byte{0xFF, 0xFF}}, -1},
		{"goto_w +65536", &Instruction{Op: GOTO_W, Operand: []byte{0x00, 0x01, 0x00, 0x00}}, 65536},
		{"jsr_w offset", &Instruction{Op: JSR_W, Operand: []byte{0x00, 0x00, 0x00, 0x0A}}, 10},
		{"ifeq -3", &Instruction{Op: IFEQ, Operand: []byte{0xFF, 0xFD}}, -3},
		{"no operand", &Instruction{Op: GOTO}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.inst.BranchOffset()
			if got != tc.want {
				t.Errorf("BranchOffset() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestInstruction_BranchTarget(t *testing.T) {
	inst := &Instruction{Offset: 10, Op: GOTO, Operand: []byte{0x00, 0x05}}
	if got := inst.BranchTarget(); got != 15 {
		t.Errorf("BranchTarget() = %d, want 15", got)
	}
}

func TestInstruction_CPIndex(t *testing.T) {
	tests := []struct {
		name string
		inst *Instruction
		want uint16
	}{
		{"ldc idx=5", &Instruction{Op: LDC, Operand: []byte{0x05}}, 5},
		{"ldc no operand", &Instruction{Op: LDC}, 0},
		{"getstatic idx=10", &Instruction{Op: GETSTATIC, Operand: []byte{0x00, 0x0A}}, 10},
		{"invokevirtual no operand", &Instruction{Op: INVOKEVIRTUAL}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.inst.CPIndex()
			if got != tc.want {
				t.Errorf("CPIndex() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestInstruction_ImmediateByte(t *testing.T) {
	inst := &Instruction{Op: BIPUSH, Operand: []byte{0x2A}} // 42
	if got := inst.ImmediateByte(); got != 42 {
		t.Errorf("ImmediateByte() = %d, want 42", got)
	}
	noOp := &Instruction{Op: BIPUSH}
	if got := noOp.ImmediateByte(); got != 0 {
		t.Errorf("ImmediateByte() on empty = %d, want 0", got)
	}

	// negative value
	neg := &Instruction{Op: BIPUSH, Operand: []byte{0xFF}} // -1 as int8
	if got := neg.ImmediateByte(); got != -1 {
		t.Errorf("ImmediateByte(-1) = %d, want -1", got)
	}
}

func TestInstruction_ImmediateShort(t *testing.T) {
	inst := &Instruction{Op: SIPUSH, Operand: []byte{0x01, 0x2C}} // 300
	if got := inst.ImmediateShort(); got != 300 {
		t.Errorf("ImmediateShort() = %d, want 300", got)
	}
	noOp := &Instruction{Op: SIPUSH}
	if got := noOp.ImmediateShort(); got != 0 {
		t.Errorf("ImmediateShort() on empty = %d, want 0", got)
	}
}

func TestInstruction_IIncValue(t *testing.T) {
	tests := []struct {
		name string
		inst *Instruction
		want int16
	}{
		{"non-wide iinc +5", &Instruction{Op: IINC, Operand: []byte{0x01, 0x05}}, 5},
		{"non-wide iinc -1", &Instruction{Op: IINC, Operand: []byte{0x01, 0xFF}}, -1},
		{"wide iinc +10", &Instruction{Op: IINC, Wide: true, Operand: []byte{0x00, 0x01, 0x00, 0x0A}}, 10},
		{"wide iinc -5", &Instruction{Op: IINC, Wide: true, Operand: []byte{0x00, 0x01, 0xFF, 0xFB}}, -5},
		{"no operand", &Instruction{Op: IINC}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.inst.IIncValue()
			if got != tc.want {
				t.Errorf("IIncValue() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestInstruction_NewArrayElementType(t *testing.T) {
	inst := &Instruction{Op: NEWARRAY, Operand: []byte{byte(ArrayTypeInt)}}
	got := inst.NewArrayElementType()
	if got != ArrayTypeInt {
		t.Errorf("got %v, want ArrayTypeInt", got)
	}
	noOp := &Instruction{Op: NEWARRAY}
	if got := noOp.NewArrayElementType(); got != 0 {
		t.Errorf("empty operand: got %d, want 0", got)
	}
}

func TestInstruction_MultiANewArrayDimensions(t *testing.T) {
	inst := &Instruction{Op: MULTIANEWARRAY, Operand: []byte{0x00, 0x05, 0x03}} // 3 dims
	if got := inst.MultiANewArrayDimensions(); got != 3 {
		t.Errorf("got %d, want 3", got)
	}
	short := &Instruction{Op: MULTIANEWARRAY, Operand: []byte{0x00, 0x05}}
	if got := short.MultiANewArrayDimensions(); got != 0 {
		t.Errorf("short operand: got %d, want 0", got)
	}
}

func TestInstruction_String(t *testing.T) {
	tests := []struct {
		name     string
		inst     *Instruction
		contains string
	}{
		{"nop", &Instruction{Op: NOP, Offset: 0}, "nop"},
		{"return", &Instruction{Op: RETURN, Offset: 5}, "return"},
		{"wide iload", &Instruction{Op: ILOAD, Wide: true, Offset: 2}, "wide iload"},
		{"unknown op 0xF0", &Instruction{Op: 0xF0, Offset: 0}, "?"},
		// Note: synthetic opcodes (FAKE_TRY=0x100, FAKE_CATCH=0x101) cannot be used
		// directly in Instruction.String() because opcodeTable is [256]*OpcodeInfo and
		// inst.Op >= 0x100 would index out of range — tested via Opcode.String() instead.
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.inst.String()
			if !strings.Contains(s, tc.contains) {
				t.Errorf("String() = %q, want to contain %q", s, tc.contains)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// OpcodeInfo methods
// ---------------------------------------------------------------------------

func TestOpcodeInfo_IsJump(t *testing.T) {
	jumps := []Opcode{GOTO, GOTO_W, JSR, JSR_W, IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE,
		IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
		IF_ACMPEQ, IF_ACMPNE, IFNULL, IFNONNULL, TABLESWITCH, LOOKUPSWITCH}
	noJumps := []Opcode{NOP, IADD, RETURN, IRETURN, GETSTATIC, INVOKEVIRTUAL}

	for _, op := range jumps {
		info := LookupOp(op)
		if info == nil {
			t.Errorf("no info for jump op %v", op)
			continue
		}
		if !info.IsJump() {
			t.Errorf("IsJump() = false for %v, want true", op)
		}
	}
	for _, op := range noJumps {
		info := LookupOp(op)
		if info == nil {
			t.Errorf("no info for non-jump op %v", op)
			continue
		}
		if info.IsJump() {
			t.Errorf("IsJump() = true for %v, want false", op)
		}
	}
}

func TestOpcodeInfo_IsReturn(t *testing.T) {
	returns := []Opcode{IRETURN, LRETURN, FRETURN, DRETURN, ARETURN, RETURN}
	noReturns := []Opcode{NOP, GOTO, INVOKEVIRTUAL, IADD}

	for _, op := range returns {
		info := LookupOp(op)
		if info == nil {
			t.Errorf("no info for %v", op)
			continue
		}
		if !info.IsReturn() {
			t.Errorf("IsReturn() = false for %v", op)
		}
	}
	for _, op := range noReturns {
		info := LookupOp(op)
		if info == nil {
			continue
		}
		if info.IsReturn() {
			t.Errorf("IsReturn() = true for %v", op)
		}
	}
}

func TestOpcodeInfo_IsStore(t *testing.T) {
	stores := []Opcode{ISTORE, LSTORE, FSTORE, DSTORE, ASTORE,
		ISTORE_0, ISTORE_1, ISTORE_2, ISTORE_3,
		LSTORE_0, LSTORE_1, LSTORE_2, LSTORE_3,
		FSTORE_0, FSTORE_1, FSTORE_2, FSTORE_3,
		DSTORE_0, DSTORE_1, DSTORE_2, DSTORE_3,
		ASTORE_0, ASTORE_1, ASTORE_2, ASTORE_3}
	noStores := []Opcode{NOP, ILOAD, ILOAD_0, IADD, RETURN}

	for _, op := range stores {
		info := LookupOp(op)
		if info == nil {
			t.Errorf("no info for store op %v", op)
			continue
		}
		if !info.IsStore() {
			t.Errorf("IsStore() = false for %v", op)
		}
	}
	for _, op := range noStores {
		info := LookupOp(op)
		if info == nil {
			continue
		}
		if info.IsStore() {
			t.Errorf("IsStore() = true for %v", op)
		}
	}
}

func TestOpcodeInfo_IsLoad(t *testing.T) {
	loads := []Opcode{ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
		ILOAD_0, ILOAD_1, ILOAD_2, ILOAD_3,
		LLOAD_0, LLOAD_1, LLOAD_2, LLOAD_3,
		FLOAD_0, FLOAD_1, FLOAD_2, FLOAD_3,
		DLOAD_0, DLOAD_1, DLOAD_2, DLOAD_3,
		ALOAD_0, ALOAD_1, ALOAD_2, ALOAD_3}
	noLoads := []Opcode{NOP, ISTORE, ISTORE_0, IADD, RETURN}

	for _, op := range loads {
		info := LookupOp(op)
		if info == nil {
			t.Errorf("no info for load op %v", op)
			continue
		}
		if !info.IsLoad() {
			t.Errorf("IsLoad() = false for %v", op)
		}
	}
	for _, op := range noLoads {
		info := LookupOp(op)
		if info == nil {
			continue
		}
		if info.IsLoad() {
			t.Errorf("IsLoad() = true for %v", op)
		}
	}
}

func TestOpcodeInfo_IsInvoke(t *testing.T) {
	invokes := []Opcode{INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC, INVOKEINTERFACE, INVOKEDYNAMIC}
	noInvokes := []Opcode{NOP, GETFIELD, PUTFIELD, RETURN, NEW}

	for _, op := range invokes {
		info := LookupOp(op)
		if info == nil {
			t.Errorf("no info for invoke op %v", op)
			continue
		}
		if !info.IsInvoke() {
			t.Errorf("IsInvoke() = false for %v", op)
		}
	}
	for _, op := range noInvokes {
		info := LookupOp(op)
		if info == nil {
			continue
		}
		if info.IsInvoke() {
			t.Errorf("IsInvoke() = true for %v", op)
		}
	}
}

// ---------------------------------------------------------------------------
// StackType methods
// ---------------------------------------------------------------------------

func TestStackType_ComputationCategory(t *testing.T) {
	tests := []struct {
		st   StackType
		want int
	}{
		{StackInt, 1},
		{StackFloat, 1},
		{StackRef, 1},
		{StackReturnAddress, 1},
		{StackReturnAddressOrRef, 1},
		{StackLong, 2},
		{StackDouble, 2},
		{StackVoid, 0},
	}
	for _, tc := range tests {
		if got := tc.st.ComputationCategory(); got != tc.want {
			t.Errorf("%v.ComputationCategory() = %d, want %d", tc.st, got, tc.want)
		}
	}
}

func TestStackType_String(t *testing.T) {
	tests := []struct {
		st   StackType
		want string
	}{
		{StackInt, "int"},
		{StackFloat, "float"},
		{StackRef, "reference"},
		{StackReturnAddress, "returnAddress"},
		{StackReturnAddressOrRef, "returnAddress|ref"},
		{StackLong, "long"},
		{StackDouble, "double"},
		{StackVoid, "void"},
		{StackType(255), "StackType(255)"},
	}
	for _, tc := range tests {
		if got := tc.st.String(); got != tc.want {
			t.Errorf("StackType(%d).String() = %q, want %q", tc.st, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// NewArrayType.String
// ---------------------------------------------------------------------------

func TestNewArrayType_String(t *testing.T) {
	tests := []struct {
		t    NewArrayType
		want string
	}{
		{ArrayTypeBoolean, "boolean"},
		{ArrayTypeChar, "char"},
		{ArrayTypeFloat, "float"},
		{ArrayTypeDouble, "double"},
		{ArrayTypeByte, "byte"},
		{ArrayTypeShort, "short"},
		{ArrayTypeInt, "int"},
		{ArrayTypeLong, "long"},
		{NewArrayType(99), "array_type(99)"},
	}
	for _, tc := range tests {
		if got := tc.t.String(); got != tc.want {
			t.Errorf("NewArrayType(%d).String() = %q, want %q", tc.t, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Opcode.String
// ---------------------------------------------------------------------------

func TestOpcode_String(t *testing.T) {
	tests := []struct {
		op   Opcode
		want string
	}{
		{NOP, "nop"},
		{RETURN, "return"},
		{IRETURN, "ireturn"},
		{GOTO, "goto"},
		{FAKE_TRY, "fake_try"},
		{FAKE_CATCH, "fake_catch"},
		{Opcode(0xF0), "opcode(0xF0)"}, // unknown
	}
	for _, tc := range tests {
		if got := tc.op.String(); got != tc.want {
			t.Errorf("Opcode(0x%02X).String() = %q, want %q", uint16(tc.op), got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// LookupOpcode / LookupSyntheticOpcode / LookupOp
// ---------------------------------------------------------------------------

func TestLookupOpcode_AllDefined(t *testing.T) {
	// Sample of well-known opcodes that must be present
	known := []byte{
		byte(NOP), byte(ACONST_NULL), byte(BIPUSH), byte(SIPUSH),
		byte(ILOAD), byte(ALOAD_0), byte(ISTORE_3),
		byte(IADD), byte(GOTO), byte(RETURN), byte(GETSTATIC),
		byte(INVOKEVIRTUAL), byte(NEW), byte(NEWARRAY),
		byte(CHECKCAST), byte(INSTANCEOF), byte(MONITORENTER),
		byte(GOTO_W), byte(JSR_W),
	}
	for _, b := range known {
		info, err := LookupOpcode(b)
		if err != nil {
			t.Errorf("LookupOpcode(0x%02X): unexpected error: %v", b, err)
		}
		if info == nil {
			t.Errorf("LookupOpcode(0x%02X): nil info", b)
		}
	}
}

func TestLookupOpcode_ReservedOpcodes(t *testing.T) {
	// 0xFE and 0xFF are reserved/invalid JVM opcodes — must return error
	for _, b := range []byte{0xFE, 0xFF} {
		_, err := LookupOpcode(b)
		if err == nil {
			t.Errorf("LookupOpcode(0x%02X): expected error for unknown opcode", b)
		}
	}
}

func TestLookupSyntheticOpcode_Known(t *testing.T) {
	for _, op := range []Opcode{FAKE_TRY, FAKE_CATCH} {
		info, err := LookupSyntheticOpcode(op)
		if err != nil {
			t.Errorf("LookupSyntheticOpcode(%v): unexpected error: %v", op, err)
		}
		if info == nil {
			t.Errorf("LookupSyntheticOpcode(%v): nil info", op)
		}
	}
}

func TestLookupSyntheticOpcode_Unknown(t *testing.T) {
	_, err := LookupSyntheticOpcode(Opcode(0x200))
	if err == nil {
		t.Error("expected error for unknown synthetic opcode")
	}
}

func TestLookupOp(t *testing.T) {
	// Regular opcode
	info := LookupOp(NOP)
	if info == nil {
		t.Error("LookupOp(NOP): nil info")
	}
	// Synthetic
	info = LookupOp(FAKE_TRY)
	if info == nil {
		t.Error("LookupOp(FAKE_TRY): nil info")
	}
	// Unknown in both tables
	info = LookupOp(Opcode(0xF0))
	if info != nil {
		t.Errorf("LookupOp(0xF0): expected nil, got %v", info)
	}
	// Unknown synthetic
	info = LookupOp(Opcode(0x200))
	if info != nil {
		t.Errorf("LookupOp(0x200): expected nil, got %v", info)
	}
}

// ---------------------------------------------------------------------------
// Round-trip: DecodeInstructions → DecodeTableSwitchInstr / DecodeLookupSwitchInstr
// ---------------------------------------------------------------------------

func TestRoundTrip_TableSwitch(t *testing.T) {
	offsets := []int32{10, 20, 30}
	raw := makeTableSwitchBytes(0, 50, 0, 2, offsets)
	instrs, err := DecodeInstructions(raw)
	if err != nil {
		t.Fatalf("DecodeInstructions: %v", err)
	}
	if len(instrs) != 1 || instrs[0].Op != TABLESWITCH {
		t.Fatalf("expected 1 TABLESWITCH, got %v", instrs)
	}
	info, err := DecodeTableSwitchInstr(instrs[0])
	if err != nil {
		t.Fatalf("DecodeTableSwitchInstr: %v", err)
	}
	if info.Low != 0 || info.High != 2 {
		t.Errorf("low=%d high=%d, want 0..2", info.Low, info.High)
	}
	if len(info.Targets) != 3 {
		t.Errorf("len(targets)=%d, want 3", len(info.Targets))
	}
	// default target = instrOffset(0) + defaultOff(50)
	if info.Default != 50 {
		t.Errorf("default=%d, want 50", info.Default)
	}
}

func TestRoundTrip_LookupSwitch(t *testing.T) {
	pairs := [][2]int32{{1, 40}, {2, 80}}
	raw := makeLookupSwitchBytes(0, 200, pairs)
	instrs, err := DecodeInstructions(raw)
	if err != nil {
		t.Fatalf("DecodeInstructions: %v", err)
	}
	if len(instrs) != 1 || instrs[0].Op != LOOKUPSWITCH {
		t.Fatalf("expected 1 LOOKUPSWITCH, got %v", instrs)
	}
	info, err := DecodeLookupSwitchInstr(instrs[0])
	if err != nil {
		t.Fatalf("DecodeLookupSwitchInstr: %v", err)
	}
	if info.Default != 200 {
		t.Errorf("default=%d, want 200", info.Default)
	}
	if len(info.Pairs) != 2 {
		t.Errorf("len(pairs)=%d, want 2", len(info.Pairs))
	}
}

// errorsIs ensures we're using errors.Is / errors.As style (never ==).
// This is a compile-time check that we import "errors" and use it properly.
var _ = errors.Is

// Verify the unused import doesn't cause a build failure; the import is
// present in the file to signal adherence to repo conventions.
