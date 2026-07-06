package sig

import "testing"

func TestDecodeLocalVarSig(t *testing.T) {
	// LOCAL_SIG (0x07), count=2, l0=i4(0x08), l1=BYREF(0x10) string(0x0e).
	locals, err := DecodeLocalVarSig([]byte{0x07, 0x02, 0x08, 0x10, 0x0e})
	if err != nil {
		t.Fatalf("DecodeLocalVarSig: %v", err)
	}
	if len(locals) != 2 {
		t.Fatalf("len = %d, want 2", len(locals))
	}
	if locals[0].Kind != ETI4 {
		t.Errorf("locals[0].Kind = %v, want ETI4", locals[0].Kind)
	}
	if locals[1].Kind != ETByRef || locals[1].Elem == nil ||
		locals[1].Elem.Kind != ETString {
		t.Errorf("locals[1] = %+v, want BYREF<string>", locals[1])
	}
}

func TestDecodeLocalVarSig_Pinned(t *testing.T) {
	// LOCAL_SIG, count=1, PINNED(0x45) then SZARRAY(0x1d) U1(0x05).
	locals, err := DecodeLocalVarSig([]byte{0x07, 0x01, 0x45, 0x1d, 0x05})
	if err != nil {
		t.Fatalf("DecodeLocalVarSig: %v", err)
	}
	if len(locals) != 1 || locals[0].Kind != ETSZArray {
		t.Fatalf("got %+v, want [SZARRAY<u1>]", locals)
	}
}

func TestDecodeLocalVarSig_BadLeadAndTruncation(t *testing.T) {
	if _, err := DecodeLocalVarSig([]byte{0x06, 0x00}); err == nil {
		t.Fatal("want error on non-LOCAL_SIG lead, got nil")
	}
	if _, err := DecodeLocalVarSig([]byte{0x07, 0x02, 0x08}); err == nil {
		t.Fatal("want error on missing second local, got nil")
	}
}
