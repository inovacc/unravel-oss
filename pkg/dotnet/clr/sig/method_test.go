package sig

import "testing"

func TestDecodeMethodSig(t *testing.T) {
	// DEFAULT|HASTHIS (0x20), paramCount=2, ret=void(0x01),
	// p0=i4(0x08), p1=string(0x0e).
	ms, err := DecodeMethodSig([]byte{0x20, 0x02, 0x01, 0x08, 0x0e})
	if err != nil {
		t.Fatalf("DecodeMethodSig: %v", err)
	}
	if !ms.HasThis {
		t.Error("HasThis = false, want true")
	}
	if ms.Ret.Kind != ETVoid {
		t.Errorf("Ret.Kind = %v, want ETVoid", ms.Ret.Kind)
	}
	if len(ms.Params) != 2 ||
		ms.Params[0].Kind != ETI4 || ms.Params[1].Kind != ETString {
		t.Fatalf("Params = %+v, want [i4 string]", ms.Params)
	}
}

func TestDecodeMethodSig_NoThisNoParams(t *testing.T) {
	// DEFAULT (0x00), paramCount=0, ret=i4(0x08).
	ms, err := DecodeMethodSig([]byte{0x00, 0x00, 0x08})
	if err != nil {
		t.Fatalf("DecodeMethodSig: %v", err)
	}
	if ms.HasThis || len(ms.Params) != 0 || ms.Ret.Kind != ETI4 {
		t.Fatalf("got %+v", ms)
	}
}

func TestDecodeMethodSig_Truncated(t *testing.T) {
	if _, err := DecodeMethodSig([]byte{0x20, 0x02, 0x01, 0x08}); err == nil {
		t.Fatal("want error on missing second param, got nil")
	}
	if _, err := DecodeMethodSig(nil); err == nil {
		t.Fatal("want error on empty blob, got nil")
	}
}
