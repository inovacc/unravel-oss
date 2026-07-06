package sig

import "testing"

func TestDecodeFieldSig(t *testing.T) {
	// FIELD (0x06) then SZARRAY (0x1d) of U1 (0x05) -> byte[].
	ts, err := DecodeFieldSig([]byte{0x06, 0x1d, 0x05})
	if err != nil {
		t.Fatalf("DecodeFieldSig: %v", err)
	}
	if ts.Kind != ETSZArray || ts.Elem == nil || ts.Elem.Kind != ETU1 {
		t.Fatalf("got %+v, want SZARRAY<u1>", ts)
	}
}

func TestDecodeFieldSig_BadLead(t *testing.T) {
	// 0x06 is FIELD; 0x07 (LOCAL_SIG) must be rejected here.
	if _, err := DecodeFieldSig([]byte{0x07, 0x08}); err == nil {
		t.Fatal("want error on non-FIELD lead byte, got nil")
	}
	if _, err := DecodeFieldSig(nil); err == nil {
		t.Fatal("want error on empty blob, got nil")
	}
}
