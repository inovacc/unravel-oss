package sig

import "testing"

func decodeOneType(t *testing.T, b []byte) TypeSig {
	t.Helper()
	c := &cursor{b: b}
	ts, err := decodeType(c)
	if err != nil {
		t.Fatalf("decodeType(%x): %v", b, err)
	}
	return ts
}

func TestDecodeType_Primitives(t *testing.T) {
	tests := []struct {
		name string
		elem byte
		kind ElementType
	}{
		{"void", 0x01, ETVoid},
		{"bool", 0x02, ETBoolean},
		{"i4", 0x08, ETI4},
		{"string", 0x0e, ETString},
		{"object", 0x1c, ETObject},
		{"intptr", 0x18, ETI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := decodeOneType(t, []byte{tt.elem})
			if ts.Kind != tt.kind {
				t.Errorf("Kind = %v, want %v", ts.Kind, tt.kind)
			}
		})
	}
}

func TestDecodeType_ClassCodedToken(t *testing.T) {
	// CLASS (0x12) + TypeDefOrRef coded index for TypeRef rid=4:
	// (rid<<2)|tag where tag=1 (TypeRef) => (4<<2)|1 = 0x11, compresses to 1 byte.
	ts := decodeOneType(t, []byte{0x12, 0x11})
	if ts.Kind != ETClass {
		t.Fatalf("Kind = %v, want ETClass", ts.Kind)
	}
	if ts.Token.TableID() != 0x01 || ts.Token.RowID() != 4 {
		t.Errorf("Token = %#x (table %#x rid %d), want TypeRef rid 4",
			uint32(ts.Token), ts.Token.TableID(), ts.Token.RowID())
	}
}

func TestDecodeType_SZArray(t *testing.T) {
	// SZARRAY (0x1d) of I4 (0x08).
	ts := decodeOneType(t, []byte{0x1d, 0x08})
	if ts.Kind != ETSZArray || ts.Elem == nil || ts.Elem.Kind != ETI4 {
		t.Fatalf("got %+v, want SZARRAY<i4>", ts)
	}
}

func TestDecodeType_PtrByref(t *testing.T) {
	pt := decodeOneType(t, []byte{0x0f, 0x08}) // PTR i4
	if pt.Kind != ETPtr || pt.Elem == nil || pt.Elem.Kind != ETI4 {
		t.Fatalf("PTR: got %+v", pt)
	}
	br := decodeOneType(t, []byte{0x10, 0x0e}) // BYREF string
	if br.Kind != ETByRef || br.Elem == nil || br.Elem.Kind != ETString {
		t.Fatalf("BYREF: got %+v", br)
	}
}

func TestDecodeType_VarMvar(t *testing.T) {
	v := decodeOneType(t, []byte{0x13, 0x02}) // VAR number=2
	if v.Kind != ETVar || v.GenIndex != 2 {
		t.Fatalf("VAR: got %+v", v)
	}
	m := decodeOneType(t, []byte{0x1e, 0x00}) // MVAR number=0
	if m.Kind != ETMVar || m.GenIndex != 0 {
		t.Fatalf("MVAR: got %+v", m)
	}
}

func TestDecodeType_GenericInst(t *testing.T) {
	// GENERICINST (0x15) CLASS (0x12) tok(List`1 = TypeRef rid 8 -> (8<<2)|1=0x21)
	// argcount=1, arg=string(0x0e).
	ts := decodeOneType(t, []byte{0x15, 0x12, 0x21, 0x01, 0x0e})
	if ts.Kind != ETGenericInst {
		t.Fatalf("Kind = %v, want ETGenericInst", ts.Kind)
	}
	if ts.Elem == nil || ts.Elem.Kind != ETClass {
		t.Fatalf("generic base = %+v, want CLASS", ts.Elem)
	}
	if len(ts.Args) != 1 || ts.Args[0].Kind != ETString {
		t.Fatalf("args = %+v, want [string]", ts.Args)
	}
}

func TestDecodeType_ArrayShape(t *testing.T) {
	// ARRAY (0x14) I4 (0x08) rank=2 numsizes=1 size=4 numlobounds=1 lobound=0.
	ts := decodeOneType(t, []byte{0x14, 0x08, 0x02, 0x01, 0x04, 0x01, 0x00})
	if ts.Kind != ETArray || ts.Elem == nil || ts.Elem.Kind != ETI4 {
		t.Fatalf("ARRAY base = %+v", ts)
	}
	if ts.Rank != 2 {
		t.Errorf("Rank = %d, want 2", ts.Rank)
	}
}

func TestDecodeType_IllegalElement(t *testing.T) {
	// 0x1b = FNPTR, out of M0/M1 scope -> error, not silent.
	c := &cursor{b: []byte{0x1b}}
	if _, err := decodeType(c); err == nil {
		t.Fatal("FNPTR element: want error, got nil")
	}
}
