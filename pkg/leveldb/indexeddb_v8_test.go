package leveldb

import (
	"reflect"
	"testing"
)

func TestDecodeIndexedDBValue(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want any
		ok   bool
	}{
		{
			// FF 0F | o | " 01 'a' | I 02(=zigzag 1) | { 01
			name: "flat object",
			in:   []byte{0xFF, 0x0F, 'o', '"', 0x01, 'a', 'I', 0x02, '{', 0x01},
			want: map[string]any{"a": int64(1)},
			ok:   true,
		},
		{
			// Blink-wrapped: 24 FF 15 FE + 12 zero trailer, then the same V8 payload.
			name: "blink-wrapped object",
			in: append([]byte{0x24, 0xFF, 0x15, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				[]byte{0xFF, 0x0F, 'o', '"', 0x01, 'a', 'I', 0x02, '{', 0x01}...),
			want: map[string]any{"a": int64(1)},
			ok:   true,
		},
		{
			// nested: { "k": { "n": true } }
			name: "nested object + bool",
			in:   []byte{0xFF, 0x0F, 'o', '"', 0x01, 'k', 'o', '"', 0x01, 'n', 'T', '{', 0x01, '{', 0x01},
			want: map[string]any{"k": map[string]any{"n": true}},
			ok:   true,
		},
		{
			// dense array [1,2]: A 02 | I 02 | I 04 | $ 00 02
			name: "array",
			in:   []byte{0xFF, 0x0F, 'A', 0x02, 'I', 0x02, 'I', 0x04, '$', 0x00, 0x02},
			want: []any{int64(1), int64(2)},
			ok:   true,
		},
		{
			name: "two-byte string value",
			// { "s": <utf16 "hi"> } : o " 01 's' c 04 68 00 69 00 { 01
			in:   []byte{0xFF, 0x0F, 'o', '"', 0x01, 's', 'c', 0x04, 0x68, 0x00, 0x69, 0x00, '{', 0x01},
			want: map[string]any{"s": "hi"},
			ok:   true,
		},
		{
			name: "no v8 payload",
			in:   []byte{0x0a, 0x01, 0x02, 0x03, 0x04},
			want: nil,
			ok:   false,
		},
		{
			name: "empty",
			in:   nil,
			want: nil,
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := DecodeIndexedDBValue(tt.in)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (got=%v)", ok, tt.ok, got)
			}
			if tt.ok && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decoded = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestDecodeIndexedDBValue_VariantSweep ensures the sweep skips a false-positive
// payload start (a stray FF that decodes to a tiny scalar) in favor of the real
// object further in — i.e. it tests variants and keeps the correct one.
func TestDecodeIndexedDBValue_VariantSweep(t *testing.T) {
	// leading false candidate: FF 0F " 02 'AB'  (a 2-char string, low score)
	// then the real object:     FF 0F o " 01 'a' I 02 { 01
	in := []byte{
		0xFF, 0x0F, '"', 0x02, 'A', 'B',
		0xFF, 0x0F, 'o', '"', 0x01, 'a', 'I', 0x02, '{', 0x01,
	}
	got, ok := DecodeIndexedDBValue(in)
	if !ok {
		t.Fatal("expected ok")
	}
	m, isMap := got.(map[string]any)
	if !isMap || m["a"] != int64(1) {
		t.Errorf("sweep picked wrong variant: %#v", got)
	}
}

// TestDecodeIndexedDBValue_NoPanicOnGarbage ensures malformed/truncated V8
// payloads fail closed rather than panic.
func TestDecodeIndexedDBValue_NoPanicOnGarbage(t *testing.T) {
	cases := [][]byte{
		{0xFF, 0x0F, 'o', '"', 0xFF, 0xFF},  // string length overruns
		{0xFF, 0x0F, 'A', 0xFF, 0xFF, 0x7F}, // huge array count
		{0xFF, 0x0F, 'o'},                   // object never terminates
		{0xFF, 0x0F, 'N', 0x00},             // double truncated
	}
	for i, c := range cases {
		if _, ok := DecodeIndexedDBValue(c); ok {
			t.Errorf("case %d: expected ok=false on garbage", i)
		}
	}
}
