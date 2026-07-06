/*
Copyright (c) 2026 Security Research
*/

package pri

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// encodeStringPool builds a synthetic string-pool payload matching the
// layout decoded by ParseStrings.
func encodeStringPool(strs []string) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out[:4], uint32(len(strs)))
	for _, s := range strs {
		cu := utf16.Encode([]rune(s))
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint32(hdr, uint32(len(cu)))
		out = append(out, hdr...)
		for _, c := range cu {
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, c)
			out = append(out, b...)
		}
		out = append(out, 0x00, 0x00)
	}
	return out
}

func TestPRIStrings_UTF16Decode(t *testing.T) {
	pool := encodeStringPool([]string{"Hello", "World", "Pri"})
	got, err := ParseStrings(pool)
	if err != nil {
		t.Fatalf("ParseStrings: %v", err)
	}
	want := []string{"Hello", "World", "Pri"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got %#v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPRIStrings_Truncated(t *testing.T) {
	pool := []byte{0x03, 0x00} // claims count 3 but truncated
	_, err := ParseStrings(pool)
	if err == nil {
		t.Fatal("expected error for truncated pool")
	}
}
