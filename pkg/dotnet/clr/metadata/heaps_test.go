/*
Copyright (c) 2026 Security Research
*/
package metadata

import (
	"errors"
	"testing"
)

func TestHeaps_Accessors(t *testing.T) {
	b := newMeta()
	helloOff := b.intern("Hello")
	worldOff := b.intern("World")
	// #US: a UTF-16LE "Hi" literal => length=5 (4 bytes + 1 trailing flag).
	usOff := uint32(len(b.us))
	b.us = append(b.us, 0x05, 'H', 0, 'i', 0, 0x00) // compressed len 5, then 5 bytes
	// #Blob: a 3-byte blob {0x01,0x02,0x03}.
	blobOff := uint32(len(b.blob))
	b.blob = append(b.blob, 0x03, 0x01, 0x02, 0x03)
	gidx := b.addGUID([16]byte{1, 2, 3, 4})
	// Force #~ to exist so build() emits all streams.
	b.setRows(0x00, 0, nil)

	_, h, err := Parse(b.build())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := h.Strings(helloOff); got != "Hello" {
		t.Errorf("Strings(hello) = %q", got)
	}
	if got := h.Strings(worldOff); got != "World" {
		t.Errorf("Strings(world) = %q", got)
	}
	if got := h.UserString(usOff); got != "Hi" {
		t.Errorf("UserString = %q, want Hi", got)
	}
	if got := h.Blob(blobOff); len(got) != 3 || got[2] != 0x03 {
		t.Errorf("Blob = %v, want [1 2 3]", got)
	}
	if got := h.GUID(gidx); got[0] != 1 || got[3] != 4 {
		t.Errorf("GUID(%d) = %v", gidx, got)
	}
	if got := h.Strings(1 << 20); got != "" {
		t.Errorf("out-of-range Strings should be empty, got %q", got)
	}
}

func TestReadCompressedUint(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    uint32
		wantAdv int
		wantErr bool
	}{
		{"empty", nil, 0, 0, true},
		{"1byte", []byte{0x03}, 3, 1, false},
		{"1byte-max", []byte{0x7F}, 0x7F, 1, false},
		{"2byte", []byte{0x80 | 0x12, 0x34}, 0x1234, 2, false},
		{"2byte-truncated", []byte{0x80 | 0x12}, 0, 0, true},
		{"4byte", []byte{0xC0 | 0x01, 0x02, 0x03, 0x04}, 0x01020304, 4, false},
		{"4byte-truncated", []byte{0xC0, 0x02, 0x03}, 0, 0, true},
		{"reserved-E0", []byte{0xE0, 0, 0, 0}, 0, 0, true}, // 111x lead: illegal
		{"reserved-F0", []byte{0xF0, 0, 0, 0}, 0, 0, true},
		{"reserved-FF", []byte{0xFF, 0, 0, 0}, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, adv, err := readCompressedUint(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrBadCompressedUint) {
					t.Fatalf("err = %v, want ErrBadCompressedUint", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tt.want || adv != tt.wantAdv {
				t.Errorf("got (%#x, %d), want (%#x, %d)", got, adv, tt.want, tt.wantAdv)
			}
		})
	}
}
