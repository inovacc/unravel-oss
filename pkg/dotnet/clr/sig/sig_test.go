package sig

import (
	"errors"
	"testing"
)

func TestDecompressUint(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		wantVal uint32
		wantN   int
		wantErr bool
	}{
		{"one-byte zero", []byte{0x00}, 0, 1, false},
		{"one-byte max 0x7f", []byte{0x7f}, 0x7f, 1, false},
		{"two-byte min 0x80,0x80", []byte{0x80, 0x80}, 0x80, 2, false},
		{"two-byte 0xae,0x57 -> 0x2e57", []byte{0xae, 0x57}, 0x2e57, 2, false},
		{"two-byte max 0xbf,0xff", []byte{0xbf, 0xff}, 0x3fff, 2, false},
		{"four-byte min", []byte{0xc0, 0x00, 0x40, 0x00}, 0x4000, 4, false},
		{"four-byte max", []byte{0xdf, 0xff, 0xff, 0xff}, 0x1fffffff, 4, false},
		{"illegal lead 0xe0", []byte{0xe0, 0x00, 0x00, 0x00}, 0, 0, true},
		{"illegal lead 0xff", []byte{0xff}, 0, 0, true},
		{"empty", []byte{}, 0, 0, true},
		{"truncated two-byte", []byte{0x80}, 0, 0, true},
		{"truncated four-byte", []byte{0xc0, 0x00}, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotN, err := decompressUint(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("decompressUint(%x) err = nil, want error", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("decompressUint(%x) unexpected err: %v", tt.in, err)
			}
			if gotVal != tt.wantVal || gotN != tt.wantN {
				t.Errorf("decompressUint(%x) = (%#x, %d), want (%#x, %d)",
					tt.in, gotVal, gotN, tt.wantVal, tt.wantN)
			}
		})
	}
}

func TestErrIllegalCompressedIntIsSentinel(t *testing.T) {
	_, _, err := decompressUint([]byte{0xe0})
	if !errors.Is(err, ErrIllegalCompressedInt) {
		t.Fatalf("want ErrIllegalCompressedInt, got %v", err)
	}
}
