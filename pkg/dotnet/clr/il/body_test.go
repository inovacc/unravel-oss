/*
Copyright (c) 2026 Security Research
*/
package il

import (
	"bytes"
	"testing"
)

// raAt wraps a byte slice as an io.ReaderAt for body tests.
func raAt(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// identityRVA maps rva 1:1 to file offset for fixtures.
func identityRVA(off int) func(uint32) (int, bool) {
	return func(rva uint32) (int, bool) { return off + int(rva), true }
}

func TestReadMethodBody_TinyHeader(t *testing.T) {
	// Tiny header: low 2 bits = 0x2, high 6 bits = code length.
	// 3 bytes of code: nop(0x00) nop(0x00) ret(0x2A).
	code := []byte{0x00, 0x00, 0x2A}
	hdr := byte((len(code) << 2) | 0x2) // 0x0E
	body := append([]byte{hdr}, code...)

	mb, err := ReadMethodBody(raAt(body), func(rva uint32) (int, bool) { return int(rva) - 0x2000, true }, 0x2000, 0)
	if err != nil {
		t.Fatalf("ReadMethodBody tiny: %v", err)
	}
	if mb.IsNative {
		t.Fatalf("tiny body wrongly marked native")
	}
	if mb.MaxStack != 8 {
		t.Errorf("tiny MaxStack = %d, want 8 (ECMA default)", mb.MaxStack)
	}
	if !bytes.Equal(mb.Code, code) {
		t.Errorf("tiny Code = %x, want %x", mb.Code, code)
	}
	if mb.LocalVarSigTok != 0 {
		t.Errorf("tiny LocalVarSigTok = %#x, want 0", uint32(mb.LocalVarSigTok))
	}
	if len(mb.EH) != 0 {
		t.Errorf("tiny EH = %d, want 0", len(mb.EH))
	}
}

func TestReadMethodBody_FatHeader(t *testing.T) {
	// Fat header (12 bytes): flags+size word, maxstack, codeSize, localVarSigTok.
	// flags low 2 bits = 0x3 (fat); size (high 4 bits of the 2-byte LE word) = 3 dwords.
	code := []byte{0x00, 0x2A} // nop ret
	hdr := make([]byte, 12)
	// flagsAndSize: bits0-11 = flags, bits12-15 = header size in dwords (3).
	flagsAndSize := uint16(0x3) | (uint16(3) << 12)
	hdr[0] = byte(flagsAndSize)
	hdr[1] = byte(flagsAndSize >> 8)
	hdr[2], hdr[3] = 0x10, 0x00 // MaxStack = 16
	hdr[4] = byte(len(code))    // CodeSize LE
	// hdr[8:12] = LocalVarSigTok = 0x11000001
	hdr[8], hdr[9], hdr[10], hdr[11] = 0x01, 0x00, 0x00, 0x11
	body := append(hdr, code...)

	mb, err := ReadMethodBody(raAt(body), func(rva uint32) (int, bool) { return int(rva) - 0x2000, true }, 0x2000, 0)
	if err != nil {
		t.Fatalf("ReadMethodBody fat: %v", err)
	}
	if mb.MaxStack != 16 {
		t.Errorf("fat MaxStack = %d, want 16", mb.MaxStack)
	}
	if uint32(mb.LocalVarSigTok) != 0x11000001 {
		t.Errorf("fat LocalVarSigTok = %#x, want 0x11000001", uint32(mb.LocalVarSigTok))
	}
	if !bytes.Equal(mb.Code, code) {
		t.Errorf("fat Code = %x, want %x", mb.Code, code)
	}
}

func TestReadMethodBody_RVAUnmappable(t *testing.T) {
	_, err := ReadMethodBody(raAt([]byte{0x06}), func(uint32) (int, bool) { return 0, false }, 0x999, 0)
	if err == nil {
		t.Fatal("expected error on unmappable rva, got nil")
	}
}

func TestGateNative(t *testing.T) {
	tests := []struct {
		name      string
		rva       uint32
		implFlags uint16
		want      bool
	}{
		{"managed IL with rva", 0x2000, 0x0000, false},
		{"rva zero abstract/extern", 0x0000, 0x0000, true},
		{"native impl (0x0004)", 0x2000, 0x0004, true},
		{"runtime impl (0x0003)", 0x2000, 0x0003, true},
		{"internalcall (0x1000)", 0x2000, 0x1000, true},
		{"pinvoke (0x2000 flags)", 0x2000, 0x2000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mb, native := gateNative(tt.rva, tt.implFlags)
			if native != tt.want {
				t.Fatalf("gateNative(%#x,%#x) native=%v want %v", tt.rva, tt.implFlags, native, tt.want)
			}
			if native && !mb.IsNative {
				t.Errorf("gated body IsNative=false, want true")
			}
		})
	}
}

func TestReadMethodBody_NativeShortCircuit(t *testing.T) {
	// Even with garbage at the rva, a native implFlags returns a native marker, no error.
	mb, err := ReadMethodBody(raAt([]byte{0xFF}), func(uint32) (int, bool) { return 0, true }, 0x2000, 0x0004)
	if err != nil {
		t.Fatalf("native short-circuit err: %v", err)
	}
	if !mb.IsNative {
		t.Fatal("expected IsNative=true for native impl")
	}
}
