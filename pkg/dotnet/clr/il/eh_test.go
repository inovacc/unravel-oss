/*
Copyright (c) 2026 Security Research
*/
package il

import (
	"bytes"
	"testing"
)

// fatBodyWithEH builds a fat method body with code then one EH section.
func fatBodyWithEH(t *testing.T, code, ehSection []byte) []byte {
	t.Helper()
	hdr := make([]byte, 12)
	flagsAndSize := uint16(0x3) | uint16(corILMethodMoreSects) | (uint16(3) << 12)
	hdr[0] = byte(flagsAndSize)
	hdr[1] = byte(flagsAndSize >> 8)
	hdr[2], hdr[3] = 0x08, 0x00 // maxstack 8
	hdr[4] = byte(len(code))
	body := append(hdr, code...)
	// EH section must start 4-byte aligned after code.
	for (len(body)-12)%4 != 0 {
		body = append(body, 0)
	}
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	return append(body, ehSection...)
}

func TestReadEH_SmallSection(t *testing.T) {
	// Small EH header: kind=0x01 (EHTable), DataSize byte, pad word. One clause = 12 bytes.
	// Section total = 4 (header) + 12 = 16.
	clause := make([]byte, 12)
	// Flags(uint16)=0 (Exception), TryOffset(uint16)=0, TryLength(byte)=2,
	// HandlerOffset(uint16)=2, HandlerLength(byte)=3, ClassToken(uint32)=0x01000005.
	clause[0], clause[1] = 0x00, 0x00 // Flags
	clause[2], clause[3] = 0x00, 0x00 // TryOffset
	clause[4] = 0x02                  // TryLength
	clause[5], clause[6] = 0x02, 0x00 // HandlerOffset
	clause[7] = 0x03                  // HandlerLength
	clause[8], clause[9], clause[10], clause[11] = 0x05, 0x00, 0x00, 0x01
	section := []byte{0x01, 16, 0x00, 0x00} // kind=EHTable, DataSize=16
	section = append(section, clause...)

	code := []byte{0x00, 0x00, 0x00, 0x00, 0x2A}
	body := fatBodyWithEH(t, code, section)

	// rva must be non-zero: ReadMethodBody's native gate treats rva==0 as a
	// bodyless/native method. Map the sentinel rva back to file offset 0.
	mb, err := ReadMethodBody(bytes.NewReader(body), func(rva uint32) (int, bool) { return int(rva) - 0x2000, true }, 0x2000, 0)
	if err != nil {
		t.Fatalf("ReadMethodBody: %v", err)
	}
	if len(mb.EH) != 1 {
		t.Fatalf("EH count = %d, want 1", len(mb.EH))
	}
	got := mb.EH[0]
	if got.TryLength != 2 || got.HandlerOffset != 2 || got.HandlerLength != 3 || got.ClassTokenOrFilter != 0x01000005 {
		t.Errorf("EH clause = %+v, want try-len 2 handler@2 len3 class 0x01000005", got)
	}
}

func TestReadEH_FatSection24Bit(t *testing.T) {
	// Fat EH header: kind=0x41 (EHTable|FatFormat), DataSize is 24-bit (3 bytes).
	// One fat clause = 24 bytes. Section total = 4 + 24 = 28.
	clause := make([]byte, 24)
	// Flags(uint32)=0, TryOffset(uint32)=1, TryLength(uint32)=2,
	// HandlerOffset(uint32)=3, HandlerLength(uint32)=4, ClassToken(uint32)=0x02000006.
	put32 := func(off int, v uint32) {
		clause[off] = byte(v)
		clause[off+1] = byte(v >> 8)
		clause[off+2] = byte(v >> 16)
		clause[off+3] = byte(v >> 24)
	}
	put32(4, 1)
	put32(8, 2)
	put32(12, 3)
	put32(16, 4)
	put32(20, 0x02000006)
	section := []byte{0x41, 28, 0x00, 0x00} // kind=fat EHTable, DataSize=28 (24-bit LE)
	section = append(section, clause...)

	code := []byte{0x2A}
	body := fatBodyWithEH(t, code, section)
	// rva must be non-zero: ReadMethodBody's native gate treats rva==0 as a
	// bodyless/native method. Map the sentinel rva back to file offset 0.
	mb, err := ReadMethodBody(bytes.NewReader(body), func(rva uint32) (int, bool) { return int(rva) - 0x2000, true }, 0x2000, 0)
	if err != nil {
		t.Fatalf("ReadMethodBody fat EH: %v", err)
	}
	if len(mb.EH) != 1 {
		t.Fatalf("fat EH count = %d, want 1", len(mb.EH))
	}
	if mb.EH[0].TryOffset != 1 || mb.EH[0].ClassTokenOrFilter != 0x02000006 {
		t.Errorf("fat clause = %+v, want try@1 class 0x02000006", mb.EH[0])
	}
	// Flags==0 (typed catch) → ClassTokenOrFilter is a class token, not a filter offset.
	if mb.EH[0].IsFilter() {
		t.Errorf("typed-catch clause reported IsFilter()=true; ClassTokenOrFilter must be a class token")
	}
}

func TestReadEH_FatSectionFilterUnion(t *testing.T) {
	// A fat clause with Flags=COR_ILEXCEPTION_CLAUSE_FILTER (0x0001): the union
	// field is a filter offset, NOT a class token. Same layout as the typed-catch
	// fixture above but Flags=1 and ClassTokenOrFilter holds a code offset (0x12).
	clause := make([]byte, 24)
	put32 := func(off int, v uint32) {
		clause[off] = byte(v)
		clause[off+1] = byte(v >> 8)
		clause[off+2] = byte(v >> 16)
		clause[off+3] = byte(v >> 24)
	}
	put32(0, ehFlagFilter) // Flags = 0x0001 (filter)
	put32(4, 1)            // TryOffset
	put32(8, 2)            // TryLength
	put32(12, 3)           // HandlerOffset
	put32(16, 4)           // HandlerLength
	put32(20, 0x12)        // FilterOffset (a code offset, not a token)
	section := []byte{0x41, 28, 0x00, 0x00}
	section = append(section, clause...)

	body := fatBodyWithEH(t, []byte{0x2A}, section)
	// rva must be non-zero: ReadMethodBody's native gate treats rva==0 as a
	// bodyless/native method. Map the sentinel rva back to file offset 0.
	mb, err := ReadMethodBody(bytes.NewReader(body), func(rva uint32) (int, bool) { return int(rva) - 0x2000, true }, 0x2000, 0)
	if err != nil {
		t.Fatalf("ReadMethodBody filter EH: %v", err)
	}
	if len(mb.EH) != 1 {
		t.Fatalf("filter EH count = %d, want 1", len(mb.EH))
	}
	got := mb.EH[0]
	// Discriminate the union by Flags: FILTER set → ClassTokenOrFilter is a filter offset.
	if !got.IsFilter() {
		t.Fatalf("clause Flags=%#x: IsFilter()=false, want true", got.Flags)
	}
	if got.ClassTokenOrFilter != 0x12 {
		t.Errorf("filter clause ClassTokenOrFilter = %#x, want filter offset 0x12", got.ClassTokenOrFilter)
	}
}
