/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// synthPE writes a minimal PE32+ binary at path. When managed=true, the
// COM Descriptor data directory entry (index 14) is set non-zero, so
// IsManagedPE returns true. When managed=false, the entry is zeroed.
//
// This is intentionally hand-rolled (not via debug/pe — Go stdlib only
// reads PE) and produces the smallest layout that passes pe.Open + the
// optional-header DataDirectory check.
func synthPE(t *testing.T, path string, managed bool) {
	t.Helper()

	const (
		dosStubSize    = 0x80
		ntHeaderOffset = 0x80
		numSections    = 1
	)

	buf := make([]byte, 0x400)

	// DOS header: "MZ" at 0, e_lfanew at 0x3c.
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3c:], ntHeaderOffset)

	// PE signature.
	copy(buf[ntHeaderOffset:], []byte{'P', 'E', 0, 0})

	// IMAGE_FILE_HEADER (20 bytes) at ntHeaderOffset+4.
	fh := buf[ntHeaderOffset+4:]
	binary.LittleEndian.PutUint16(fh[0:], 0x8664) // Machine = AMD64
	binary.LittleEndian.PutUint16(fh[2:], numSections)
	binary.LittleEndian.PutUint32(fh[4:], 0)       // TimeDateStamp
	binary.LittleEndian.PutUint32(fh[8:], 0)       // PointerToSymbolTable
	binary.LittleEndian.PutUint32(fh[12:], 0)      // NumberOfSymbols
	binary.LittleEndian.PutUint16(fh[16:], 240)    // SizeOfOptionalHeader (PE32+ standard)
	binary.LittleEndian.PutUint16(fh[18:], 0x0022) // Characteristics

	// IMAGE_OPTIONAL_HEADER64 starts at ntHeaderOffset+24.
	oh := buf[ntHeaderOffset+24:]
	binary.LittleEndian.PutUint16(oh[0:], 0x20b) // Magic = PE32+
	// Pad standard fields; we only need MagicGood + DataDirectory[14].
	// PE32+ optional header layout: NumberOfRvaAndSizes is at offset 108;
	// DataDirectory follows at offset 112 (16 entries × 8 bytes = 128 bytes,
	// total optional-header size = 240 bytes).
	binary.LittleEndian.PutUint32(oh[108:], 16) // NumberOfRvaAndSizes
	dd := oh[112:]
	if managed {
		// Entry 14 = COM Descriptor.
		binary.LittleEndian.PutUint32(dd[14*8:], 0x2000) // VirtualAddress
		binary.LittleEndian.PutUint32(dd[14*8+4:], 0x48) // Size
	}

	// Section header (40 bytes) at ntHeaderOffset+24+240.
	sh := buf[ntHeaderOffset+24+240:]
	copy(sh[0:8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sh[8:], 0x10)    // VirtualSize
	binary.LittleEndian.PutUint32(sh[12:], 0x1000) // VirtualAddress
	binary.LittleEndian.PutUint32(sh[16:], 0x200)  // SizeOfRawData
	binary.LittleEndian.PutUint32(sh[20:], 0x200)  // PointerToRawData
	binary.LittleEndian.PutUint32(sh[36:], 0x60000020)

	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestIsManagedPE(t *testing.T) {
	dir := t.TempDir()

	managed := filepath.Join(dir, "minimal_managed.dll")
	unmanaged := filepath.Join(dir, "unmanaged.bin")
	synthPE(t, managed, true)
	synthPE(t, unmanaged, false)

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"managed PE returns true", managed, true},
		{"unmanaged PE returns false", unmanaged, false},
		{"nonexistent path returns false (no panic)", filepath.Join(dir, "does-not-exist.dll"), false},
		{"empty path returns false", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsManagedPE(tt.path)
			if got != tt.want {
				t.Errorf("IsManagedPE(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsManagedPE_CorruptRecovers(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.bin")
	// Write garbage that's not a valid PE.
	if err := os.WriteFile(corrupt, []byte("not a PE file at all"), 0o644); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}

	if got := IsManagedPE(corrupt); got {
		t.Errorf("IsManagedPE(corrupt) = true, want false")
	}
}
