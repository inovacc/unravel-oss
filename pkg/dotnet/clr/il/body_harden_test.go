/*
Copyright (c) 2026 Security Research
*/
package il

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// TestReadFat_OversizedCodeSize feeds a fat method-body header whose codeSize is
// 0xFFFFFFFF (~4 GiB) while the file is tiny. The reader MUST reject it before
// allocating, returning errOversizedBody rather than OOM-killing the host.
// Finding #2.
func TestReadFat_OversizedCodeSize(t *testing.T) {
	hdr := make([]byte, 12)
	flagsAndSize := uint16(corILMethodFatFormat) | (uint16(3) << 12) // fat, 3 dwords
	hdr[0] = byte(flagsAndSize)
	hdr[1] = byte(flagsAndSize >> 8)
	hdr[2], hdr[3] = 0x08, 0x00                         // maxstack 8
	binary.LittleEndian.PutUint32(hdr[4:8], 0xFFFFFFFF) // codeSize ~4 GiB
	body := hdr                                         // no actual code bytes

	_, err := ReadMethodBody(bytes.NewReader(body),
		func(rva uint32) (int, bool) { return int(rva) - 0x2000, true }, 0x2000, 0)
	if err == nil {
		t.Fatalf("expected error for oversized codeSize, got nil")
	}
	if !errors.Is(err, errOversizedBody) {
		t.Fatalf("expected errOversizedBody, got %v", err)
	}
}

// TestReadEHSections_InfiniteLoopGuard crafts a fat body with the MoreSects flag
// set, followed by an EH section whose kind byte has corILMethodSectMoreSects
// (0x80) set and dataSize==0. Without a forward-progress guard, off += dataSize
// is a no-op and readEHSections spins forever. The reader MUST return promptly
// with an error. Finding #22.
func TestReadEHSections_InfiniteLoopGuard(t *testing.T) {
	hdr := make([]byte, 12)
	flagsAndSize := uint16(corILMethodFatFormat) | uint16(corILMethodMoreSects) | (uint16(3) << 12)
	hdr[0] = byte(flagsAndSize)
	hdr[1] = byte(flagsAndSize >> 8)
	hdr[2], hdr[3] = 0x08, 0x00 // maxstack 8
	code := []byte{0x2A}        // ret
	hdr[4] = byte(len(code))
	body := append(hdr, code...)
	for (len(body)-12)%4 != 0 {
		body = append(body, 0)
	}
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	// EH section header: kind = MoreSects only (no EHTable), dataSize = 0.
	body = append(body, byte(corILMethodSectMoreSects), 0x00, 0x00, 0x00)

	done := make(chan error, 1)
	go func() {
		_, err := ReadMethodBody(bytes.NewReader(body),
			func(rva uint32) (int, bool) { return int(rva) - 0x2000, true }, 0x2000, 0)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected error for zero-dataSize MoreSects chain, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("readEHSections did not terminate (infinite loop)")
	}
}
