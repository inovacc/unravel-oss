/*
Copyright (c) 2026 Security Research
*/
package resources

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// validARSCPrefix builds a valid resource-table header + minimal string pool.
// Callers append a crafted trailing chunk.
func validARSCPrefix() *bytes.Buffer {
	buf := new(bytes.Buffer)
	// Resource table header: type=0x0002, headerSize=12, totalSize (patched), packageCount=0.
	_ = binary.Write(buf, binary.LittleEndian, uint16(resTableType))
	_ = binary.Write(buf, binary.LittleEndian, uint16(12))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	// String pool chunk (header only).
	_ = binary.Write(buf, binary.LittleEndian, uint16(stringPoolType))
	_ = binary.Write(buf, binary.LittleEndian, uint16(28))
	_ = binary.Write(buf, binary.LittleEndian, uint32(28))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(28))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf
}

// TestParseARSC_OversizedPackageChunk crafts a package chunk (type 0x0200) whose
// chunkSize is 0x7FFFFFFF while only a few real bytes follow. Without a bound
// check, data[offset:offset+chunkSize] slices out of range and panics. Finding #4.
func TestParseARSC_OversizedPackageChunk(t *testing.T) {
	buf := validARSCPrefix()
	// Package chunk header: type=0x0200, headerSize=8, chunkSize=0x7FFFFFFF.
	_ = binary.Write(buf, binary.LittleEndian, uint16(packageType))
	_ = binary.Write(buf, binary.LittleEndian, uint16(8))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x7FFFFFFF))
	data := buf.Bytes()
	binary.LittleEndian.PutUint32(data[4:], uint32(len(data)))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseARSC panicked on oversized package chunkSize: %v", r)
		}
	}()

	if _, _, _, err := ParseARSC(&bytesReaderAt{data: data}, int64(len(data))); err == nil {
		t.Fatalf("expected error for oversized package chunk, got nil")
	}
}

// TestParseARSC_ZeroSizeChunkNoInfiniteLoop crafts a non-package chunk with
// chunkSize=0. Without a forward-progress guard, offset += 0 spins forever.
// ParseARSC MUST terminate (with an error). Finding #4 / #9 hint.
func TestParseARSC_ZeroSizeChunkNoInfiniteLoop(t *testing.T) {
	buf := validARSCPrefix()
	// Non-package chunk (typeSpec 0x0201) with chunkSize=0, plus padding so the
	// loop guard offset+8 <= len(data) holds.
	_ = binary.Write(buf, binary.LittleEndian, uint16(0x0201))
	_ = binary.Write(buf, binary.LittleEndian, uint16(8))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // chunkSize = 0
	_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // trailing padding
	data := buf.Bytes()
	binary.LittleEndian.PutUint32(data[4:], uint32(len(data)))

	done := make(chan struct{})
	go func() {
		_, _, _, _ = ParseARSC(&bytesReaderAt{data: data}, int64(len(data)))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("ParseARSC did not terminate on zero-size chunk (infinite loop)")
	}
}
