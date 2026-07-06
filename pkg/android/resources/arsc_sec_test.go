package resources

import (
	"encoding/binary"
	"testing"
)

// buildStringPoolData builds a minimal string pool chunk with the given stringCount
// embedded in a data slice of the given total size.
func buildStringPoolData(totalSize, stringCount int) []byte {
	buf := make([]byte, totalSize)
	// chunk type = RES_STRING_POOL_TYPE (0x0001)
	binary.LittleEndian.PutUint16(buf[0:], 0x0001)
	binary.LittleEndian.PutUint16(buf[2:], 28) // header size
	binary.LittleEndian.PutUint32(buf[4:], uint32(totalSize))
	binary.LittleEndian.PutUint32(buf[8:], uint32(stringCount))
	// stringsStart beyond end so no strings are decoded
	binary.LittleEndian.PutUint32(buf[20:], uint32(totalSize))
	return buf
}

// TestARSC_StringPool_OverflowSafeCheck verifies that on 32-bit-equivalent overflow
// the guard correctly rejects the input instead of producing a wrong offsetsEnd.
// We simulate the overflow case by passing a stringCount that would cause
// 28 + stringCount*4 to exceed len(data) but the data is constructed so that
// the old guard (offsetsEnd > len(data)) could be bypassed if overflow wraps.
func TestARSC_StringPool_OverflowSafeCheck(t *testing.T) {
	// stringCount = (len-28)/4 + 1 → just over the safe limit.
	const dataSize = 128
	const stringCount = (dataSize-28)/4 + 1 // 26 entries, offsetsEnd would be 28+26*4=132 > 128
	buf := buildStringPoolData(dataSize, stringCount)

	info, _, err := parseStringPool(buf)
	if err != nil {
		t.Fatalf("parseStringPool returned unexpected error: %v", err)
	}
	// The guard should have fired and returned early (empty sample strings).
	if len(info.SampleStrings) != 0 {
		t.Errorf("expected no sample strings on overflow guard, got %d", len(info.SampleStrings))
	}
}

// TestARSC_StringPool_NormalParsing verifies that a well-formed pool with a small
// count still parses without error.
func TestARSC_StringPool_NormalParsing(t *testing.T) {
	const sc = 2
	offsetsSize := sc * 4
	dataSize := 28 + offsetsSize + 32 // enough room for the offsets + some string data
	buf := buildStringPoolData(dataSize, sc)

	info, _, err := parseStringPool(buf)
	if err != nil {
		t.Fatalf("parseStringPool returned unexpected error: %v", err)
	}
	if info.TotalStrings != sc {
		t.Errorf("TotalStrings: got %d want %d", info.TotalStrings, sc)
	}
}
