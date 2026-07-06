package manifest

import (
	"encoding/binary"
	"testing"
)

// buildSecStringPoolChunk constructs a minimal string pool chunk with the given stringCount.
// The chunk is just large enough to hold the offset table (but no actual strings).
func buildSecStringPoolChunk(stringCount int) []byte {
	// String pool header: type(2)+headerSize(2)+chunkSize(4)+stringCount(4)+styleCount(4)+flags(4)+stringsStart(4)+stylesStart(4) = 28 bytes
	offsetsSize := stringCount * 4
	chunkSize := 28 + offsetsSize
	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:], uint16(chunkStringPool))
	binary.LittleEndian.PutUint16(buf[2:], 28)                      // header size
	binary.LittleEndian.PutUint32(buf[4:], uint32(chunkSize))       // chunk size
	binary.LittleEndian.PutUint32(buf[8:], uint32(stringCount))     // stringCount
	binary.LittleEndian.PutUint32(buf[12:], 0)                      // styleCount
	binary.LittleEndian.PutUint32(buf[16:], 0)                      // flags (UTF-16)
	binary.LittleEndian.PutUint32(buf[20:], uint32(28+offsetsSize)) // stringsStart
	binary.LittleEndian.PutUint32(buf[24:], 0)                      // stylesStart
	return buf
}

// TestStringPool_HugeCountRejected verifies that a stringCount exceeding the cap
// is rejected rather than causing a multi-GB []int allocation.
func TestStringPool_HugeCountRejected(t *testing.T) {
	// Use a stringCount just above the 1<<17 limit.
	p := &axmlParser{}
	// Build a chunk that would pass the offset overflow check but violates the entry cap.
	// We set stringCount = maxStringPoolEntries+1 = 131073; the chunk must be at least
	// 28 + 131073*4 = 524320 bytes to pass the offset table check — skip that;
	// the cap check fires before the offset check.
	const bigCount = (1 << 17) + 1
	chunk := make([]byte, 28+bigCount*4)
	binary.LittleEndian.PutUint16(chunk[0:], uint16(chunkStringPool))
	binary.LittleEndian.PutUint16(chunk[2:], 28)
	binary.LittleEndian.PutUint32(chunk[4:], uint32(len(chunk)))
	binary.LittleEndian.PutUint32(chunk[8:], uint32(bigCount))
	binary.LittleEndian.PutUint32(chunk[20:], uint32(28+bigCount*4))

	err := p.parseStringPool(chunk)
	if err == nil {
		t.Fatal("expected error for stringCount > maxStringPoolEntries, got nil")
	}
}

// TestStringPool_LegitimateCount verifies that a normal-sized string pool parses.
func TestStringPool_LegitimateCount(t *testing.T) {
	p := &axmlParser{}
	// 3 UTF-8 strings
	const sc = 3
	chunk := buildSecStringPoolChunk(sc)
	// Set UTF-8 flag
	binary.LittleEndian.PutUint32(chunk[16:], 1<<8)
	err := p.parseStringPool(chunk)
	if err != nil {
		t.Fatalf("unexpected error for small string pool: %v", err)
	}
}

// TestParseElementStart_AttrStartOOB verifies that an attrStart beyond the chunk
// returns an error rather than silently producing an element with no attributes.
func TestParseElementStart_AttrStartOOB(t *testing.T) {
	p := &axmlParser{}
	headerSize := 16
	// Total chunk smaller than attrStart would require.
	chunk := make([]byte, headerSize+20)
	binary.LittleEndian.PutUint16(chunk[2:4], uint16(headerSize))
	// attrOffset = 0xFFFF → attrStart = headerSize + 0xFFFF >> chunk length
	binary.LittleEndian.PutUint16(chunk[headerSize+8:], 0xFFFF)
	// attrSize = 20 (valid)
	binary.LittleEndian.PutUint16(chunk[headerSize+10:], 20)
	// attrCount = 1
	binary.LittleEndian.PutUint16(chunk[headerSize+12:], 1)

	_, err := p.parseElementStart(chunk)
	if err == nil {
		t.Fatal("expected error for attrStart OOB, got nil")
	}
}

// TestParseElementStart_AttrSizeZero verifies that attrSize==0 is treated as an error.
func TestParseElementStart_AttrSizeZero(t *testing.T) {
	p := &axmlParser{}
	headerSize := 16
	chunk := make([]byte, headerSize+20)
	binary.LittleEndian.PutUint16(chunk[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint16(chunk[headerSize+8:], 0)  // attrOffset=0
	binary.LittleEndian.PutUint16(chunk[headerSize+10:], 0) // attrSize=0
	binary.LittleEndian.PutUint16(chunk[headerSize+12:], 1) // attrCount=1

	_, err := p.parseElementStart(chunk)
	if err == nil {
		t.Fatal("expected error for attrSize==0, got nil")
	}
}
