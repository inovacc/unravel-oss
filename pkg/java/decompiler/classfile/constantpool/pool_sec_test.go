package constantpool

import (
	"encoding/binary"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// buildCPWithManyUTF8 builds a raw constant pool stream containing count entries,
// each a TagUTF8 with the given string length (filled with 'A').
// Returns the raw bytes and the constant_pool_count to pass to Read.
func buildCPWithManyUTF8(count int, strLen int) ([]byte, uint16) {
	var buf []byte
	for range count {
		buf = append(buf, byte(TagUTF8))
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(strLen))
		buf = append(buf, lenBuf...)
		buf = append(buf, make([]byte, strLen)...)
	}
	return buf, uint16(count + 1) // constant_pool_count = count+1
}

// TestCP_AggregateSizeLimit verifies that a pool whose UTF-8 entries sum to more
// than maxCPBytes is rejected rather than allocating ~4 GiB.
func TestCP_AggregateSizeLimit(t *testing.T) {
	// 1000 entries × 65535 bytes each = ~65 MiB, well over maxCPBytes (32 MiB).
	const entryCount = 1000
	const entryLen = 65535
	buf, cpCount := buildCPWithManyUTF8(entryCount, entryLen)

	r := reader.NewReader(buf)
	_, err := Read(r, cpCount)
	if err == nil {
		t.Fatal("expected error for aggregate CP size > maxCPBytes, got nil")
	}
}

// TestCP_SmallPool verifies a legitimate small constant pool parses without error.
func TestCP_SmallPool(t *testing.T) {
	const entryCount = 3
	const entryLen = 10
	buf, cpCount := buildCPWithManyUTF8(entryCount, entryLen)

	r := reader.NewReader(buf)
	pool, err := Read(r, cpCount)
	if err != nil {
		t.Fatalf("unexpected error for small pool: %v", err)
	}
	if pool.Count() != cpCount {
		t.Errorf("pool count: got %d want %d", pool.Count(), cpCount)
	}
}
