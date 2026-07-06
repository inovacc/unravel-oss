package leveldb

import (
	"encoding/binary"
	"testing"
)

// buildSecDataBlock builds a minimal LevelDB data block with one key entry.
// The restart array is appended at the end (1 restart at offset 0).
func buildSecDataBlock(shared, unshared uint64, keyData, valueData []byte) []byte {
	var buf []byte

	appendUvarint := func(v uint64) {
		b := make([]byte, 10)
		n := binary.PutUvarint(b, v)
		buf = append(buf, b[:n]...)
	}

	appendUvarint(shared)
	appendUvarint(unshared)
	appendUvarint(uint64(len(valueData)))
	buf = append(buf, keyData...)
	buf = append(buf, valueData...)

	// Restarts: 1 entry pointing to offset 0.
	restartBuf := make([]byte, 8) // 1 restart (4 bytes) + count (4 bytes)
	binary.LittleEndian.PutUint32(restartBuf[0:], 0)
	binary.LittleEndian.PutUint32(restartBuf[4:], 1)
	buf = append(buf, restartBuf...)
	return buf
}

// TestParseDataBlock_SharedOverflow verifies that shared+unshared summing to
// uint64 overflow (wrap to 0) is caught before make([]byte, 0).
func TestParseDataBlock_SharedOverflow(t *testing.T) {
	// shared = 2^63, unshared = 2^63 → sum wraps to 0.
	// We build a data block with these varint values; the guard should break early.
	// Since 2^63 > restartsStart, the first guard (shared > restartsStart) fires.
	var buf []byte
	appendUvarint := func(v uint64) {
		b := make([]byte, 10)
		n := binary.PutUvarint(b, v)
		buf = append(buf, b[:n]...)
	}

	const half = uint64(1) << 63
	appendUvarint(half) // shared
	appendUvarint(half) // unshared
	appendUvarint(0)    // valueLen

	// Restart table: count=1, restart at 0.
	restarts := make([]byte, 8)
	binary.LittleEndian.PutUint32(restarts[0:], 0)
	binary.LittleEndian.PutUint32(restarts[4:], 1)
	buf = append(buf, restarts...)

	pairs := parseDataBlock(buf)
	// Should return no pairs (guard fired), not panic.
	if len(pairs) != 0 {
		t.Errorf("expected 0 pairs for overflow input, got %d", len(pairs))
	}
}

// TestParseDataBlock_NormalEntry verifies a legitimate data block parses correctly.
func TestParseDataBlock_NormalEntry(t *testing.T) {
	key := []byte("hello")
	val := []byte("world")
	buf := buildSecDataBlock(0, uint64(len(key)), key, val)

	pairs := parseDataBlock(buf)
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if string(pairs[0].key) != "hello" {
		t.Errorf("key: got %q want %q", pairs[0].key, "hello")
	}
	if string(pairs[0].value) != "world" {
		t.Errorf("value: got %q want %q", pairs[0].value, "world")
	}
}

// buildBatchData builds a minimal batch payload with one record.
func buildBatchData(keyLen, valueLen uint64) []byte {
	buf := make([]byte, 12)                   // sequence(8) + count(4)
	binary.LittleEndian.PutUint64(buf[0:], 1) // sequence
	binary.LittleEndian.PutUint32(buf[8:], 1) // count=1

	appendUvarint := func(v uint64) {
		b := make([]byte, 10)
		n := binary.PutUvarint(b, v)
		buf = append(buf, b[:n]...)
	}

	buf = append(buf, ValueTypeValue) // value type
	appendUvarint(keyLen)
	if keyLen <= uint64(len(buf)) {
		buf = append(buf, make([]byte, keyLen)...)
	}
	appendUvarint(valueLen)
	if valueLen <= uint64(len(buf)) {
		buf = append(buf, make([]byte, valueLen)...)
	}
	return buf
}

// TestParseBatch_HugeKeyLen verifies that a keyLen > remaining data does not panic.
func TestParseBatch_HugeKeyLen(t *testing.T) {
	// Build a batch where the declared keyLen is much larger than actual data.
	// header: sequence(8) + count(4)
	var buf []byte
	hdr := make([]byte, 12)
	binary.LittleEndian.PutUint64(hdr[0:], 1)
	binary.LittleEndian.PutUint32(hdr[8:], 1)
	buf = append(buf, hdr...)
	buf = append(buf, ValueTypeValue)

	// Encode keyLen=0xFFFF as uvarint (3 bytes)
	uvarBuf := make([]byte, 10)
	n := binary.PutUvarint(uvarBuf, 0xFFFF)
	buf = append(buf, uvarBuf[:n]...)
	// No actual key bytes follow.

	result := &ParseResult{}
	parseBatch(buf, result)
	// Should not panic; ParseErrors should be incremented.
	if result.Stats.ParseErrors == 0 {
		t.Error("expected ParseErrors > 0 for truncated key, got 0")
	}
}

// TestParseBatch_HugeValueLen verifies that a valueLen > remaining data does not panic.
func TestParseBatch_HugeValueLen(t *testing.T) {
	const keyStr = "k"
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint64(buf[0:], 1)
	binary.LittleEndian.PutUint32(buf[8:], 1)

	appendUvarint := func(v uint64) {
		b := make([]byte, 10)
		n := binary.PutUvarint(b, v)
		buf = append(buf, b[:n]...)
	}

	buf = append(buf, ValueTypeValue)
	appendUvarint(uint64(len(keyStr)))
	buf = append(buf, []byte(keyStr)...)
	appendUvarint(0xFFFFFFFF) // huge value len
	// no actual value bytes follow

	result := &ParseResult{}
	parseBatch(buf, result)
	if result.Stats.ParseErrors == 0 {
		t.Error("expected ParseErrors > 0 for huge valueLen, got 0")
	}
}
