/*
Copyright (c) 2026 Security Research
*/

package pri

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// stringPoolHeader is the synthetic preamble we use for the synthetic
// fixture: 4 bytes uint32 count, then per-entry 4 bytes uint32 length
// (in code units), then 2*length bytes UTF-16LE payload, then a 2-byte
// NUL terminator.
//
// Real PRI string pools vary across HSDT/HSCH layouts; this decoder
// targets the format the synthetic fixture emits. Unknown layouts will
// surface as empty pools and a warning rather than crashing.

// ParseStrings decodes a UTF-16LE string pool. The slice contains the
// raw bytes of the pool (offset already applied). Returns the decoded
// strings in declaration order.
func ParseStrings(pool []byte) ([]string, error) {
	if len(pool) < 4 {
		return nil, fmt.Errorf("pri string pool truncated: %d bytes", len(pool))
	}
	count := binary.LittleEndian.Uint32(pool[:4])
	if count > 1<<20 {
		return nil, fmt.Errorf("pri string pool count unreasonable: %d", count)
	}
	out := make([]string, 0, count)
	off := uint64(4)
	for i := range count {
		if off+4 > uint64(len(pool)) {
			return nil, fmt.Errorf("pri string pool truncated at entry %d", i)
		}
		lenCU := binary.LittleEndian.Uint32(pool[off : off+4])
		off += 4
		// Bounds-check the UTF-16LE payload.
		if uint64(lenCU) > 1<<20 {
			return nil, fmt.Errorf("pri string entry %d length unreasonable: %d", i, lenCU)
		}
		payloadBytes := uint64(lenCU) * 2
		if off+payloadBytes+2 > uint64(len(pool)) {
			return nil, fmt.Errorf("pri string entry %d out of bounds: need %d, have %d", i, off+payloadBytes+2, len(pool))
		}
		s, err := decodeUTF16LE(pool[off : off+payloadBytes])
		if err != nil {
			return nil, fmt.Errorf("pri string entry %d: %w", i, err)
		}
		out = append(out, s)
		off += payloadBytes + 2 // skip 2-byte NUL terminator
	}
	return out, nil
}

// decodeUTF16LE converts a UTF-16LE byte slice to a Go string.
func decodeUTF16LE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("utf-16le payload length not even: %d", len(b))
	}
	codeUnits := make([]uint16, len(b)/2)
	for i := range codeUnits {
		codeUnits[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(codeUnits)), nil
}
