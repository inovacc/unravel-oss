/*
Copyright (c) 2026 Security Research
*/

package pri

import (
	"encoding/binary"
	"fmt"
)

// HeaderSize is the fixed size of the PRI header preamble.
const HeaderSize = 32

// MagicLen is the byte length of the PRI magic string.
const MagicLen = 8

// Recognised magic strings. PriTools observes these three primary
// variants; unknown but plausibly-prefixed magics fall through to the
// "unsupported magic" error path.
var (
	magicPri0 = []byte("mrm_pri0")
	magicPri1 = []byte("mrm_pri1")
	magicPri2 = []byte("mrm_pri2")
)

// Header captures the parsed PRI header fields. The layout is loose by
// design — different PRI versions reuse the same header preamble with
// minor field-meaning drift; downstream code reads the magic and adapts.
type Header struct {
	Magic        string // "mrm_pri0" | "mrm_pri1" | "mrm_pri2"
	Version      uint32
	TotalSize    uint64
	TocOffset    uint32
	TocCount     uint32
	SectionStart uint32 // Offset where the section data begins
	Warnings     []string
}

// ParseHeader validates a PRI header from a byte slice. Returns a
// wrapped error on magic mismatch, truncation, or a declared total size
// that exceeds MaxFileSize.
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("pri truncated: %d bytes < header size %d", len(data), HeaderSize)
	}

	magic := data[:MagicLen]
	if !isKnownMagic(magic) {
		return nil, fmt.Errorf("pri magic mismatch: got %q", string(magic))
	}

	h := &Header{
		Magic: string(magic),
	}

	// Version: 4 bytes after magic.
	h.Version = binary.LittleEndian.Uint32(data[8:12])
	// TotalSize: 8 bytes (u64) at offset 12.
	h.TotalSize = binary.LittleEndian.Uint64(data[12:20])
	// TocOffset / TocCount / SectionStart: 4 bytes each at 20, 24, 28.
	h.TocOffset = binary.LittleEndian.Uint32(data[20:24])
	h.TocCount = binary.LittleEndian.Uint32(data[24:28])
	h.SectionStart = binary.LittleEndian.Uint32(data[28:32])

	if h.TotalSize > uint64(MaxFileSize) {
		return nil, fmt.Errorf("pri size exceeds limit: %d > %d", h.TotalSize, MaxFileSize)
	}
	// If the declared size disagrees with len(data), warn but continue —
	// some PRIs are bundled with extra trailing data.
	if h.TotalSize > 0 && h.TotalSize > uint64(len(data)) {
		h.Warnings = append(h.Warnings, fmt.Sprintf("declared total size %d > available %d", h.TotalSize, len(data)))
	}

	return h, nil
}

// isKnownMagic reports whether m matches one of the recognised PRI
// magic byte sequences.
func isKnownMagic(m []byte) bool {
	if len(m) < MagicLen {
		return false
	}
	switch {
	case eqBytes(m, magicPri0),
		eqBytes(m, magicPri1),
		eqBytes(m, magicPri2):
		return true
	}
	return false
}

func eqBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
