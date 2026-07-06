/*
Copyright (c) 2026 Security Research
*/
package metadata

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	bsjbSignature   = 0x424A5342
	heapSizeStrings = 0x01
	heapSizeGUID    = 0x02
	heapSizeBlob    = 0x04
	maxTableID      = 0x2D
)

// ErrENCStream rejects the uncompressed Edit-and-Continue "#-" table stream.
var ErrENCStream = errors.New("uncompressed #- stream unsupported")

// ErrIndirectionTablesUnsupported rejects metadata that uses *Ptr indirection.
var ErrIndirectionTablesUnsupported = errors.New("metadata indirection (*Ptr) tables unsupported")

// stream is one entry in the metadata stream-header list.
type stream struct {
	name string
	data []byte
}

// root holds the parsed BSJB root: the located streams keyed by name.
type root struct {
	streams map[string]stream
}

// parseRoot decodes the BSJB metadata root header (II.24.2.1) and slices out
// each stream body from meta by its offset+size.
func parseRoot(meta []byte) (*root, error) {
	if len(meta) < 20 {
		return nil, fmt.Errorf("metadata too small: %d bytes", len(meta))
	}
	if binary.LittleEndian.Uint32(meta) != bsjbSignature {
		return nil, fmt.Errorf("bad BSJB signature %#x", binary.LittleEndian.Uint32(meta))
	}
	verLen := binary.LittleEndian.Uint32(meta[12:])
	p := 16 + int(verLen)
	if verLen > uint32(len(meta)) || p+4 > len(meta) {
		return nil, fmt.Errorf("metadata version length %d out of range", verLen)
	}
	p += 2 // Flags
	nStreams := binary.LittleEndian.Uint16(meta[p:])
	p += 2

	r := &root{streams: make(map[string]stream, nStreams)}
	for i := 0; i < int(nStreams); i++ {
		if p+8 > len(meta) {
			return nil, fmt.Errorf("truncated stream header %d", i)
		}
		off := binary.LittleEndian.Uint32(meta[p:])
		size := binary.LittleEndian.Uint32(meta[p+4:])
		p += 8
		name, n, err := readStreamName(meta[p:])
		if err != nil {
			return nil, fmt.Errorf("stream header %d: %w", i, err)
		}
		p += n
		end := uint64(off) + uint64(size)
		if uint64(off) > uint64(len(meta)) || end > uint64(len(meta)) {
			return nil, fmt.Errorf("stream %q range [%d,%d) out of bounds", name, off, end)
		}
		r.streams[name] = stream{name: name, data: meta[off:end]}
	}
	return r, nil
}

// readStreamName reads a null-terminated, 4-byte-padded ASCII stream name.
func readStreamName(buf []byte) (string, int, error) {
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			name := string(buf[:i])
			pad := (i + 1 + 3) &^ 3
			if pad > len(buf) {
				return "", 0, fmt.Errorf("stream name padding overruns buffer")
			}
			return name, pad, nil
		}
	}
	return "", 0, fmt.Errorf("unterminated stream name")
}
