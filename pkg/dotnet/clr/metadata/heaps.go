/*
Copyright (c) 2026 Security Research
*/
package metadata

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Heaps holds the four ECMA-335 metadata heaps (II.24.2.2-4): #Strings, #US,
// #Blob, and #GUID. newHeaps locates the raw heap bodies from the BSJB root;
// the Strings/UserString/Blob/GUID methods read typed values out of them.
type Heaps struct {
	strings []byte // #Strings: null-terminated UTF-8, indexed by byte offset
	us      []byte // #US: user-string blobs, indexed by byte offset
	blob    []byte // #Blob: length-prefixed blobs, indexed by byte offset
	guid    []byte // #GUID: 16-byte records, 1-based index
}

// newHeaps slices the heap stream bodies out of the parsed BSJB root. Absent
// streams yield nil slices (a metadata region need not carry every heap).
func newHeaps(r *root) *Heaps {
	h := &Heaps{}
	if s, ok := r.streams["#Strings"]; ok {
		h.strings = s.data
	}
	if s, ok := r.streams["#US"]; ok {
		h.us = s.data
	}
	if s, ok := r.streams["#Blob"]; ok {
		h.blob = s.data
	}
	if s, ok := r.streams["#GUID"]; ok {
		h.guid = s.data
	}
	return h
}

// Strings returns the null-terminated UTF-8 string at idx in #Strings. An
// out-of-range idx yields the empty string.
func (h *Heaps) Strings(idx uint32) string {
	if int(idx) >= len(h.strings) {
		return ""
	}
	b := h.strings[idx:]
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// UserString returns the #US literal at idx (II.24.2.4): a compressed length
// prefix, then UTF-16LE bytes plus one trailing flag byte (stripped here).
func (h *Heaps) UserString(idx uint32) string {
	raw := readBlobAt(h.us, idx) // #US shares #Blob's length-prefix framing
	if len(raw) == 0 {
		return ""
	}
	body := raw[:len(raw)-1] // drop the trailing flag byte
	if len(body)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(body)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(body[i*2:])
	}
	return string(utf16Decode(u16))
}

// Blob returns the byte slice at idx in #Blob: a compressed-int length prefix
// followed by that many bytes.
func (h *Heaps) Blob(idx uint32) []byte { return readBlobAt(h.blob, idx) }

// allUserStrings walks #US from offset 1, decoding each compressed-length
// record and advancing past it, collecting every non-empty literal in heap
// order. It backs both Tables.UserStrings() and the M1 ldstr resolver.
func (h *Heaps) allUserStrings() []string {
	var out []string
	off := uint32(1) // #US always opens with a 0 byte at offset 0
	for int(off) < len(h.us) {
		n, adv, err := readCompressedUint(h.us[off:])
		if err != nil {
			break
		}
		recStart := off
		off += uint32(adv) + n
		if int(off) > len(h.us) {
			break
		}
		if s := h.UserString(recStart); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// GUID returns the 1-based 16-byte GUID at idx (0 => zero GUID).
func (h *Heaps) GUID(idx uint32) [16]byte {
	var g [16]byte
	if idx == 0 {
		return g
	}
	start := int(idx-1) * 16
	if start+16 > len(h.guid) {
		return g
	}
	copy(g[:], h.guid[start:start+16])
	return g
}

// readBlobAt reads a compressed-length-prefixed blob at off in heap. A malformed
// length prefix (ErrBadCompressedUint) yields nil rather than a partial slice.
func readBlobAt(heap []byte, off uint32) []byte {
	if int(off) >= len(heap) {
		return nil
	}
	n, adv, err := readCompressedUint(heap[off:])
	if err != nil {
		return nil
	}
	start := int(off) + adv
	end := start + int(n)
	if start > len(heap) || end > len(heap) {
		return nil
	}
	return heap[start:end]
}

// ErrBadCompressedUint marks a malformed or reserved ECMA-335 II.23.2
// compressed-integer length prefix (truncated buffer or an illegal 111x lead
// byte). Callers compare with errors.Is.
var ErrBadCompressedUint = errors.New("malformed compressed integer")

// readCompressedUint decodes an ECMA-335 II.23.2 compressed unsigned integer.
// Returns the value and the number of bytes consumed. It returns a non-nil
// error (wrapping ErrBadCompressedUint) on an empty/truncated buffer or on the
// reserved illegal lead-byte form (top three bits 111x, i.e. lead >= 0xE0).
func readCompressedUint(b []byte) (uint32, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("empty buffer: %w", ErrBadCompressedUint)
	}
	switch {
	case b[0]&0x80 == 0:
		return uint32(b[0]), 1, nil
	case b[0]&0xC0 == 0x80:
		if len(b) < 2 {
			return 0, 0, fmt.Errorf("truncated 2-byte form: %w", ErrBadCompressedUint)
		}
		return uint32(b[0]&0x3F)<<8 | uint32(b[1]), 2, nil
	case b[0]&0xE0 == 0xC0:
		if len(b) < 4 {
			return 0, 0, fmt.Errorf("truncated 4-byte form: %w", ErrBadCompressedUint)
		}
		return uint32(b[0]&0x1F)<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), 4, nil
	default:
		// Top three bits are 111x (lead byte >= 0xE0): reserved, illegal.
		return 0, 0, fmt.Errorf("reserved lead byte %#x: %w", b[0], ErrBadCompressedUint)
	}
}

func utf16Decode(u []uint16) []rune { return utf16.Decode(u) }
