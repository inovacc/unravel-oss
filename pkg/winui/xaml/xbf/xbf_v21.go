/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf16"
)

// IsWAS16XBF reports whether data carries the on-disk header signature used by
// WindowsAppSDK 1.6.x XBF v2.1 files (as produced by recent Microsoft.UI.Xaml
// tooling). The format differs from the synthetic v2.1 layout produced by
// newXBFBuilder used in this package's unit tests:
//
//	Real WAS-1.6 v2.1 header layout:
//	  0x00  4B   magic   "XBF\0"
//	  0x04  u32  node-stream-offset (start of opcode stream)
//	  0x08  u32  scratch / metadata-tail offset
//	  0x0C  u32  major  (= 2)
//	  0x10  u32  minor  (= 1)
//	  0x14  u32  fixed header tail length (= 0x78 = 120)
//	  0x18  u32  reserved (= 0)
//	  0x1C  5*u64  section table (offsets, mostly empty / 4 B placeholder regions)
//	  0x44  64B  ASCII SHA-256 hex digest of payload
//	  0x84  ...  string table:
//	             [u32 count]
//	             count * { [u32 char_count][char_count*2 UTF-16LE chars][u16 NUL] }
//
// The legacy compact layout used by this package's synthetic fixtures keeps
// version as two u16 fields immediately after the magic and uses a 7-region
// table-of-contents inside the first 64 header bytes; that path stays handled
// by ParseHeader. IsWAS16XBF is the gate that lets DecodeXBFBytes pick the
// right path.
func IsWAS16XBF(data []byte) bool {
	if len(data) < 0x84 {
		return false
	}
	if data[0] != 'X' || data[1] != 'B' || data[2] != 'F' || data[3] != 0x00 {
		return false
	}
	major := binary.LittleEndian.Uint32(data[0x0C:0x10])
	minor := binary.LittleEndian.Uint32(data[0x10:0x14])
	tail := binary.LittleEndian.Uint32(data[0x14:0x18])
	rsv := binary.LittleEndian.Uint32(data[0x18:0x1C])
	return major == 2 && minor == 1 && tail == 0x78 && rsv == 0
}

// IsXBFv3 reports whether data carries the "XBF\0" magic and a v3+ major
// version at offset 0x0C (matching the WAS-1.6 v2.1 layout where major+minor
// live at 0x0C/0x10 — see IsWAS16XBF). Phase 20 (XBF-V3-01): detect-only
// forward-compat. Real v3 decoder deferred to v2.4 when production targets
// ship XBF v3.
func IsXBFv3(data []byte) bool {
	if len(data) < 0x14 {
		return false
	}
	if data[0] != 'X' || data[1] != 'B' || data[2] != 'F' || data[3] != 0x00 {
		return false
	}
	major := binary.LittleEndian.Uint32(data[0x0C:0x10])
	return major >= 3
}

// XBFv3MinorHint returns "<major>.<minor>" reading major at 0x0C and minor
// at 0x10 when the slice covers both, else degrades gracefully.
func XBFv3MinorHint(data []byte) string {
	if len(data) < 0x10 {
		return "3.unknown"
	}
	major := binary.LittleEndian.Uint32(data[0x0C:0x10])
	if len(data) < 0x14 {
		return fmt.Sprintf("%d.unknown", major)
	}
	minor := binary.LittleEndian.Uint32(data[0x10:0x14])
	return fmt.Sprintf("%d.%d", major, minor)
}

// V21Header holds the fields decoded from the WAS-1.6 v2.1 header that are
// useful to downstream stages.
type V21Header struct {
	NodeStreamOffset   uint32
	MetadataTailOffset uint32
	Major              uint32
	Minor              uint32
	HeaderTailLen      uint32
	Sections           [5]uint64
	HashDigestHex      string
	StringTableOffset  uint32 // always 0x84
}

// decodeV21Header parses the fixed-shape WAS-1.6 v2.1 header. Bounds checks
// are conservative; any failure returns an error so the top-level decoder can
// emit a graceful raw-bytes fallback entry.
func decodeV21Header(data []byte) (*V21Header, error) {
	if len(data) < 0x84 {
		return nil, fmt.Errorf("xbf v21 truncated: need at least 132 bytes for header, have %d", len(data))
	}
	h := &V21Header{
		NodeStreamOffset:   binary.LittleEndian.Uint32(data[0x04:0x08]),
		MetadataTailOffset: binary.LittleEndian.Uint32(data[0x08:0x0C]),
		Major:              binary.LittleEndian.Uint32(data[0x0C:0x10]),
		Minor:              binary.LittleEndian.Uint32(data[0x10:0x14]),
		HeaderTailLen:      binary.LittleEndian.Uint32(data[0x14:0x18]),
		StringTableOffset:  0x84,
	}
	for i := range 5 {
		off := 0x1C + i*8
		h.Sections[i] = binary.LittleEndian.Uint64(data[off : off+8])
	}
	h.HashDigestHex = string(data[0x44:0x84])
	if h.NodeStreamOffset > uint32(len(data)) {
		return nil, fmt.Errorf("xbf v21 header invalid: node-stream offset %d > file size %d", h.NodeStreamOffset, len(data))
	}
	return h, nil
}

// V21StringTable is the parsed string pool of a WAS-1.6 v2.1 XBF.
type V21StringTable struct {
	Count   uint32
	Strings []string
	// EndOffset is the byte offset immediately after the last string's NUL.
	EndOffset uint32
}

// decodeV21StringTable reads the string table that begins at offset 0x84.
// Each string is encoded as:
//
//	[u32 char_count][char_count * 2 bytes UTF-16LE][u16 NUL]
//
// The NUL terminator is mandated by observation across all 3 fixtures; treat
// any deviation as a soft error and stop early — the partial decode is still
// useful.
func decodeV21StringTable(data []byte, off uint32) (*V21StringTable, error) {
	if uint64(off)+4 > uint64(len(data)) {
		return nil, fmt.Errorf("xbf v21 string table: count out of bounds at offset %d", off)
	}
	t := &V21StringTable{}
	t.Count = binary.LittleEndian.Uint32(data[off : off+4])
	if t.Count > uint32(MaxTableEntries) {
		return nil, fmt.Errorf("xbf v21 string table: count %d exceeds limit %d", t.Count, MaxTableEntries)
	}
	p := uint64(off) + 4
	t.Strings = make([]string, 0, t.Count)
	for i := uint32(0); i < t.Count; i++ {
		if p+4 > uint64(len(data)) {
			return t, fmt.Errorf("xbf v21 string table: header for entry %d out of bounds", i)
		}
		slen := binary.LittleEndian.Uint32(data[p : p+4])
		p += 4
		if slen > 4096 {
			return t, fmt.Errorf("xbf v21 string table: entry %d length %d exceeds sanity limit", i, slen)
		}
		need := uint64(slen) * 2
		if p+need > uint64(len(data)) {
			return t, fmt.Errorf("xbf v21 string table: entry %d body needs %d bytes, only %d remain", i, need, uint64(len(data))-p)
		}
		u := make([]uint16, slen)
		for j := range slen {
			u[j] = binary.LittleEndian.Uint16(data[p+uint64(j)*2 : p+uint64(j)*2+2])
		}
		t.Strings = append(t.Strings, string(utf16.Decode(u)))
		p += need
		// NUL terminator (u16). Tolerate missing on the final string.
		if p+2 <= uint64(len(data)) {
			p += 2
		}
	}
	t.EndOffset = uint32(p)
	return t, nil
}

// DecodeWAS16V21 is the public entry-point for decoding a WindowsAppSDK 1.6.x
// XBF v2.1 byte slice. It avoids the ParseHeader / ParseTables path because
// the on-disk layout differs from this package's synthetic fixtures. The
// result reports the decoded string pool plus header metadata; callers route
// these into a winui.XAMLEntry via ToWAS16XAMLEntry.
//
// The decoder explicitly does NOT attempt to walk the opcode stream — that
// requires an opcode-table mapping that is still being reverse-engineered.
// The string table alone carries every XAML element name, control type,
// resource key, and brand token (verified against 3 real-world WhatsApp
// fixtures), which is sufficient to surface "xaml_text" content downstream
// without false errors.
func DecodeWAS16V21(data []byte) (*WAS16Result, error) {
	hdr, err := decodeV21Header(data)
	if err != nil {
		return nil, err
	}
	st, err := decodeV21StringTable(data, hdr.StringTableOffset)
	// st is non-nil even on partial decode; keep what we have.
	out := &WAS16Result{
		Header:    hdr,
		Strings:   nil,
		Recovered: "",
	}
	if st != nil {
		out.Strings = st.Strings
	}
	if err != nil {
		// Soft-fail: bubble up the partial result so callers can decide
		// whether to emit kind="xbf" with warnings or fall back to xbf-raw.
		out.Warnings = append(out.Warnings, err.Error())
	}
	out.Recovered = renderWAS16XAML(out.Strings, hdr)
	return out, nil
}

// WAS16Result is the decoded form of a WAS-1.6 v2.1 XBF.
type WAS16Result struct {
	Header    *V21Header
	Strings   []string
	Recovered string
	Warnings  []string
}

// renderWAS16XAML produces a best-effort XAML-shaped placeholder containing
// every recovered string literal as a comment block plus the header version.
// This is consumed by callers that wire the result into XAMLEntry.Recovered;
// the goal is to expose the contents to grep/search tooling without claiming
// a fully-reconstructed XAML AST.
func renderWAS16XAML(strs []string, hdr *V21Header) string {
	if len(strs) == 0 {
		return ""
	}
	out := make([]byte, 0, 256+len(strs)*32)
	out = append(out, fmt.Appendf(nil, "<!-- xbf v%d.%d (WindowsAppSDK 1.6.x) string-pool size=%d -->\n", hdr.Major, hdr.Minor, len(strs))...)
	out = append(out, []byte("<XBFStringPool>\n")...)
	for _, s := range strs {
		// Skip empty / pure whitespace.
		if s == "" {
			continue
		}
		out = append(out, []byte("  <s>")...)
		// Escape minimal XML entities to keep the output well-formed.
		for _, r := range s {
			switch r {
			case '<':
				out = append(out, []byte("&lt;")...)
			case '>':
				out = append(out, []byte("&gt;")...)
			case '&':
				out = append(out, []byte("&amp;")...)
			default:
				out = append(out, []byte(string(r))...)
			}
		}
		out = append(out, []byte("</s>\n")...)
	}
	out = append(out, []byte("</XBFStringPool>\n")...)
	return string(out)
}

// rawHexPrefix returns the hex of the first up-to-n bytes of data.
func rawHexPrefix(data []byte, n int) string {
	if len(data) < n {
		n = len(data)
	}
	return hex.EncodeToString(data[:n])
}
