/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"encoding/binary"
	"fmt"
	"io"
)

// XBFMagic is the 4-byte XBF v2.x magic prefix.
var XBFMagic = [4]byte{'X', 'B', 'F', 0x00}

// MaxTableSize is the per-region size cap (16 MiB). T-04-04 mitigation.
const MaxTableSize = uint64(16 << 20)

// HeaderSize is the size in bytes of the on-disk XBF header (magic + version
// + 7 region descriptors).
const HeaderSize = 4 + 2 + 2 + 7*8

// Region describes a sub-section inside an XBF file.
type Region struct {
	Offset uint32
	Size   uint32
}

// End returns the (overflow-safe) byte index immediately after the region.
func (r Region) End() uint64 {
	return uint64(r.Offset) + uint64(r.Size)
}

// TableTOC enumerates the seven XBF v2.1 tables in declaration order.
type TableTOC struct {
	Strings        Region
	Assemblies     Region
	TypeNamespaces Region
	Types          Region
	Properties     Region
	XmlNamespaces  Region
	Events         Region
}

// Header is the parsed XBF v2.x file header.
type Header struct {
	Magic    [4]byte
	Major    uint16
	Minor    uint16
	TableTOC TableTOC
	// Warnings collects best-effort decode notices (unsupported version etc.)
	// so callers can surface them without aborting parsing.
	Warnings []string
}

// MaxRegionEnd returns the highest End()
// across every region in the TOC.
func (h *Header) MaxRegionEnd() uint32 {
	ends := []uint64{
		h.TableTOC.Strings.End(),
		h.TableTOC.Assemblies.End(),
		h.TableTOC.TypeNamespaces.End(),
		h.TableTOC.Types.End(),
		h.TableTOC.Properties.End(),
		h.TableTOC.XmlNamespaces.End(),
		h.TableTOC.Events.End(),
	}
	var max uint64
	for _, e := range ends {
		if e > max {
			max = e
		}
	}
	if max > 0xFFFFFFFF {
		return 0xFFFFFFFF
	}
	return uint32(max)
}

// regionsInOrder returns slice of TOC regions for iteration.
func (t *TableTOC) regionsInOrder() []Region {
	return []Region{t.Strings, t.Assemblies, t.TypeNamespaces, t.Types, t.Properties, t.XmlNamespaces, t.Events}
}

// ParseHeader reads and validates an XBF header. Returns wrapped error for
// malformed input; never panics.
func ParseHeader(r io.ReadSeeker) (*Header, error) {
	// Determine file size first (for bounds-checks).
	fileSize, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seek end: %w", err)
	}
	if fileSize < int64(HeaderSize) {
		return nil, fmt.Errorf("xbf truncated: file size %d < header size %d", fileSize, HeaderSize)
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek start: %w", err)
	}

	buf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	h := &Header{}
	copy(h.Magic[:], buf[0:4])

	// Magic check: byte-for-byte (NOT string compare).
	for i := range 4 {
		if h.Magic[i] != XBFMagic[i] {
			return nil, fmt.Errorf("xbf magic mismatch: got %v, want %v", h.Magic, XBFMagic)
		}
	}

	h.Major = binary.LittleEndian.Uint16(buf[4:6])
	h.Minor = binary.LittleEndian.Uint16(buf[6:8])
	if h.Major != 2 {
		h.Warnings = append(h.Warnings, fmt.Sprintf("unsupported XBF major version %d.%d (expected 2.x)", h.Major, h.Minor))
	}

	// Parse 7 regions.
	off := 8
	regions := make([]*Region, 7)
	regions[0] = &h.TableTOC.Strings
	regions[1] = &h.TableTOC.Assemblies
	regions[2] = &h.TableTOC.TypeNamespaces
	regions[3] = &h.TableTOC.Types
	regions[4] = &h.TableTOC.Properties
	regions[5] = &h.TableTOC.XmlNamespaces
	regions[6] = &h.TableTOC.Events
	for i := range 7 {
		regions[i].Offset = binary.LittleEndian.Uint32(buf[off : off+4])
		regions[i].Size = binary.LittleEndian.Uint32(buf[off+4 : off+8])
		off += 8
	}

	// Validate regions: uint64 arithmetic to detect overflow; per-region cap;
	// in-bounds against fileSize.
	tableNames := []string{"Strings", "Assemblies", "TypeNamespaces", "Types", "Properties", "XmlNamespaces", "Events"}
	for i, reg := range regions {
		if reg.Size == 0 {
			continue // empty region is allowed
		}
		end := uint64(reg.Offset) + uint64(reg.Size)
		// Overflow detection: if either operand fits in uint32 but their sum
		// exceeds uint32 max, we treat that as out-of-bounds.
		if end < uint64(reg.Offset) || end < uint64(reg.Size) {
			return nil, fmt.Errorf("table region %s offset+size overflow: offset=%d size=%d", tableNames[i], reg.Offset, reg.Size)
		}
		if uint64(reg.Size) > MaxTableSize {
			return nil, fmt.Errorf("table region %s size exceeds limit: size=%d cap=%d", tableNames[i], reg.Size, MaxTableSize)
		}
		if end > uint64(fileSize) {
			return nil, fmt.Errorf("table region %s out of bounds: end=%d file=%d", tableNames[i], end, fileSize)
		}
	}

	return h, nil
}
