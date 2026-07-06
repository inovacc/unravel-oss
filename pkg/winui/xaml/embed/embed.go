/*
Copyright (c) 2026 Security Research
*/

package embed

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// EmbeddedResource is a single RT_RCDATA payload extracted from a PE.
type EmbeddedResource struct {
	ResourceID uint32
	Kind       string // "xml" | "xbf" | "unknown"
	Bytes      []byte
	Offset     int64 // file offset of payload (provenance)
}

// PE resource directory layout sizes (per Microsoft PE/COFF spec).
const (
	resourceDirHeaderSize = 16
	resourceDirEntrySize  = 8
	resourceDataEntrySize = 16
	maxResourceLevels     = 3 // Type -> Name -> Language
)

// ScanPE opens exePath, locates `.rsrc`, and returns every RT_RCDATA payload
// with a sniffed Kind. No resources is not an error — empty slice + nil err.
//
// Every offset/size read is bounds-checked against the section size; never
// panics regardless of input.
func ScanPE(exePath string) (out []EmbeddedResource, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("scan-pe panic: %v", r)
			out = nil
		}
	}()

	f, ferr := pe.Open(exePath)
	if ferr != nil {
		return nil, fmt.Errorf("pe open: %w", ferr)
	}
	defer func() { _ = f.Close() }()

	rsrc := f.Section(".rsrc")
	if rsrc == nil {
		return []EmbeddedResource{}, nil
	}
	data, derr := rsrc.Data()
	if derr != nil {
		return nil, fmt.Errorf("rsrc data: %w", derr)
	}
	if uint32(len(data)) < uint32(rsrc.VirtualSize) && rsrc.VirtualSize > 0 {
		// Some loaders truncate `.Data()` to physical size; we operate on what
		// we have and bound-check accordingly.
	}
	if len(data) < resourceDirHeaderSize {
		return nil, fmt.Errorf("rsrc section truncated: %d bytes", len(data))
	}

	sectionVA := uint32(rsrc.VirtualAddress)

	// Locate the RT_RCDATA Type entry at the top-level directory.
	typeEntries, terr := readDirEntries(data, 0)
	if terr != nil {
		return nil, terr
	}
	for _, te := range typeEntries {
		if te.nameIsString {
			continue
		}
		if te.id != RT_RCDATA {
			continue
		}
		if !te.isSubdir {
			continue
		}
		// Descend into Name level.
		nameEntries, nerr := readDirEntries(data, te.offset)
		if nerr != nil {
			return nil, nerr
		}
		for _, ne := range nameEntries {
			if !ne.isSubdir {
				continue
			}
			// Descend into Language level.
			langEntries, lerr := readDirEntries(data, ne.offset)
			if lerr != nil {
				return nil, lerr
			}
			for _, le := range langEntries {
				if le.isSubdir {
					continue
				}
				// Read IMAGE_RESOURCE_DATA_ENTRY.
				if int(le.offset)+resourceDataEntrySize > len(data) {
					return nil, fmt.Errorf("data entry out of bounds: off=%d size=%d", le.offset, len(data))
				}
				deRVA := binary.LittleEndian.Uint32(data[le.offset : le.offset+4])
				deSize := binary.LittleEndian.Uint32(data[le.offset+4 : le.offset+8])
				// Convert RVA to offset into rsrc-section data.
				if deRVA < sectionVA {
					return nil, fmt.Errorf("data RVA %d below section VA %d", deRVA, sectionVA)
				}
				localOff := deRVA - sectionVA
				// Bounds-check the slice we're about to take.
				if uint64(localOff)+uint64(deSize) > uint64(len(data)) {
					return nil, fmt.Errorf("resource size out of bounds: %d > %d", uint64(localOff)+uint64(deSize), len(data))
				}
				payload := make([]byte, deSize)
				copy(payload, data[localOff:uint64(localOff)+uint64(deSize)])
				kind := sniffKind(payload)
				out = append(out, EmbeddedResource{
					ResourceID: ne.id,
					Kind:       kind,
					Bytes:      payload,
					Offset:     int64(rsrc.Offset) + int64(localOff),
				})
			}
		}
	}
	return out, nil
}

type rsrcEntry struct {
	id           uint32
	nameIsString bool
	offset       uint32 // offset into section data; either subdir or data-entry depending on isSubdir
	isSubdir     bool
}

// readDirEntries parses an IMAGE_RESOURCE_DIRECTORY at off into the section.
func readDirEntries(data []byte, off uint32) ([]rsrcEntry, error) {
	if uint64(off)+uint64(resourceDirHeaderSize) > uint64(len(data)) {
		return nil, fmt.Errorf("rsrc dir out of bounds at %d", off)
	}
	namedCount := binary.LittleEndian.Uint16(data[off+12 : off+14])
	idCount := binary.LittleEndian.Uint16(data[off+14 : off+16])
	total := uint32(namedCount) + uint32(idCount)
	entriesOff := off + resourceDirHeaderSize
	end := uint64(entriesOff) + uint64(total)*uint64(resourceDirEntrySize)
	if end > uint64(len(data)) {
		return nil, fmt.Errorf("rsrc dir entries out of bounds: %d > %d", end, len(data))
	}
	out := make([]rsrcEntry, 0, total)
	for i := range total {
		base := entriesOff + i*resourceDirEntrySize
		nameOrID := binary.LittleEndian.Uint32(data[base : base+4])
		offsetFld := binary.LittleEndian.Uint32(data[base+4 : base+8])
		e := rsrcEntry{}
		e.nameIsString = (nameOrID & 0x80000000) != 0
		e.id = nameOrID & 0x7FFFFFFF
		e.isSubdir = (offsetFld & 0x80000000) != 0
		e.offset = offsetFld & 0x7FFFFFFF
		out = append(out, e)
	}
	return out, nil
}

func sniffKind(b []byte) string {
	if len(b) >= len(XBFMagic) && bytes.Equal(b[:len(XBFMagic)], XBFMagic) {
		return "xbf"
	}
	for _, p := range XMLProloguePrefixes {
		if len(b) >= len(p) && bytes.HasPrefix(b, p) {
			return "xml"
		}
	}
	// Tolerate UTF-8 BOM before XML prologue.
	if len(b) > 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		for _, p := range XMLProloguePrefixes {
			if len(b) >= 3+len(p) && bytes.HasPrefix(b[3:], p) {
				return "xml"
			}
		}
	}
	return "unknown"
}
