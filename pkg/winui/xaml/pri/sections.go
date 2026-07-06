/*
Copyright (c) 2026 Security Research
*/

package pri

import (
	"encoding/binary"
	"fmt"
)

// SectionRef is a single entry from the section table-of-contents.
type SectionRef struct {
	Name   string `json:"name"`
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
}

// sectionTOCEntrySize is the on-disk size of a single TOC entry:
// 16 bytes section name + 4 bytes offset + 4 bytes size.
const sectionTOCEntrySize = 24

// ParseSections reads the section table-of-contents starting at the
// configured offset. Each entry is bounds-checked against the input
// length; out-of-bounds entries cause a wrapped error.
func ParseSections(data []byte, h *Header) ([]SectionRef, error) {
	if h == nil {
		return nil, fmt.Errorf("pri header nil")
	}
	if h.TocCount == 0 {
		return nil, nil
	}
	tocOff := h.TocOffset
	if tocOff == 0 {
		// Fallback: TOC immediately follows the header.
		tocOff = HeaderSize
	}
	end := uint64(tocOff) + uint64(h.TocCount)*uint64(sectionTOCEntrySize)
	if end > uint64(len(data)) {
		return nil, fmt.Errorf("pri toc out of bounds: end %d > %d", end, len(data))
	}
	out := make([]SectionRef, 0, h.TocCount)
	for i := uint32(0); i < h.TocCount; i++ {
		base := uint64(tocOff) + uint64(i)*uint64(sectionTOCEntrySize)
		nameRaw := data[base : base+16]
		off := binary.LittleEndian.Uint32(data[base+16 : base+20])
		size := binary.LittleEndian.Uint32(data[base+20 : base+24])
		// Bounds-check the section payload itself.
		if uint64(off)+uint64(size) > uint64(len(data)) {
			return nil, fmt.Errorf("section out of bounds: name=%q off=%d size=%d", trimNulls(nameRaw), off, size)
		}
		if uint64(size) > uint64(MaxFileSize) {
			return nil, fmt.Errorf("pri size exceeds limit: section %q size %d", trimNulls(nameRaw), size)
		}
		out = append(out, SectionRef{
			Name:   trimNulls(nameRaw),
			Offset: uint64(off),
			Size:   uint64(size),
		})
	}
	return out, nil
}

// trimNulls trims trailing NUL bytes (and ASCII spaces) from a fixed-
// width section name slice.
func trimNulls(b []byte) string {
	end := len(b)
	for end > 0 && (b[end-1] == 0 || b[end-1] == ' ') {
		end--
	}
	return string(b[:end])
}

// resolveByName walks a name-reference chain bounded by MaxSectionVisits.
// Returns the resolved SectionRef and a warning string when the cap is
// hit; never panics.
func resolveByName(refs []SectionRef, name string) (*SectionRef, string) {
	visited := make(map[string]struct{}, MaxSectionVisits)
	cur := name
	for range MaxSectionVisits {
		if _, dup := visited[cur]; dup {
			return nil, fmt.Sprintf("pri: circular section reference detected at %q", cur)
		}
		visited[cur] = struct{}{}
		for i := range refs {
			if refs[i].Name == cur {
				return &refs[i], ""
			}
		}
		// No match — bail.
		return nil, ""
	}
	return nil, fmt.Sprintf("pri: section resolution hop limit exceeded starting at %q", name)
}
