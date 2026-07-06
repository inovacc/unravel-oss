/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// MaxTableEntries is the per-table sanity cap on entry count. Documented;
// trips on garbage uint16 counts before any allocation occurs.
const MaxTableEntries = 65535

// AssemblyRef references an assembly by its name index in the Strings table.
type AssemblyRef struct {
	NameIdx uint16
}

// TypeNamespaceRef binds an assembly to a namespace name string.
type TypeNamespaceRef struct {
	AssemblyIdx uint16
	NameIdx     uint16
}

// TypeRef references a CLR/WinRT type.
type TypeRef struct {
	NamespaceIdx uint16
	NameIdx      uint16
}

// PropertyRef references a property on a type.
type PropertyRef struct {
	TypeIdx uint16
	NameIdx uint16
}

// XmlNamespaceRef references an XML namespace URI by string index.
type XmlNamespaceRef struct {
	NameIdx uint16
}

// EventRef references an event on a type.
type EventRef struct {
	TypeIdx uint16
	NameIdx uint16
}

// Tables is the parsed bundle of XBF metadata tables.
type Tables struct {
	Strings        []string
	Assemblies     []AssemblyRef
	TypeNamespaces []TypeNamespaceRef
	Types          []TypeRef
	Properties     []PropertyRef
	XmlNamespaces  []XmlNamespaceRef
	Events         []EventRef
	// Warnings: best-effort decode notices (OOB cross-references, etc.).
	Warnings []string
}

// String safely returns the string at idx, or a placeholder marker if idx is
// out of range.
func (t *Tables) String(idx int) string {
	if idx < 0 || idx >= len(t.Strings) {
		return fmt.Sprintf("<!-- xbf:string-oob:%d -->", idx)
	}
	return t.Strings[idx]
}

// TypeName returns the resolved fully-qualified-ish type name at idx; on OOB
// returns a placeholder.
func (t *Tables) TypeName(idx int) string {
	if idx < 0 || idx >= len(t.Types) {
		return fmt.Sprintf("<!-- xbf:type-oob:%d -->", idx)
	}
	return t.String(int(t.Types[idx].NameIdx))
}

// PropertyName returns the resolved property name at idx; on OOB placeholder.
func (t *Tables) PropertyName(idx int) string {
	if idx < 0 || idx >= len(t.Properties) {
		return fmt.Sprintf("<!-- xbf:prop-oob:%d -->", idx)
	}
	return t.String(int(t.Properties[idx].NameIdx))
}

// XmlNamespaceURI returns the resolved namespace URI at idx; on OOB placeholder.
func (t *Tables) XmlNamespaceURI(idx int) string {
	if idx < 0 || idx >= len(t.XmlNamespaces) {
		return fmt.Sprintf("<!-- xbf:xmlns-oob:%d -->", idx)
	}
	return t.String(int(t.XmlNamespaces[idx].NameIdx))
}

// ParseTables reads each TOC region and decodes its table contents.
func ParseTables(r io.ReadSeeker, h *Header) (*Tables, error) {
	t := &Tables{}

	// Strings.
	if h.TableTOC.Strings.Size > 0 {
		buf, err := readRegion(r, h.TableTOC.Strings)
		if err != nil {
			return nil, fmt.Errorf("read strings region: %w", err)
		}
		strs, err := parseStringTable(buf)
		if err != nil {
			return nil, err
		}
		t.Strings = strs
	}

	// Assemblies.
	if err := parseFixedTable(r, h.TableTOC.Assemblies, 2, "assemblies", func(b []byte) {
		t.Assemblies = append(t.Assemblies, AssemblyRef{NameIdx: binary.LittleEndian.Uint16(b)})
	}); err != nil {
		return nil, err
	}

	// TypeNamespaces.
	if err := parseFixedTable(r, h.TableTOC.TypeNamespaces, 4, "type-namespaces", func(b []byte) {
		t.TypeNamespaces = append(t.TypeNamespaces, TypeNamespaceRef{
			AssemblyIdx: binary.LittleEndian.Uint16(b[0:2]),
			NameIdx:     binary.LittleEndian.Uint16(b[2:4]),
		})
	}); err != nil {
		return nil, err
	}

	// Types.
	if err := parseFixedTable(r, h.TableTOC.Types, 4, "types", func(b []byte) {
		t.Types = append(t.Types, TypeRef{
			NamespaceIdx: binary.LittleEndian.Uint16(b[0:2]),
			NameIdx:      binary.LittleEndian.Uint16(b[2:4]),
		})
	}); err != nil {
		return nil, err
	}

	// Properties.
	if err := parseFixedTable(r, h.TableTOC.Properties, 4, "properties", func(b []byte) {
		t.Properties = append(t.Properties, PropertyRef{
			TypeIdx: binary.LittleEndian.Uint16(b[0:2]),
			NameIdx: binary.LittleEndian.Uint16(b[2:4]),
		})
	}); err != nil {
		return nil, err
	}

	// XmlNamespaces.
	if err := parseFixedTable(r, h.TableTOC.XmlNamespaces, 2, "xml-namespaces", func(b []byte) {
		t.XmlNamespaces = append(t.XmlNamespaces, XmlNamespaceRef{NameIdx: binary.LittleEndian.Uint16(b)})
	}); err != nil {
		return nil, err
	}

	// Events.
	if err := parseFixedTable(r, h.TableTOC.Events, 4, "events", func(b []byte) {
		t.Events = append(t.Events, EventRef{
			TypeIdx: binary.LittleEndian.Uint16(b[0:2]),
			NameIdx: binary.LittleEndian.Uint16(b[2:4]),
		})
	}); err != nil {
		return nil, err
	}

	// Cross-reference best-effort warnings (don't abort).
	for i, ref := range t.TypeNamespaces {
		if int(ref.AssemblyIdx) >= len(t.Assemblies) {
			t.Warnings = append(t.Warnings, fmt.Sprintf("type-namespace[%d] assembly idx %d out of range", i, ref.AssemblyIdx))
		}
		if int(ref.NameIdx) >= len(t.Strings) {
			t.Warnings = append(t.Warnings, fmt.Sprintf("type-namespace[%d] name idx %d out of range", i, ref.NameIdx))
		}
	}
	for i, ref := range t.Types {
		if int(ref.NamespaceIdx) >= len(t.TypeNamespaces) {
			t.Warnings = append(t.Warnings, fmt.Sprintf("type[%d] namespace idx %d out of range", i, ref.NamespaceIdx))
		}
		if int(ref.NameIdx) >= len(t.Strings) {
			t.Warnings = append(t.Warnings, fmt.Sprintf("type[%d] name idx %d out of range", i, ref.NameIdx))
		}
	}

	return t, nil
}

// readRegion reads a region's bytes after seeking. Bounds already validated
// in ParseHeader; we re-check Size against allocation cap defensively.
func readRegion(r io.ReadSeeker, reg Region) ([]byte, error) {
	if uint64(reg.Size) > MaxTableSize {
		return nil, fmt.Errorf("table size exceeds limit: %d > %d", reg.Size, MaxTableSize)
	}
	if _, err := r.Seek(int64(reg.Offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek region: %w", err)
	}
	buf := make([]byte, reg.Size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read region: %w", err)
	}
	return buf, nil
}

// parseFixedTable reads a region whose layout is:
//
//	[u16 count][count * entrySize bytes]
//
// and invokes onEntry for each entry.
func parseFixedTable(r io.ReadSeeker, reg Region, entrySize int, label string, onEntry func([]byte)) error {
	if reg.Size == 0 {
		return nil
	}
	buf, err := readRegion(r, reg)
	if err != nil {
		return fmt.Errorf("read %s region: %w", label, err)
	}
	if len(buf) < 2 {
		return fmt.Errorf("%s table truncated: missing count", label)
	}
	count := binary.LittleEndian.Uint16(buf[0:2])
	if int(count) > MaxTableEntries {
		return fmt.Errorf("%s table entry count exceeds limit: %d > %d", label, count, MaxTableEntries)
	}
	need := 2 + int(count)*entrySize
	if need > len(buf) {
		return fmt.Errorf("%s table truncated: need %d bytes have %d", label, need, len(buf))
	}
	for i := 0; i < int(count); i++ {
		base := 2 + i*entrySize
		onEntry(buf[base : base+entrySize])
	}
	return nil
}

// parseStringTable decodes a region containing:
//
//	[u16 count]
//	count * { [u16 charCount][charCount*2 bytes UTF-16LE] }
func parseStringTable(buf []byte) ([]string, error) {
	if len(buf) < 2 {
		return nil, fmt.Errorf("string table truncated: missing count")
	}
	count := binary.LittleEndian.Uint16(buf[0:2])
	if int(count) > MaxTableEntries {
		return nil, fmt.Errorf("string table entry count exceeds limit: %d > %d", count, MaxTableEntries)
	}
	out := make([]string, 0, count)
	off := 2
	for i := 0; i < int(count); i++ {
		if off+2 > len(buf) {
			return nil, fmt.Errorf("string table truncated at entry %d (header)", i)
		}
		charCount := binary.LittleEndian.Uint16(buf[off : off+2])
		off += 2
		// Bound: charCount*2 must fit. Use uint64 to avoid uint16 overflow.
		need := uint64(charCount) * 2
		if uint64(off)+need > uint64(len(buf)) {
			return nil, fmt.Errorf("string table truncated at entry %d (need %d, have %d)", i, need, len(buf)-off)
		}
		end := off + int(need)
		// Decode UTF-16 LE.
		u16 := make([]uint16, charCount)
		for j := 0; j < int(charCount); j++ {
			u16[j] = binary.LittleEndian.Uint16(buf[off+j*2 : off+j*2+2])
		}
		out = append(out, string(utf16.Decode(u16)))
		off = end
	}
	return out, nil
}
