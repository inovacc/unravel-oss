/*
Copyright (c) 2026 Security Research
*/
package metadata

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// Tables holds the decoded #~ table stream: per-table row counts, computed
// index widths, and raw row windows ready for typed decode.
type Tables struct {
	heaps     *Heaps
	heapSizes byte
	rowCount  [64]uint32
	rowWidth  [64]int    // bytes per row, 0 until sized
	rowData   [64][]byte // raw row bytes for each present table
	sorted    uint64
	rawRows   []byte // remaining #~ bytes after Rows[]; carved in M0-2
}

// RowCount returns the number of rows in table id (0 if absent).
func (t *Tables) RowCount(id byte) uint32 {
	if int(id) >= len(t.rowCount) {
		return 0
	}
	return t.rowCount[id]
}

// heapSizes2byte reports whether the heap index for table id's heap-typed
// columns is 2 bytes wide. It is keyed on the GUID bit for the generic helper
// used by row sizing; callers pass the relevant heap bit elsewhere.
func (t *Tables) heapSizes2byte(_ byte) bool {
	return t.heapSizes&heapSizeGUID == 0
}

// Parse is the SOLE BSJB-root parser. It decodes the metadata root, the heaps,
// and the #~ table stream (header + row counts). Row decode + index sizing land
// in later tasks; this version fills row counts and rejects #- (ENC).
func Parse(meta []byte) (*Tables, *Heaps, error) {
	r, err := parseRoot(meta)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata root: %w", err)
	}
	if _, isENC := r.streams["#-"]; isENC {
		return nil, nil, ErrENCStream
	}
	tilde, ok := r.streams["#~"]
	if !ok {
		return nil, nil, fmt.Errorf("missing #~ table stream")
	}

	heaps := newHeaps(r)
	t := &Tables{heaps: heaps}
	if err := t.parseTilde(tilde.data); err != nil {
		return nil, nil, fmt.Errorf("#~ stream: %w", err)
	}
	return t, heaps, nil
}

// parseTilde decodes the #~ stream header (II.24.2.6): HeapSizes, Valid/Sorted
// masks, and Rows[] for each set bit.
func (t *Tables) parseTilde(d []byte) error {
	if len(d) < 24 {
		return fmt.Errorf("#~ header too small: %d bytes", len(d))
	}
	t.heapSizes = d[6]
	valid := binary.LittleEndian.Uint64(d[8:])
	t.sorted = binary.LittleEndian.Uint64(d[16:])
	p := 24

	nTables := bits.OnesCount64(valid)
	if p+nTables*4 > len(d) {
		return fmt.Errorf("truncated Rows[] (%d tables)", nTables)
	}
	for id := 0; id < 64; id++ {
		if valid&(1<<uint(id)) == 0 {
			continue
		}
		t.rowCount[id] = binary.LittleEndian.Uint32(d[p:])
		p += 4
	}
	// Reject *Ptr indirection before sizing: those tables have no schema, so
	// sizeTables must never reach them (M0-7).
	if id, present := t.firstIndirectionTable(); present {
		return fmt.Errorf("table %#x present: %w", id, ErrIndirectionTablesUnsupported)
	}
	// Stash the remaining bytes, then carve them into per-table row windows
	// now that row counts are known.
	t.rawRows = d[p:]
	if err := t.sizeTables(); err != nil {
		return err
	}
	return nil
}

// indirectionTables are the *Ptr tables that, when present, make raw owner-range
// resolution unsafe (II.24.2.6, ENC/optimized metadata). M0 refuses them.
var indirectionTables = [...]byte{0x03, 0x05, 0x07, 0x12, 0x13} // Field/Method/Param/Event/PropertyPtr

func (t *Tables) firstIndirectionTable() (byte, bool) {
	for _, id := range indirectionTables {
		if t.rowCount[id] > 0 {
			return id, true
		}
	}
	return 0, false
}

func (t *Tables) stringIdxWidth() int {
	if t.heapSizes&heapSizeStrings != 0 {
		return 4
	}
	return 2
}

func (t *Tables) guidIdxWidth() int {
	if t.heapSizes&heapSizeGUID != 0 {
		return 4
	}
	return 2
}

func (t *Tables) blobIdxWidth() int {
	if t.heapSizes&heapSizeBlob != 0 {
		return 4
	}
	return 2
}

// simpleIdxWidth returns the byte width of a row index into table id: 4 bytes
// iff that table has >= 2^16 rows, else 2 (II.24.2.6).
func (t *Tables) simpleIdxWidth(id byte) int {
	if t.rowCount[id] >= (1 << 16) {
		return 4
	}
	return 2
}

// sizeTables computes the row width of every present table and carves rawRows
// into per-table windows. rowWidthOf is the schema-driven column summer (the
// full schema is filled in M0-5; M0-2 wires the carving).
func (t *Tables) sizeTables() error {
	for id := 0; id < 64; id++ {
		if t.rowCount[id] == 0 {
			continue
		}
		w := t.rowWidthOf(byte(id))
		t.rowWidth[id] = w
		need := int(t.rowCount[id]) * w
		if need > len(t.rawRows) {
			return fmt.Errorf("table %#x needs %d bytes, %d remain", id, need, len(t.rawRows))
		}
		t.rowData[id] = t.rawRows[:need]
		t.rawRows = t.rawRows[need:]
	}
	return nil
}
