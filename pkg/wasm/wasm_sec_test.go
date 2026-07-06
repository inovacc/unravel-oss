package wasm

import (
	"bytes"
	"testing"
)

// encodeLEB128u32 encodes v as an unsigned LEB128 byte sequence.
func encodeLEB128u32(v uint32) []byte {
	var buf []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			break
		}
	}
	return buf
}

// buildTypeSectionPayload builds a Type section payload with count set to the
// given value, followed by a single 0x60 marker (so the loop reads one entry).
func buildTypeSectionPayload(count uint32) []byte {
	var buf []byte
	buf = append(buf, encodeLEB128u32(count)...)
	buf = append(buf, 0x60) // function type marker
	buf = append(buf, 0)    // 0 params
	buf = append(buf, 0)    // 0 results
	return buf
}

// TestParseTypeSection_HugeCount verifies that a count of 0xFFFFFFFF does not
// trigger a ~192 GiB pre-allocation.  The function must return without panicking
// and produce at most maxWasmTypeEntries results.
func TestParseTypeSection_HugeCount(t *testing.T) {
	payload := buildTypeSectionPayload(0xFFFFFFFF)
	r := bytes.NewReader(payload)
	types := parseTypeSection(r)
	// Should not panic; may return 0 or 1 entries (loop reads until EOF).
	if len(types) > maxWasmTypeEntries {
		t.Errorf("type count exceeds cap: %d > %d", len(types), maxWasmTypeEntries)
	}
}

// TestParseTypeSection_SmallCount verifies a legitimate small count works correctly.
func TestParseTypeSection_SmallCount(t *testing.T) {
	// 2 function types, each () → ()
	var buf []byte
	buf = append(buf, encodeLEB128u32(2)...)
	for range 2 {
		buf = append(buf, 0x60, 0, 0)
	}
	r := bytes.NewReader(buf)
	types := parseTypeSection(r)
	if len(types) != 2 {
		t.Errorf("expected 2 types, got %d", len(types))
	}
}

// buildImportSectionPayload builds an Import section payload with count=0xFFFFFFFF
// followed by a single valid import entry so the loop runs once then hits EOF.
func buildImportSectionPayload(count uint32) []byte {
	var buf []byte
	buf = append(buf, encodeLEB128u32(count)...)
	// One import: module="m" field="f" kind=KindFunc typeidx=0
	buf = append(buf, encodeLEB128u32(1)...) // module len
	buf = append(buf, 'm')
	buf = append(buf, encodeLEB128u32(1)...) // field len
	buf = append(buf, 'f')
	buf = append(buf, byte(KindFunc))
	buf = append(buf, encodeLEB128u32(0)...) // typeidx
	return buf
}

// TestParseImportSection_HugeCount verifies that a count of 0xFFFFFFFF does not
// cause a huge pre-allocation panic.
func TestParseImportSection_HugeCount(t *testing.T) {
	payload := buildImportSectionPayload(0xFFFFFFFF)

	// We need an io.ReadSeeker; wrap in a bytes.Reader via a thin adapter.
	r := bytes.NewReader(payload)
	imports, _ := parseImportSection(r)
	if len(imports) > maxWasmImportEntries {
		t.Errorf("import count exceeds cap: %d > %d", len(imports), maxWasmImportEntries)
	}
}

// TestParseExportSection_HugeCount verifies that a count of 0xFFFFFFFF does not
// cause a huge pre-allocation panic.
func TestParseExportSection_HugeCount(t *testing.T) {
	var buf []byte
	buf = append(buf, encodeLEB128u32(0xFFFFFFFF)...)
	// One export: name="e" kind=KindFunc index=0
	buf = append(buf, encodeLEB128u32(1)...)
	buf = append(buf, 'e')
	buf = append(buf, byte(KindFunc))
	buf = append(buf, encodeLEB128u32(0)...)

	r := bytes.NewReader(buf)
	exports, _ := parseExportSection(r)
	if len(exports) > maxWasmExportEntries {
		t.Errorf("export count exceeds cap: %d > %d", len(exports), maxWasmExportEntries)
	}
}
