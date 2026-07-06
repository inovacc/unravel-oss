/*
Copyright (c) 2026 Security Research
*/
package msi

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/richardlehane/mscfb"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// Tunable caps for parsing the MSI metadata/Info path against malicious CFBF
// inputs. These are vars (not consts) so tests can shrink them without
// allocating GiB. Defaults are generous: real MSI metadata streams and tables
// are far smaller, so legitimate packages are never rejected.
var (
	// maxMetaStreamBytes bounds a single CFBF metadata/data stream read. The
	// well-guarded Extract path already caps streams at 128 MiB; mirror it here.
	maxMetaStreamBytes int64 = 128 << 20 // 128 MiB
	// maxStrings caps the string-pool slice pre-sized from an attacker-controlled
	// stream length, so a huge _StringPool cannot drive a giant make([]string,n).
	maxStrings = 16_000_000
	// maxRows caps rows materialized per table. Real tables have a few thousand
	// rows; a tiny rowSize over a large stream would otherwise yield tens of
	// millions of map allocations.
	maxRows = 1_000_000
)

// columnType represents an MSI column data type.
type columnType int

const (
	colShortInt columnType = iota // 2 bytes
	colLongInt                    // 4 bytes
	colString                     // 2 or 4 byte string pool index
)

// column describes a single column in an MSI table.
type column struct {
	Name     string
	Type     columnType
	Width    int // bytes: 2 or 4
	Nullable bool
}

// tableReader decodes the MSI internal database stored in CFBF streams.
type tableReader struct {
	doc        *mscfb.Reader
	stringPool []string
	tables     []string
	columns    map[string][]column // table name -> columns
	streams    map[string]*mscfb.File
}

// newTableReader opens an MSI file and parses the database metadata.
func newTableReader(r io.ReaderAt, _ int64) (*tableReader, error) {
	doc, err := mscfb.New(r)
	if err != nil {
		return nil, fmt.Errorf("open CFBF: %w", err)
	}

	tr := &tableReader{
		doc:     doc,
		columns: make(map[string][]column),
		streams: make(map[string]*mscfb.File),
	}

	// Index all streams, decoding MSI-encoded names
	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		decoded := decodeMSIStreamName(entry.Name)
		tr.streams[decoded] = entry
	}

	// Parse string pool
	if err := tr.parseStringPool(); err != nil {
		return nil, fmt.Errorf("parse string pool: %w", err)
	}

	// Parse table list
	if err := tr.parseTableList(); err != nil {
		return nil, fmt.Errorf("parse table list: %w", err)
	}

	// Parse column definitions
	if err := tr.parseColumns(); err != nil {
		return nil, fmt.Errorf("parse columns: %w", err)
	}

	return tr, nil
}

// decodeMSIStreamName decodes the MSI-encoded OLE stream name back to ASCII.
//
// MSI uses a custom encoding to fit table/stream names into OLE storage names.
// Each Unicode character encodes one or two ASCII characters:
//   - 0x4800..0x483F: single char, value = MimeToChar(rune - 0x4800)
//   - 0x3800..0x47FF: two chars encoded in 12 bits
//   - 0x4840: prefix marker (table indicator), skipped
//   - Other: kept as-is (e.g. "SummaryInformation")
func decodeMSIStreamName(encoded string) string {
	runes := []rune(encoded)
	var out []byte

	for _, r := range runes {
		switch {
		case r == 0x4840:
			// Table prefix marker — skip
			continue
		case r >= 0x3800 && r < 0x4800:
			// Two characters encoded in 12 bits
			val := int(r) - 0x3800
			c1 := (val & 0x3F)
			c2 := (val >> 6) & 0x3F
			out = append(out, mimeToChar(c1), mimeToChar(c2))
		case r >= 0x4800 && r < 0x4840:
			// Single character
			out = append(out, mimeToChar(int(r)-0x4800))
		default:
			// Pass-through (ASCII or other)
			out = append(out, byte(r))
		}
	}

	return string(out)
}

// mimeToChar converts a 6-bit value to the MSI MIME character.
func mimeToChar(val int) byte {
	switch {
	case val < 10:
		return byte('0' + val)
	case val < 36:
		return byte('A' + val - 10)
	case val < 62:
		return byte('a' + val - 36)
	case val == 62:
		return '.'
	default:
		return '_'
	}
}

// parseStringPool reads _StringPool and _StringData streams.
func (tr *tableReader) parseStringPool() error {
	poolStream := tr.streams["_StringPool"]
	dataStream := tr.streams["_StringData"]

	if poolStream == nil || dataStream == nil {
		return fmt.Errorf("missing string pool streams")
	}

	poolData, err := readAll(poolStream)
	if err != nil {
		return fmt.Errorf("read _StringPool: %w", err)
	}

	strData, err := readAll(dataStream)
	if err != nil {
		return fmt.Errorf("read _StringData: %w", err)
	}

	tr.stringPool = decodeStringPool(poolData, strData)

	return nil
}

// decodeStringPool builds the string pool from the _StringPool and _StringData
// buffers. Split out from parseStringPool so the numStrings cap is unit-testable.
func decodeStringPool(poolData, strData []byte) []string {
	// Each entry in _StringPool is 4 bytes: uint16 length + uint16 refcount.
	// SEC: numStrings derives directly from an attacker-controlled stream
	// length; cap it before sizing the slice so a huge pool cannot drive a
	// giant make([]string, n) allocation.
	numStrings := len(poolData) / 4
	if numStrings > maxStrings {
		numStrings = maxStrings
	}
	pool := make([]string, numStrings)

	offset := 0
	for i := range numStrings {
		if i*4+4 > len(poolData) {
			break
		}

		strLen := int(binary.LittleEndian.Uint16(poolData[i*4 : i*4+2]))
		// refcount at poolData[i*4+2 : i*4+4] — we don't need it

		if offset+strLen > len(strData) {
			pool[i] = ""
			offset += strLen
			continue
		}

		pool[i] = string(strData[offset : offset+strLen])
		offset += strLen
	}

	return pool
}

// parseTableList reads the _Tables stream.
func (tr *tableReader) parseTableList() error {
	stream := tr.streams["_Tables"]
	if stream == nil {
		return fmt.Errorf("missing _Tables stream")
	}

	data, err := readAll(stream)
	if err != nil {
		return err
	}

	// Each entry is a string pool index (2 bytes if pool < 65536, else 4 bytes)
	indexSize := tr.stringIndexSize()

	for i := 0; i+indexSize <= len(data); i += indexSize {
		idx := tr.readStringIndex(data[i : i+indexSize])
		if idx > 0 && idx < len(tr.stringPool) {
			tr.tables = append(tr.tables, tr.stringPool[idx])
		}
	}

	return nil
}

// parseColumns reads the _Columns stream.
func (tr *tableReader) parseColumns() error {
	stream := tr.streams["_Columns"]
	if stream == nil {
		return fmt.Errorf("missing _Columns stream")
	}

	data, err := readAll(stream)
	if err != nil {
		return err
	}

	indexSize := tr.stringIndexSize()
	// Each column entry: table_index(indexSize) + col_number(2) + col_name(indexSize) + col_type(2)
	entrySize := indexSize + 2 + indexSize + 2

	for i := 0; i+entrySize <= len(data); i += entrySize {
		tableIdx := tr.readStringIndex(data[i : i+indexSize])
		// colNum at data[i+indexSize : i+indexSize+2]
		nameIdx := tr.readStringIndex(data[i+indexSize+2 : i+indexSize+2+indexSize])
		colTypeRaw := binary.LittleEndian.Uint16(data[i+indexSize+2+indexSize : i+entrySize])

		tableName := tr.getString(tableIdx)
		colName := tr.getString(nameIdx)

		if tableName == "" {
			continue
		}

		col := decodeColumnType(colTypeRaw, indexSize)
		col.Name = colName

		tr.columns[tableName] = append(tr.columns[tableName], col)
	}

	return nil
}

// decodeColumnType converts the raw MSI column type uint16 to our column struct.
func decodeColumnType(raw uint16, indexSize int) column {
	col := column{}
	col.Nullable = raw&0x1000 == 0

	switch {
	case raw&0x0F00 == 0x0000: // short int
		col.Type = colShortInt
		col.Width = 2
	case raw&0x0F00 == 0x0100: // long int
		col.Type = colLongInt
		col.Width = 4
	default: // string
		col.Type = colString
		col.Width = indexSize
	}

	return col
}

// readTable reads all rows from the named table stream.
func (tr *tableReader) readTable(name string) ([]map[string]any, error) {
	cols, ok := tr.columns[name]
	if !ok || len(cols) == 0 {
		return nil, fmt.Errorf("no columns for table %q", name)
	}

	stream := tr.streams[name]
	if stream == nil {
		return nil, nil // table exists in metadata but has no data stream
	}

	data, err := readAll(stream)
	if err != nil {
		return nil, err
	}

	return tr.decodeRows(name, cols, data)
}

// decodeRows decodes table rows from a flat data buffer. Split out from
// readTable so the row-cap guard can be unit-tested without a CFBF fixture.
func (tr *tableReader) decodeRows(name string, cols []column, data []byte) ([]map[string]any, error) {
	rowSize := 0
	for _, c := range cols {
		rowSize += c.Width
	}

	if rowSize == 0 {
		return nil, nil
	}

	var rows []map[string]any
	for offset := 0; offset+rowSize <= len(data); offset += rowSize {
		// SEC: a tiny rowSize over a large stream would otherwise materialize
		// tens of millions of map[string]any rows. Stop at the cap rather than
		// exhausting memory; the read is already bounded by maxMetaStreamBytes.
		if len(rows) >= maxRows {
			return rows, fmt.Errorf("table %q exceeds row cap %d", name, maxRows)
		}

		row := make(map[string]any, len(cols))
		pos := offset

		for _, c := range cols {
			if pos+c.Width > len(data) {
				break
			}

			switch c.Type {
			case colShortInt:
				row[c.Name] = int(binary.LittleEndian.Uint16(data[pos : pos+2]))
			case colLongInt:
				row[c.Name] = int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			case colString:
				idx := tr.readStringIndex(data[pos : pos+c.Width])
				row[c.Name] = tr.getString(idx)
			}

			pos += c.Width
		}

		rows = append(rows, row)
	}

	return rows, nil
}

// stringIndexSize returns 2 if pool has < 65536 strings, else 4.
func (tr *tableReader) stringIndexSize() int {
	if len(tr.stringPool) >= 65536 {
		return 4
	}

	return 2
}

// readStringIndex reads a 2 or 4 byte little-endian string pool index.
func (tr *tableReader) readStringIndex(b []byte) int {
	if len(b) >= 4 {
		return int(binary.LittleEndian.Uint32(b))
	}

	if len(b) >= 2 {
		return int(binary.LittleEndian.Uint16(b))
	}

	return 0
}

// getString safely returns the string at the given pool index.
func (tr *tableReader) getString(idx int) string {
	if idx >= 0 && idx < len(tr.stringPool) {
		return tr.stringPool[idx]
	}

	return ""
}

// readAll reads the entire contents of an mscfb.File, bounded against a
// hostile stream that declares far more bytes than the file actually holds.
func readAll(f *mscfb.File) ([]byte, error) {
	return readAllLimit(f, maxMetaStreamBytes)
}

// readAllLimit reads r fully but errors (rather than materializing the whole
// stream) once it exceeds max. Split out so tests can inject a small cap.
func readAllLimit(r io.Reader, max int64) ([]byte, error) {
	data, err := safeio.ReadAllLimit(r, max)
	if err != nil {
		return nil, fmt.Errorf("read stream: %w", err)
	}

	return data, nil
}

// streamNames returns the names of all OLE streams.
func (tr *tableReader) streamNames() []string {
	names := make([]string, 0, len(tr.streams))
	for name := range tr.streams {
		names = append(names, name)
	}

	return names
}

// IsMSI checks whether a CFBF file contains MSI-specific streams.
func IsMSI(r io.ReaderAt, size int64) bool {
	doc, err := mscfb.New(r)
	if err != nil {
		return false
	}

	need := map[string]bool{"_Tables": false, "_StringPool": false, "_StringData": false}

	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		decoded := decodeMSIStreamName(entry.Name)
		if _, ok := need[decoded]; ok {
			need[decoded] = true
		}
	}

	for _, found := range need {
		if !found {
			return false
		}
	}

	return true
}

// getPropertyValue reads a single property value from the Property table.
func (tr *tableReader) getPropertyValue(rows []map[string]any, prop string) string {
	for _, row := range rows {
		if name, ok := row["Property"]; ok {
			if strings.EqualFold(fmt.Sprint(name), prop) {
				if val, ok := row["Value"]; ok {
					return fmt.Sprint(val)
				}
			}
		}
	}

	return ""
}
