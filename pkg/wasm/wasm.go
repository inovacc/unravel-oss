/*
Copyright (c) 2026 Security Research
*/
package wasm

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// WASM magic bytes: \x00asm
var wasmMagic = []byte{0x00, 0x61, 0x73, 0x6D}

// Section IDs
const (
	SectionCustom    uint8 = 0
	SectionType      uint8 = 1
	SectionImport    uint8 = 2
	SectionFunction  uint8 = 3
	SectionTable     uint8 = 4
	SectionMemory    uint8 = 5
	SectionGlobal    uint8 = 6
	SectionExport    uint8 = 7
	SectionStart     uint8 = 8
	SectionElement   uint8 = 9
	SectionCode      uint8 = 10
	SectionData      uint8 = 11
	SectionDataCount uint8 = 12
)

// Import/export kind constants
const (
	KindFunc   byte = 0x00
	KindTable  byte = 0x01
	KindMemory byte = 0x02
	KindGlobal byte = 0x03
)

// SEC allocation caps — promote to package level so tests can reference them.
const (
	maxWasmTypeEntries   = 1 << 20 // 1 M function types; generous for any real WASM module
	maxWasmImportEntries = 1 << 20 // 1 M imports
	maxWasmExportEntries = 1 << 20 // 1 M exports
)

// WASM value type constants
const (
	ValTypeI32       byte = 0x7F
	ValTypeI64       byte = 0x7E
	ValTypeF32       byte = 0x7D
	ValTypeF64       byte = 0x7C
	ValTypeV128      byte = 0x7B
	ValTypeFuncRef   byte = 0x70
	ValTypeExternRef byte = 0x6F
)

// WASMInfo holds parsed metadata from a WebAssembly binary module.
type WASMInfo struct {
	Version     uint32    `json:"version"`
	Sections    []Section `json:"sections"`
	Imports     []Import  `json:"imports"`
	Exports     []Export  `json:"exports"`
	Functions   int       `json:"functions"`
	Memories    int       `json:"memories"`
	Tables      int       `json:"tables"`
	Globals     int       `json:"globals"`
	CustomNames []string  `json:"custom_names,omitempty"`
	CodeSize    int64     `json:"code_size"`
	DataSize    int64     `json:"data_size"`
}

// Section describes a single section in the WASM module.
type Section struct {
	ID   uint8  `json:"id"`
	Name string `json:"name"`
	Size uint32 `json:"size"`
}

// Import describes a single import entry.
type Import struct {
	Module string `json:"module"`
	Field  string `json:"field"`
	Kind   string `json:"kind"` // "func", "table", "memory", "global"
}

// Export describes a single export entry.
type Export struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Index uint32 `json:"index"`
}

// FuncType describes a function signature from the Type section.
type FuncType struct {
	Params  []string `json:"params"`
	Results []string `json:"results"`
}

// sectionName returns the human-readable name for a section ID.
func sectionName(id uint8) string {
	switch id {
	case SectionCustom:
		return "Custom"
	case SectionType:
		return "Type"
	case SectionImport:
		return "Import"
	case SectionFunction:
		return "Function"
	case SectionTable:
		return "Table"
	case SectionMemory:
		return "Memory"
	case SectionGlobal:
		return "Global"
	case SectionExport:
		return "Export"
	case SectionStart:
		return "Start"
	case SectionElement:
		return "Element"
	case SectionCode:
		return "Code"
	case SectionData:
		return "Data"
	case SectionDataCount:
		return "DataCount"
	default:
		return fmt.Sprintf("Unknown(%d)", id)
	}
}

// kindName returns the human-readable name for an import/export kind byte.
func kindName(k byte) string {
	switch k {
	case KindFunc:
		return "func"
	case KindTable:
		return "table"
	case KindMemory:
		return "memory"
	case KindGlobal:
		return "global"
	default:
		return fmt.Sprintf("unknown(%d)", k)
	}
}

// valTypeName returns the human-readable name for a WASM value type byte.
func valTypeName(v byte) string {
	switch v {
	case ValTypeI32:
		return "i32"
	case ValTypeI64:
		return "i64"
	case ValTypeF32:
		return "f32"
	case ValTypeF64:
		return "f64"
	case ValTypeV128:
		return "v128"
	case ValTypeFuncRef:
		return "funcref"
	case ValTypeExternRef:
		return "externref"
	default:
		return fmt.Sprintf("unknown(0x%02x)", v)
	}
}

// Parse reads a WASM binary file and extracts module metadata.
func Parse(path string) (*WASMInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wasm: %w", err)
	}
	defer func() { _ = f.Close() }()

	return parseReader(f)
}

// ParseBytes parses WASM module metadata from raw bytes.
func ParseBytes(data []byte) (*WASMInfo, error) {
	return parseReader(&bytesReader{data: data, pos: 0})
}

// bytesReader is a simple io.Reader + io.ByteReader over a byte slice.
type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *bytesReader) ReadByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

// byteReaderWrapper wraps an io.Reader to also implement io.ByteReader.
type byteReaderWrapper struct {
	r   io.Reader
	buf [1]byte
}

func (w *byteReaderWrapper) Read(p []byte) (int, error) {
	return w.r.Read(p)
}

func (w *byteReaderWrapper) ReadByte() (byte, error) {
	_, err := io.ReadFull(w.r, w.buf[:])
	return w.buf[0], err
}

// readerByteReader is the interface we need for parsing.
type readerByteReader interface {
	io.Reader
	io.ByteReader
}

// ensureByteReader wraps an io.Reader into a readerByteReader if needed.
func ensureByteReader(r io.Reader) readerByteReader {
	if rb, ok := r.(readerByteReader); ok {
		return rb
	}
	return &byteReaderWrapper{r: r}
}

func parseReader(r io.Reader) (*WASMInfo, error) {
	br := ensureByteReader(r)

	// Read and validate magic number
	magic := make([]byte, 4)
	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	for i := range 4 {
		if magic[i] != wasmMagic[i] {
			return nil, fmt.Errorf("not a wasm file: invalid magic bytes")
		}
	}

	// Read version (4 bytes, little-endian)
	var version uint32
	if err := binary.Read(br, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}

	info := &WASMInfo{
		Version: version,
	}

	// Parse sections
	for {
		sectionID, err := br.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read section id: %w", err)
		}

		sectionSize, err := readLEB128u32(br)
		if err != nil {
			return nil, fmt.Errorf("read section size: %w", err)
		}
		// Guard against OOM from attacker-controlled section sizes.
		// 256 MiB is a generous upper bound; real WASM sections are far smaller.
		const maxSectionSize = 256 << 20
		if sectionSize > maxSectionSize {
			return nil, fmt.Errorf("wasm: section size %d exceeds limit %d", sectionSize, maxSectionSize)
		}

		sec := Section{
			ID:   sectionID,
			Name: sectionName(sectionID),
			Size: sectionSize,
		}
		info.Sections = append(info.Sections, sec)

		// Read section payload
		payload := make([]byte, sectionSize)
		if _, err := io.ReadFull(br, payload); err != nil {
			return nil, fmt.Errorf("read section %s payload: %w", sec.Name, err)
		}

		pr := &bytesReader{data: payload, pos: 0}

		switch sectionID {
		case SectionCustom:
			name, err := readName(pr)
			if err == nil {
				info.CustomNames = append(info.CustomNames, name)
			}
		case SectionType:
			// Count function types (we don't store signatures for now)
			// but we parse them for correctness
			parseTypeSection(pr)
		case SectionImport:
			imports, err := parseImportSection(pr)
			if err == nil {
				info.Imports = imports
				// Count imported items by kind
				for _, imp := range imports {
					switch imp.Kind {
					case "func":
						info.Functions++
					case "table":
						info.Tables++
					case "memory":
						info.Memories++
					case "global":
						info.Globals++
					}
				}
			}
		case SectionFunction:
			count, err := readLEB128u32(pr)
			if err == nil {
				info.Functions += int(count)
			}
		case SectionTable:
			count, err := readLEB128u32(pr)
			if err == nil {
				info.Tables += int(count)
			}
		case SectionMemory:
			count, err := readLEB128u32(pr)
			if err == nil {
				info.Memories += int(count)
			}
		case SectionGlobal:
			count, err := readLEB128u32(pr)
			if err == nil {
				info.Globals += int(count)
			}
		case SectionExport:
			exports, err := parseExportSection(pr)
			if err == nil {
				info.Exports = exports
			}
		case SectionCode:
			info.CodeSize = int64(sectionSize)
		case SectionData:
			info.DataSize = int64(sectionSize)
		}
	}

	return info, nil
}

// readLEB128u32 reads an unsigned LEB128-encoded 32-bit integer.
func readLEB128u32(r io.ByteReader) (uint32, error) {
	var result uint32
	var shift uint

	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, fmt.Errorf("read leb128: %w", err)
		}

		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}

		shift += 7
		if shift >= 35 {
			return 0, fmt.Errorf("leb128 overflow")
		}
	}

	return result, nil
}

// readName reads a WASM name (length-prefixed UTF-8 string).
func readName(r readerByteReader) (string, error) {
	length, err := readLEB128u32(r)
	if err != nil {
		return "", fmt.Errorf("read name length: %w", err)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read name data: %w", err)
	}

	return string(buf), nil
}

// parseTypeSection parses function type signatures from the Type section.
func parseTypeSection(r readerByteReader) []FuncType {
	count, err := readLEB128u32(r)
	if err != nil {
		return nil
	}

	// SEC: cap the capacity hint before make to prevent a ~192 GiB allocation from
	// a WASM Type section whose count LEB128 = 0xFFFFFFFF (4 billion).
	// The section payload is capped at 256 MiB, so the loop will terminate early;
	// the initial make however fires before any iteration.
	safeCount := min(count, maxWasmTypeEntries)
	types := make([]FuncType, 0, safeCount)

	for range count {
		marker, err := r.ReadByte()
		if err != nil || marker != 0x60 { // 0x60 = function type marker
			break
		}

		ft := FuncType{}

		// Parse params
		paramCount, err := readLEB128u32(r)
		if err != nil {
			break
		}
		for range paramCount {
			vt, err := r.ReadByte()
			if err != nil {
				return types
			}
			ft.Params = append(ft.Params, valTypeName(vt))
		}

		// Parse results
		resultCount, err := readLEB128u32(r)
		if err != nil {
			break
		}
		for range resultCount {
			vt, err := r.ReadByte()
			if err != nil {
				return types
			}
			ft.Results = append(ft.Results, valTypeName(vt))
		}

		types = append(types, ft)
	}

	return types
}

// parseImportSection parses import entries.
func parseImportSection(r readerByteReader) ([]Import, error) {
	count, err := readLEB128u32(r)
	if err != nil {
		return nil, fmt.Errorf("read import count: %w", err)
	}

	// SEC: cap capacity hint to prevent large pre-allocation on crafted WASM.
	safeImportCount := min(count, maxWasmImportEntries)
	imports := make([]Import, 0, safeImportCount)

	for range count {
		module, err := readName(r)
		if err != nil {
			return imports, fmt.Errorf("read import module: %w", err)
		}

		field, err := readName(r)
		if err != nil {
			return imports, fmt.Errorf("read import field: %w", err)
		}

		kind, err := r.ReadByte()
		if err != nil {
			return imports, fmt.Errorf("read import kind: %w", err)
		}

		imp := Import{
			Module: module,
			Field:  field,
			Kind:   kindName(kind),
		}

		// Skip the import descriptor based on kind
		switch kind {
		case KindFunc:
			// typeidx
			if _, err := readLEB128u32(r); err != nil {
				return imports, fmt.Errorf("read import func typeidx: %w", err)
			}
		case KindTable:
			// elemtype + limits
			if _, err := r.ReadByte(); err != nil {
				return imports, fmt.Errorf("read import table elemtype: %w", err)
			}
			if err := skipLimits(r); err != nil {
				return imports, fmt.Errorf("read import table limits: %w", err)
			}
		case KindMemory:
			// limits
			if err := skipLimits(r); err != nil {
				return imports, fmt.Errorf("read import memory limits: %w", err)
			}
		case KindGlobal:
			// valtype + mut
			if _, err := r.ReadByte(); err != nil {
				return imports, fmt.Errorf("read import global valtype: %w", err)
			}
			if _, err := r.ReadByte(); err != nil {
				return imports, fmt.Errorf("read import global mut: %w", err)
			}
		}

		imports = append(imports, imp)
	}

	return imports, nil
}

// parseExportSection parses export entries.
func parseExportSection(r readerByteReader) ([]Export, error) {
	count, err := readLEB128u32(r)
	if err != nil {
		return nil, fmt.Errorf("read export count: %w", err)
	}

	// SEC: cap capacity hint to prevent large pre-allocation on crafted WASM.
	safeExportCount := min(count, maxWasmExportEntries)
	exports := make([]Export, 0, safeExportCount)

	for range count {
		name, err := readName(r)
		if err != nil {
			return exports, fmt.Errorf("read export name: %w", err)
		}

		kind, err := r.ReadByte()
		if err != nil {
			return exports, fmt.Errorf("read export kind: %w", err)
		}

		index, err := readLEB128u32(r)
		if err != nil {
			return exports, fmt.Errorf("read export index: %w", err)
		}

		exports = append(exports, Export{
			Name:  name,
			Kind:  kindName(kind),
			Index: index,
		})
	}

	return exports, nil
}

// skipLimits skips a WASM limits structure (flag + min [+ max]).
func skipLimits(r io.ByteReader) error {
	flag, err := r.ReadByte()
	if err != nil {
		return err
	}

	// Read min
	if _, err := readLEB128u32(r); err != nil {
		return err
	}

	// If flag has bit 0 set, there's a max
	if flag&0x01 != 0 {
		if _, err := readLEB128u32(r); err != nil {
			return err
		}
	}

	return nil
}

// IsWASM checks if the given bytes start with the WASM magic number.
func IsWASM(header []byte) bool {
	if len(header) < 4 {
		return false
	}
	return header[0] == 0x00 && header[1] == 0x61 && header[2] == 0x73 && header[3] == 0x6D
}
