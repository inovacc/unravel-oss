/*
Copyright (c) 2026 Security Research
*/
package dex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const (
	headerSize  = 0x70
	endianConst = 0x12345678
	noIndex     = 0xFFFFFFFF
)

// Parse reads and parses a single DEX file from an io.ReaderAt.
func Parse(r io.ReaderAt, size int64) (*DexFile, error) {
	if size < headerSize {
		return nil, fmt.Errorf("dex: file too small (%d bytes)", size)
	}

	var hdr DexHeader
	if err := readAt(r, 0, &hdr); err != nil {
		return nil, fmt.Errorf("dex: reading header: %w", err)
	}

	version, err := validateMagic(hdr.Magic)
	if err != nil {
		return nil, err
	}

	if hdr.EndianTag != endianConst {
		return nil, fmt.Errorf("dex: unsupported endian tag 0x%08X", hdr.EndianTag)
	}

	dex := &DexFile{
		Header:  hdr,
		Version: version,
	}

	dex.Strings, err = readStrings(r, size, hdr.StringIDsSize, hdr.StringIDsOff)
	if err != nil {
		return nil, fmt.Errorf("dex: reading strings: %w", err)
	}

	dex.Types, err = readTypes(r, size, hdr.TypeIDsSize, hdr.TypeIDsOff, dex.Strings)
	if err != nil {
		return nil, fmt.Errorf("dex: reading types: %w", err)
	}

	protos, err := readProtos(r, size, hdr.ProtoIDsSize, hdr.ProtoIDsOff, dex.Strings, dex.Types)
	if err != nil {
		return nil, fmt.Errorf("dex: reading protos: %w", err)
	}

	dex.Methods, err = readMethods(r, size, hdr.MethodIDsSize, hdr.MethodIDsOff, dex.Strings, dex.Types)
	if err != nil {
		return nil, fmt.Errorf("dex: reading methods: %w", err)
	}

	// Resolve method descriptors from proto_ids
	for i := range dex.Methods {
		pIdx := int(dex.Methods[i].ProtoIdx)
		if pIdx >= 0 && pIdx < len(protos) {
			dex.Methods[i].Descriptor = protos[pIdx]
		}
	}

	dex.Fields, err = readFields(r, size, hdr.FieldIDsSize, hdr.FieldIDsOff, dex.Strings, dex.Types)
	if err != nil {
		return nil, fmt.Errorf("dex: reading fields: %w", err)
	}

	dex.Classes, err = readClassDefs(r, size, hdr.ClassDefsSize, hdr.ClassDefsOff, dex.Strings, dex.Types)
	if err != nil {
		return nil, fmt.Errorf("dex: reading class defs: %w", err)
	}

	return dex, nil
}

func validateMagic(magic [8]byte) (string, error) {
	if magic[0] != 'd' || magic[1] != 'e' || magic[2] != 'x' || magic[3] != '\n' {
		return "", fmt.Errorf("dex: invalid magic bytes: %x", magic[:4])
	}
	if magic[7] != 0x00 {
		return "", fmt.Errorf("dex: magic must end with null byte")
	}

	version := string(magic[4:7])
	if version < "035" || version > "040" {
		return "", fmt.Errorf("dex: unsupported version %q", version)
	}

	return version, nil
}

func readAt(r io.ReaderAt, off int64, v any) error {
	buf := new(bytes.Buffer)
	size := binary.Size(v)
	raw := make([]byte, size)

	n, err := r.ReadAt(raw, off)
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("short read: got %d, want %d", n, size)
	}

	_, _ = buf.Write(raw)
	return binary.Read(buf, binary.LittleEndian, v)
}

// boundedCount checks that allocating count elements of elemSize bytes would
// not exceed the total input length. It returns an error when the count is
// implausible so callers can reject crafted headers before any allocation.
func boundedCount(count uint32, elemSize int, inputLen int64) error {
	if elemSize > 0 && uint64(count)*uint64(elemSize) > uint64(inputLen) {
		return fmt.Errorf("dex: implausible count %d (elem %dB) exceeds input size %d", count, elemSize, inputLen)
	}
	// For variable-length elements (elemSize==0) each must consume >=1 byte.
	if elemSize == 0 && int64(count) > inputLen {
		return fmt.Errorf("dex: implausible count %d exceeds input size %d", count, inputLen)
	}
	return nil
}

func readStrings(r io.ReaderAt, fileSize int64, count, off uint32) ([]string, error) {
	if count == 0 {
		return nil, nil
	}
	// Each string ID is 4 bytes; each string also consumes >=1 byte of data.
	if err := boundedCount(count, 4, fileSize); err != nil {
		return nil, err
	}

	offsets := make([]uint32, count)
	if err := readAt(r, int64(off), &offsets); err != nil {
		return nil, fmt.Errorf("reading string ID offsets: %w", err)
	}

	strings := make([]string, count)
	for i, strOff := range offsets {
		s, err := readMUTF8String(r, fileSize, int64(strOff))
		if err != nil {
			return nil, fmt.Errorf("reading string %d at 0x%x: %w", i, strOff, err)
		}
		strings[i] = s
	}

	return strings, nil
}

// readMUTF8String reads a ULEB128-prefixed string from the given offset.
// For simplicity, it reads the ULEB128 length then reads bytes until a null
// terminator, since most DEX strings are ASCII-compatible.
func readMUTF8String(r io.ReaderAt, _ int64, off int64) (string, error) {
	// Read ULEB128 length prefix (up to 5 bytes).
	leb := make([]byte, 5)
	n, err := r.ReadAt(leb, off)
	if err != nil && n == 0 {
		return "", err
	}

	var strLen uint32
	var shift uint
	var consumed int
	for i := 0; i < n; i++ {
		b := leb[i]
		strLen |= uint32(b&0x7F) << shift
		consumed++
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}

	dataOff := off + int64(consumed)
	if strLen == 0 {
		return "", nil
	}

	// Read string data; cap at 4096 bytes to avoid excessive reads.
	readLen := min(int(strLen), 4096)
	// Add extra byte for null terminator.
	buf := make([]byte, readLen+1)
	n, err = r.ReadAt(buf, dataOff)
	if err != nil && n == 0 {
		return "", err
	}

	// Find null terminator.
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return string(buf[:i]), nil
		}
	}

	return string(buf[:n]), nil
}

func readTypes(r io.ReaderAt, fileSize int64, count, off uint32, strs []string) ([]string, error) {
	if count == 0 {
		return nil, nil
	}
	// Each type_id_item is 4 bytes.
	if err := boundedCount(count, 4, fileSize); err != nil {
		return nil, err
	}

	indices := make([]uint32, count)
	if err := readAt(r, int64(off), &indices); err != nil {
		return nil, err
	}

	types := make([]string, count)
	for i, idx := range indices {
		if int(idx) < len(strs) {
			types[i] = strs[idx]
		} else {
			types[i] = fmt.Sprintf("<invalid_type_%d>", idx)
		}
	}

	return types, nil
}

// readProtos reads proto_id_items and returns JVM-style method descriptors.
// Each proto has: shorty_idx (u32), return_type_idx (u32), parameters_off (u32).
func readProtos(r io.ReaderAt, fileSize int64, count, off uint32, strs, types []string) ([]string, error) {
	if count == 0 {
		return nil, nil
	}
	// Each proto_id_item is 12 bytes.
	if err := boundedCount(count, 12, fileSize); err != nil {
		return nil, err
	}

	type rawProto struct {
		ShortyIdx     uint32
		ReturnTypeIdx uint32
		ParametersOff uint32
	}

	raw := make([]rawProto, count)
	if err := readAt(r, int64(off), &raw); err != nil {
		return nil, err
	}

	descs := make([]string, count)
	for i, p := range raw {
		retType := "V"
		if int(p.ReturnTypeIdx) < len(types) {
			retType = dalvikTypeToDescriptor(types[p.ReturnTypeIdx])
		}

		params := ""
		if p.ParametersOff != 0 {
			params = readTypeList(r, p.ParametersOff, types)
		}

		descs[i] = "(" + params + ")" + retType
	}

	return descs, nil
}

// readTypeList reads a type_list at the given offset.
// Format: size (u32), then size * type_idx (u16).
func readTypeList(r io.ReaderAt, off uint32, types []string) string {
	var size uint32
	buf := make([]byte, 4)
	if _, err := r.ReadAt(buf, int64(off)); err != nil {
		return ""
	}
	size = uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24

	if size == 0 || size > 256 {
		return ""
	}

	var result strings.Builder
	for i := uint32(0); i < size; i++ {
		typeBuf := make([]byte, 2)
		if _, err := r.ReadAt(typeBuf, int64(off)+4+int64(i*2)); err != nil {
			break
		}
		typeIdx := uint16(typeBuf[0]) | uint16(typeBuf[1])<<8
		if int(typeIdx) < len(types) {
			result.WriteString(dalvikTypeToDescriptor(types[typeIdx]))
		}
	}

	return result.String()
}

// dalvikTypeToDescriptor converts a Dalvik type string to JVM descriptor.
// Dalvik uses the same format as JVM: Lcom/example/Class; for objects, I for int, etc.
func dalvikTypeToDescriptor(t string) string {
	if t == "" {
		return "Ljava/lang/Object;"
	}
	// Dalvik types are already in JVM descriptor format
	return t
}

func readMethods(r io.ReaderAt, fileSize int64, count, off uint32, strs, types []string) ([]MethodRef, error) {
	if count == 0 {
		return nil, nil
	}
	// Each method_id_item is 8 bytes (u16 + u16 + u32).
	if err := boundedCount(count, 8, fileSize); err != nil {
		return nil, err
	}

	type rawMethod struct {
		ClassIdx uint16
		ProtoIdx uint16
		NameIdx  uint32
	}

	raw := make([]rawMethod, count)
	if err := readAt(r, int64(off), &raw); err != nil {
		return nil, err
	}

	methods := make([]MethodRef, count)
	for i, m := range raw {
		methods[i] = MethodRef{
			ClassIdx:  m.ClassIdx,
			ProtoIdx:  m.ProtoIdx,
			NameIdx:   m.NameIdx,
			ClassName: resolveType(types, int(m.ClassIdx)),
			Name:      resolveString(strs, int(m.NameIdx)),
		}
	}

	return methods, nil
}

func readFields(r io.ReaderAt, fileSize int64, count, off uint32, strs, types []string) ([]FieldRef, error) {
	if count == 0 {
		return nil, nil
	}
	// Each field_id_item is 8 bytes (u16 + u16 + u32).
	if err := boundedCount(count, 8, fileSize); err != nil {
		return nil, err
	}

	type rawField struct {
		ClassIdx uint16
		TypeIdx  uint16
		NameIdx  uint32
	}

	raw := make([]rawField, count)
	if err := readAt(r, int64(off), &raw); err != nil {
		return nil, err
	}

	fields := make([]FieldRef, count)
	for i, f := range raw {
		fields[i] = FieldRef{
			ClassIdx:  f.ClassIdx,
			TypeIdx:   f.TypeIdx,
			NameIdx:   f.NameIdx,
			ClassName: resolveType(types, int(f.ClassIdx)),
			Name:      resolveString(strs, int(f.NameIdx)),
			TypeName:  resolveType(types, int(f.TypeIdx)),
		}
	}

	return fields, nil
}

func readClassDefs(r io.ReaderAt, fileSize int64, count, off uint32, strs, types []string) ([]ClassDef, error) {
	if count == 0 {
		return nil, nil
	}
	// Each class_def_item is 32 bytes (8 × u32).
	if err := boundedCount(count, 32, fileSize); err != nil {
		return nil, err
	}

	type rawClassDef struct {
		TypeIdx         uint32
		AccessFlags     uint32
		SuperclassIdx   uint32
		InterfacesOff   uint32
		SourceFileIdx   uint32
		AnnotationsOff  uint32
		ClassDataOff    uint32
		StaticValuesOff uint32
	}

	raw := make([]rawClassDef, count)
	if err := readAt(r, int64(off), &raw); err != nil {
		return nil, err
	}

	classes := make([]ClassDef, count)
	for i, c := range raw {
		classes[i] = ClassDef{
			TypeIdx:         c.TypeIdx,
			AccessFlags:     c.AccessFlags,
			SuperclassIdx:   c.SuperclassIdx,
			InterfacesOff:   c.InterfacesOff,
			SourceFileIdx:   c.SourceFileIdx,
			AnnotationsOff:  c.AnnotationsOff,
			ClassDataOff:    c.ClassDataOff,
			StaticValuesOff: c.StaticValuesOff,
			ClassName:       resolveType(types, int(c.TypeIdx)),
		}

		if c.SuperclassIdx != noIndex {
			classes[i].Superclass = resolveType(types, int(c.SuperclassIdx))
		}
		if c.SourceFileIdx != noIndex {
			classes[i].SourceFile = resolveString(strs, int(c.SourceFileIdx))
		}
	}

	return classes, nil
}

func resolveString(strs []string, idx int) string {
	if idx >= 0 && idx < len(strs) {
		return strs[idx]
	}
	return fmt.Sprintf("<invalid_string_%d>", idx)
}

func resolveType(types []string, idx int) string {
	if idx >= 0 && idx < len(types) {
		return types[idx]
	}
	return fmt.Sprintf("<invalid_type_%d>", idx)
}
