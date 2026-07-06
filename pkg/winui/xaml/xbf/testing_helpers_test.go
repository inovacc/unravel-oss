/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// xbfBuilder is an in-test helper that synthesizes valid XBF byte streams.
type xbfBuilder struct {
	major, minor uint16
	strings      []string
	assemblies   []AssemblyRef
	typeNS       []TypeNamespaceRef
	types        []TypeRef
	properties   []PropertyRef
	xmlNS        []XmlNamespaceRef
	events       []EventRef
	stream       []byte
}

func newXBFBuilder() *xbfBuilder {
	return &xbfBuilder{major: 2, minor: 1}
}

func (b *xbfBuilder) addString(s string) uint16 {
	for i, x := range b.strings {
		if x == s {
			return uint16(i)
		}
	}
	idx := uint16(len(b.strings))
	b.strings = append(b.strings, s)
	return idx
}

func (b *xbfBuilder) addType(name string) uint16 {
	nameIdx := b.addString(name)
	idx := uint16(len(b.types))
	b.types = append(b.types, TypeRef{NamespaceIdx: 0, NameIdx: nameIdx})
	return idx
}

func (b *xbfBuilder) addProperty(name string) uint16 {
	nameIdx := b.addString(name)
	idx := uint16(len(b.properties))
	b.properties = append(b.properties, PropertyRef{TypeIdx: 0, NameIdx: nameIdx})
	return idx
}

func (b *xbfBuilder) emit(bytes ...byte) {
	b.stream = append(b.stream, bytes...)
}

func (b *xbfBuilder) emitU16(v uint16) {
	var x [2]byte
	binary.LittleEndian.PutUint16(x[:], v)
	b.stream = append(b.stream, x[:]...)
}

// startObject emits OpStartObject + type idx.
func (b *xbfBuilder) startObject(typeIdx uint16) {
	b.emit(byte(OpStartObject))
	b.emitU16(typeIdx)
}

func (b *xbfBuilder) endObject() {
	b.emit(byte(OpEndObject))
}

func (b *xbfBuilder) startProperty(propIdx uint16) {
	b.emit(byte(OpStartProperty))
	b.emitU16(propIdx)
}

func (b *xbfBuilder) endProperty() {
	b.emit(byte(OpEndProperty))
}

func (b *xbfBuilder) setValue(strIdx uint16) {
	b.emit(byte(OpSetValue))
	b.emitU16(strIdx)
}

func (b *xbfBuilder) addNamespace(prefixIdx, uriIdx uint16) {
	b.emit(byte(OpAddNamespace))
	b.emitU16(prefixIdx)
	b.emitU16(uriIdx)
}

func (b *xbfBuilder) endOfStream() {
	b.emit(byte(OpEndOfStream))
}

// build serializes the full XBF file: header + tables + node stream.
func (b *xbfBuilder) build() []byte {
	stringTable := encodeStringTable(b.strings)
	asmTable := encodeFixed2(uint16Slice(b.assemblies, func(r AssemblyRef) []uint16 { return []uint16{r.NameIdx} }), 2)
	tnsTable := encodeFixed2(uint16Slice(b.typeNS, func(r TypeNamespaceRef) []uint16 { return []uint16{r.AssemblyIdx, r.NameIdx} }), 4)
	typesTable := encodeFixed2(uint16Slice(b.types, func(r TypeRef) []uint16 { return []uint16{r.NamespaceIdx, r.NameIdx} }), 4)
	propsTable := encodeFixed2(uint16Slice(b.properties, func(r PropertyRef) []uint16 { return []uint16{r.TypeIdx, r.NameIdx} }), 4)
	xmlNsTable := encodeFixed2(uint16Slice(b.xmlNS, func(r XmlNamespaceRef) []uint16 { return []uint16{r.NameIdx} }), 2)
	eventsTable := encodeFixed2(uint16Slice(b.events, func(r EventRef) []uint16 { return []uint16{r.TypeIdx, r.NameIdx} }), 4)

	regions := [][]byte{stringTable, asmTable, tnsTable, typesTable, propsTable, xmlNsTable, eventsTable}

	var out bytes.Buffer
	out.Write([]byte{'X', 'B', 'F', 0x00})
	tmp16 := func(v uint16) {
		var x [2]byte
		binary.LittleEndian.PutUint16(x[:], v)
		out.Write(x[:])
	}
	tmp16(b.major)
	tmp16(b.minor)

	// Compute offsets after the 64-byte header.
	offsets := make([]uint32, 7)
	cursor := uint32(HeaderSize)
	for i, r := range regions {
		offsets[i] = cursor
		cursor += uint32(len(r))
	}

	for i, r := range regions {
		var x [4]byte
		binary.LittleEndian.PutUint32(x[:], offsets[i])
		out.Write(x[:])
		binary.LittleEndian.PutUint32(x[:], uint32(len(r)))
		out.Write(x[:])
	}
	for _, r := range regions {
		out.Write(r)
	}
	out.Write(b.stream)
	return out.Bytes()
}

func encodeStringTable(strs []string) []byte {
	var buf bytes.Buffer
	var x [2]byte
	binary.LittleEndian.PutUint16(x[:], uint16(len(strs)))
	buf.Write(x[:])
	for _, s := range strs {
		u16 := utf16.Encode([]rune(s))
		binary.LittleEndian.PutUint16(x[:], uint16(len(u16)))
		buf.Write(x[:])
		for _, c := range u16 {
			binary.LittleEndian.PutUint16(x[:], c)
			buf.Write(x[:])
		}
	}
	return buf.Bytes()
}

func uint16Slice[T any](items []T, extract func(T) []uint16) [][]uint16 {
	out := make([][]uint16, len(items))
	for i, it := range items {
		out[i] = extract(it)
	}
	return out
}

func encodeFixed2(rows [][]uint16, entrySize int) []byte {
	var buf bytes.Buffer
	var x [2]byte
	binary.LittleEndian.PutUint16(x[:], uint16(len(rows)))
	buf.Write(x[:])
	for _, row := range rows {
		for _, v := range row {
			binary.LittleEndian.PutUint16(x[:], v)
			buf.Write(x[:])
		}
		_ = entrySize
	}
	return buf.Bytes()
}
