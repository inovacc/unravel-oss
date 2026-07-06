/*
Copyright (c) 2026 Security Research
*/
package dex2class

import (
	"encoding/binary"
	"io"
	"math"
)

// StaticValue represents a decoded static field initializer from DEX.
type StaticValue struct {
	Type  byte // encoded_value type
	Int   int64
	Float float64
	Str   string // for string values (resolved from string_ids)
	Bool  bool
}

// encoded_value type constants (from DEX spec)
const (
	evByte    = 0x00
	evShort   = 0x02
	evChar    = 0x03
	evInt     = 0x04
	evLong    = 0x06
	evFloat   = 0x11
	evDouble  = 0x12
	evString  = 0x17
	evType    = 0x18
	evNull    = 0x1e
	evBoolean = 0x1f
)

// readStaticValues reads the encoded_array at the given offset.
// Returns one StaticValue per static field, in declaration order.
// The strings slice is used to resolve string_id indices.
func readStaticValues(r io.ReaderAt, off uint32, strings []string) []StaticValue {
	if off == 0 {
		return nil
	}

	// encoded_array_item: size (uleb128), then size × encoded_value
	buf := make([]byte, 512)
	n, err := r.ReadAt(buf, int64(off))
	if err != nil && n == 0 {
		return nil
	}
	buf = buf[:n]

	pos := 0
	size, pos := readULEB(buf, pos)
	if size == 0 || size > 1000 {
		return nil
	}

	values := make([]StaticValue, 0, size)
	for i := uint32(0); i < size && pos < len(buf); i++ {
		val, newPos := decodeEncodedValue(buf, pos, strings)
		if newPos <= pos {
			break // prevent infinite loop
		}
		pos = newPos
		values = append(values, val)
	}

	return values
}

// decodeEncodedValue decodes one encoded_value from the buffer.
// Format: 1 byte header (type in low 5 bits, size-1 in high 3 bits),
// followed by (size-1+1) bytes of data.
func decodeEncodedValue(buf []byte, pos int, strings []string) (StaticValue, int) {
	if pos >= len(buf) {
		return StaticValue{}, pos
	}

	header := buf[pos]
	pos++

	valueType := header & 0x1f
	valueArg := int(header>>5) + 1 // number of data bytes = arg + 1, except for special types

	sv := StaticValue{Type: valueType}

	switch valueType {
	case evByte:
		if pos < len(buf) {
			sv.Int = int64(int8(buf[pos]))
			pos++
		}

	case evShort, evChar, evInt, evLong:
		// Variable-width signed integer (valueArg bytes)
		nBytes := int(header>>5) + 1
		val := readSignedInt(buf, pos, nBytes)
		sv.Int = val
		pos += nBytes

	case evFloat:
		nBytes := int(header>>5) + 1
		raw := readUnsignedInt(buf, pos, nBytes)
		// Left-align to 32 bits
		raw <<= (4 - uint(nBytes)) * 8
		sv.Float = float64(math.Float32frombits(uint32(raw)))
		pos += nBytes

	case evDouble:
		nBytes := int(header>>5) + 1
		raw := readUnsignedInt(buf, pos, nBytes)
		// Left-align to 64 bits
		raw <<= (8 - uint(nBytes)) * 8
		sv.Float = math.Float64frombits(raw)
		pos += nBytes

	case evString:
		nBytes := int(header>>5) + 1
		idx := int(readUnsignedInt(buf, pos, nBytes))
		if idx >= 0 && idx < len(strings) {
			sv.Str = strings[idx]
		}
		pos += nBytes

	case evType:
		nBytes := int(header>>5) + 1
		pos += nBytes // skip type index

	case evNull:
		// no data bytes
		_ = valueArg

	case evBoolean:
		// value is in the arg bits (0 or 1)
		sv.Bool = (header >> 5) != 0
		sv.Int = int64(header >> 5)

	default:
		// Unknown type — skip valueArg bytes
		nBytes := int(header>>5) + 1
		if valueType != evNull && valueType != evBoolean {
			pos += nBytes
		}
	}

	return sv, pos
}

func readSignedInt(buf []byte, pos, nBytes int) int64 {
	if pos+nBytes > len(buf) {
		return 0
	}
	val := uint64(0)
	for i := range nBytes {
		val |= uint64(buf[pos+i]) << (uint(i) * 8)
	}
	// Sign extend
	if nBytes < 8 && val&(1<<(uint(nBytes)*8-1)) != 0 {
		val |= ^uint64(0) << (uint(nBytes) * 8)
	}
	return int64(val)
}

func readUnsignedInt(buf []byte, pos, nBytes int) uint64 {
	if pos+nBytes > len(buf) {
		return 0
	}
	val := uint64(0)
	for i := range nBytes {
		val |= uint64(buf[pos+i]) << (uint(i) * 8)
	}
	return val
}

func readULEB(buf []byte, pos int) (uint32, int) {
	var result uint32
	var shift uint
	for pos < len(buf) {
		b := buf[pos]
		pos++
		result |= uint32(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result, pos
}

// addConstantValueAttr adds a ConstantValue attribute to a field in the .class output.
// This makes the decompiler show field initializers like `static final String X = "value"`.
func (cw *classWriter) addConstantValueAttr(sv StaticValue, fieldDesc string) (uint16, uint16) {
	cvAttrName := cw.addUTF8("ConstantValue")

	switch sv.Type {
	case evString:
		strIdx := cw.addStringConst(sv.Str)
		return cvAttrName, strIdx
	case evInt, evShort, evByte, evChar:
		intIdx := cw.addIntegerConst(int32(sv.Int))
		return cvAttrName, intIdx
	case evLong:
		longIdx := cw.addLongConst(sv.Int)
		return cvAttrName, longIdx
	case evFloat:
		floatIdx := cw.addFloatConst(float32(sv.Float))
		return cvAttrName, floatIdx
	case evDouble:
		doubleIdx := cw.addDoubleConst(sv.Float)
		return cvAttrName, doubleIdx
	case evBoolean:
		intIdx := cw.addIntegerConst(int32(sv.Int))
		return cvAttrName, intIdx
	}

	return 0, 0
}

// addStringConst adds a CONSTANT_String entry.
func (cw *classWriter) addStringConst(s string) uint16 {
	utf8Idx := cw.addUTF8(s)
	key := "string:" + s
	if idx, ok := cw.utf8Cache[key]; ok {
		return idx
	}
	idx := uint16(len(cw.pool))
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, utf8Idx)
	cw.pool = append(cw.pool, cpEntry{tag: cpString, data: data})
	cw.utf8Cache[key] = idx
	return idx
}

// addIntegerConst adds a CONSTANT_Integer entry.
func (cw *classWriter) addIntegerConst(v int32) uint16 {
	idx := uint16(len(cw.pool))
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(v))
	cw.pool = append(cw.pool, cpEntry{tag: cpInteger, data: data})
	return idx
}

// addLongConst adds a CONSTANT_Long entry (takes 2 CP slots).
func (cw *classWriter) addLongConst(v int64) uint16 {
	idx := uint16(len(cw.pool))
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(v))
	cw.pool = append(cw.pool, cpEntry{tag: cpLong, data: data})
	cw.pool = append(cw.pool, cpEntry{}) // long takes 2 slots
	return idx
}

// addFloatConst adds a CONSTANT_Float entry.
func (cw *classWriter) addFloatConst(v float32) uint16 {
	idx := uint16(len(cw.pool))
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, math.Float32bits(v))
	cw.pool = append(cw.pool, cpEntry{tag: cpFloat, data: data})
	return idx
}

// addDoubleConst adds a CONSTANT_Double entry (takes 2 CP slots).
func (cw *classWriter) addDoubleConst(v float64) uint16 {
	idx := uint16(len(cw.pool))
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, math.Float64bits(v))
	cw.pool = append(cw.pool, cpEntry{tag: cpDouble, data: data})
	cw.pool = append(cw.pool, cpEntry{}) // double takes 2 slots
	return idx
}
