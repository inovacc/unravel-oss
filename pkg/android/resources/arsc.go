/*
Copyright (c) 2026 Security Research
*/

package resources

import (
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

const (
	resTableType       = 0x0002
	stringPoolType     = 0x0001
	packageType        = 0x0200
	stringPoolUTF8Flag = 0x100
)

// ParseARSC parses resources.arsc to extract the global string pool, package name, and type names.
// Returns: string pool info, package name, type names, error
func ParseARSC(r io.ReaderAt, size int64) (*StringPoolInfo, string, []string, error) {
	if size < 12 {
		return nil, "", nil, fmt.Errorf("resources.arsc too small: %d bytes", size)
	}

	data := make([]byte, size)
	if _, err := r.ReadAt(data, 0); err != nil {
		return nil, "", nil, fmt.Errorf("read resources.arsc: %w", err)
	}

	offset := 0

	headerType := binary.LittleEndian.Uint16(data[offset:])
	if headerType != resTableType {
		return nil, "", nil, fmt.Errorf("invalid resource table type: 0x%04x", headerType)
	}
	headerSize := binary.LittleEndian.Uint16(data[offset+2:])
	offset += int(headerSize)

	if offset+8 > len(data) {
		return nil, "", nil, fmt.Errorf("truncated after resource table header")
	}

	chunkType := binary.LittleEndian.Uint16(data[offset:])
	if chunkType != stringPoolType {
		return nil, "", nil, fmt.Errorf("expected global string pool, got type 0x%04x", chunkType)
	}

	stringPool, poolSize, err := parseStringPool(data[offset:])
	if err != nil {
		return nil, "", nil, fmt.Errorf("parse global string pool: %w", err)
	}
	offset += poolSize

	var packageName string
	var typeNames []string

	for offset+8 <= len(data) {
		chunkType := binary.LittleEndian.Uint16(data[offset:])
		chunkSize := int(binary.LittleEndian.Uint32(data[offset+4:]))

		// SEC: chunkSize is attacker-controlled. A valid ResChunk_header is at
		// least 8 bytes, so chunkSize < 8 is malformed and would also stall the
		// walk (offset += 0 -> infinite loop). An oversized chunkSize would make
		// data[offset:offset+chunkSize] slice out of bounds (panic), and the
		// offset+chunkSize < offset term catches int wraparound. Validate once
		// at the top so both the package-chunk slice and the advance are bounded.
		if chunkSize < 8 || offset+chunkSize > len(data) || offset+chunkSize < offset {
			return stringPool, packageName, typeNames, fmt.Errorf("truncated or malformed chunk (type 0x%04x size %d)", chunkType, chunkSize)
		}

		if chunkType == packageType {
			var err error
			packageName, typeNames, err = parsePackageChunk(data[offset : offset+chunkSize])
			if err != nil {
				return stringPool, "", nil, fmt.Errorf("parse package chunk: %w", err)
			}
			break
		}

		offset += chunkSize
	}

	return stringPool, packageName, typeNames, nil
}

func parseStringPool(data []byte) (*StringPoolInfo, int, error) {
	if len(data) < 28 {
		return nil, 0, fmt.Errorf("string pool chunk too small")
	}

	chunkSize := int(binary.LittleEndian.Uint32(data[4:]))
	if chunkSize > len(data) {
		return nil, 0, fmt.Errorf("string pool chunk size exceeds data")
	}

	stringCount := int(binary.LittleEndian.Uint32(data[8:]))
	flags := binary.LittleEndian.Uint32(data[16:])
	stringsStart := int(binary.LittleEndian.Uint32(data[20:]))

	isUTF8 := (flags & stringPoolUTF8Flag) != 0

	info := &StringPoolInfo{
		TotalStrings:  stringCount,
		UTF8:          isUTF8,
		SampleStrings: make([]string, 0, 50),
	}

	// String offsets array starts at byte 28 (after the 28-byte string pool header)
	offsetsStart := 28
	// SEC: use overflow-safe check: stringCount must fit in (len(data)-28)/4.
	// Plain offsetsStart+stringCount*4 can overflow to a negative value on 32-bit
	// builds (stringCount ~536 M), bypassing the bounds guard.
	if stringCount > (len(data)-offsetsStart)/4 {
		return info, chunkSize, nil
	}
	offsetsEnd := offsetsStart + stringCount*4
	if offsetsEnd > len(data) {
		return info, chunkSize, nil
	}

	// stringsStart is relative to the string pool chunk header
	stringsBase := stringsStart

	for i := 0; i < stringCount && len(info.SampleStrings) < 50; i++ {
		if offsetsStart+i*4+4 > len(data) {
			break
		}

		strOffset := int(binary.LittleEndian.Uint32(data[offsetsStart+i*4:]))
		strPos := stringsBase + strOffset

		if strPos >= chunkSize || strPos >= len(data) {
			continue
		}

		var str string
		var err error

		if isUTF8 {
			str, err = readUTF8String(data[strPos:min(chunkSize, len(data))])
		} else {
			str, err = readUTF16String(data[strPos:min(chunkSize, len(data))])
		}

		if err == nil && len(str) > 0 {
			info.SampleStrings = append(info.SampleStrings, str)
		}
	}

	return info, chunkSize, nil
}

func parsePackageChunk(data []byte) (string, []string, error) {
	if len(data) < 288 {
		return "", nil, fmt.Errorf("package chunk too small")
	}

	headerSize := int(binary.LittleEndian.Uint16(data[2:]))

	// Package name is 128 UTF-16LE chars (256 bytes) starting at offset 8 in the package chunk
	// (after type=2, headerSize=2, chunkSize=4 = 8 bytes header, then packageId=4 = offset 12)
	const packageNameOffset = 12
	if packageNameOffset+256 > len(data) {
		return "", nil, fmt.Errorf("insufficient data for package name")
	}

	nameBytes := data[packageNameOffset : packageNameOffset+256]
	packageName := decodeUTF16LE(nameBytes)

	// Type string pool starts after the package header
	offset := headerSize

	var typeNames []string

	if offset+8 <= len(data) {
		chunkType := binary.LittleEndian.Uint16(data[offset:])
		if chunkType == stringPoolType {
			typePool, _, err := parseStringPool(data[offset:])
			if err == nil && typePool != nil {
				typeNames = typePool.SampleStrings
			}
		}
	}

	return packageName, typeNames, nil
}

func readUTF8String(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("insufficient data for UTF-8 string")
	}

	// ARSC UTF-8 string format:
	// - char length: 1 or 2 bytes (high bit = continuation)
	// - byte length: 1 or 2 bytes (high bit = continuation)
	// - UTF-8 data (byteLen bytes)
	// - null terminator
	pos := 0

	// Skip char length
	if data[pos]&0x80 != 0 {
		pos += 2
	} else {
		pos++
	}

	if pos >= len(data) {
		return "", fmt.Errorf("insufficient data for byte length")
	}

	// Read byte length
	var byteLen int
	if data[pos]&0x80 != 0 {
		if pos+1 >= len(data) {
			return "", fmt.Errorf("insufficient data for 2-byte length")
		}
		byteLen = int(data[pos]&0x7F)<<8 | int(data[pos+1])
		pos += 2
	} else {
		byteLen = int(data[pos])
		pos++
	}

	if pos+byteLen > len(data) {
		return "", fmt.Errorf("string data exceeds buffer")
	}

	return string(data[pos : pos+byteLen]), nil
}

func readUTF16String(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("insufficient data for UTF-16 string")
	}

	charCount := int(binary.LittleEndian.Uint16(data[0:]))
	if charCount == 0 {
		return "", nil
	}

	if len(data) < 2+charCount*2 {
		return "", fmt.Errorf("insufficient data for UTF-16 chars")
	}

	chars := make([]uint16, charCount)
	for i := range charCount {
		chars[i] = binary.LittleEndian.Uint16(data[2+i*2:])
	}

	runes := utf16.Decode(chars)
	return string(runes), nil
}

func decodeUTF16LE(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	chars := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		ch := binary.LittleEndian.Uint16(data[i:])
		if ch == 0 {
			break
		}
		chars = append(chars, ch)
	}

	return string(utf16.Decode(chars))
}
