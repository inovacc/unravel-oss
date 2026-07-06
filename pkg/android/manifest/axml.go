/*
Copyright (c) 2026 Security Research
*/
package manifest

import (
	"encoding/binary"
	"fmt"
)

// AXML chunk types.
const (
	chunkResXMLType        = 0x0003 // RES_XML_TYPE
	chunkStringPool        = 0x0001 // RES_STRING_POOL_TYPE
	chunkResourceIDTable   = 0x0180 // RES_XML_RESOURCE_MAP_TYPE
	chunkXMLNamespaceStart = 0x0100 // RES_XML_START_NAMESPACE_TYPE
	chunkXMLNamespaceEnd   = 0x0101 // RES_XML_END_NAMESPACE_TYPE
	chunkXMLElementStart   = 0x0102 // RES_XML_START_ELEMENT_TYPE
	chunkXMLElementEnd     = 0x0103 // RES_XML_END_ELEMENT_TYPE
	chunkXMLCData          = 0x0104 // RES_XML_CDATA_TYPE
)

// Attribute value types (from ResourceTypes.h).
const (
	typeNull      = 0x00
	typeReference = 0x01
	typeString    = 0x03
	typeFloat     = 0x04
	typeInt       = 0x10
	typeHex       = 0x11
	typeBool      = 0x12
)

// Well-known Android resource IDs for manifest attributes.
const (
	attrVersionCode           = 0x0101021b
	attrVersionName           = 0x0101021c
	attrMinSdkVersion         = 0x0101020c
	attrTargetSdkVersion      = 0x01010270
	attrName                  = 0x01010003
	attrPackage               = 0x01010021 // not used; package comes from <manifest> attrs
	attrExported              = 0x01010010
	attrPermission            = 0x01010006
	attrDebuggable            = 0x0101000f
	attrAllowBackup           = 0x01010280
	attrUsesCleartextTraffic  = 0x010104ec
	attrNetworkSecurityConfig = 0x01010527
	attrScheme                = 0x01010027
	attrHost                  = 0x01010028
	attrPath                  = 0x0101002a
	attrMimeType              = 0x01010026
)

// axmlParser holds state during binary XML parsing.
type axmlParser struct {
	data        []byte
	stringPool  []string
	resourceIDs []uint32
}

// axmlAttribute represents a single attribute of an XML element.
type axmlAttribute struct {
	NamespaceIdx int32
	NameIdx      int32
	ValueStrIdx  int32
	ValueType    uint32
	ValueData    uint32
}

// axmlElement represents a parsed XML element with its attributes.
type axmlElement struct {
	NamespaceIdx int32
	NameIdx      int32
	Attrs        []axmlAttribute
}

// ParseAXML decodes a compiled Android binary XML byte slice into
// a stream of elements that the manifest builder consumes.
func ParseAXML(data []byte) (*Manifest, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("axml: data too short (%d bytes)", len(data))
	}

	magic := binary.LittleEndian.Uint16(data[0:2])
	headerSize := binary.LittleEndian.Uint16(data[2:4])

	if magic != chunkResXMLType {
		return nil, fmt.Errorf("axml: invalid magic 0x%04x (expected 0x%04x)", magic, chunkResXMLType)
	}

	p := &axmlParser{data: data}
	m := &Manifest{
		Security: SecurityFlags{
			AllowBackup: true, // Android default is true
		},
	}

	offset := int(headerSize)

	var (
		elementStack     []axmlElement
		currentFilter    *IntentFilter
		currentComponent *Component
	)

	for offset < len(data) {
		if offset+8 > len(data) {
			break
		}

		chunkType := binary.LittleEndian.Uint16(data[offset:])
		chunkSize := int(binary.LittleEndian.Uint32(data[offset+4:]))

		if chunkSize < 8 || offset+chunkSize > len(data) {
			break
		}

		switch chunkType {
		case chunkStringPool:
			if err := p.parseStringPool(data[offset : offset+chunkSize]); err != nil {
				return nil, fmt.Errorf("axml: string pool: %w", err)
			}

		case chunkResourceIDTable:
			p.parseResourceIDs(data[offset : offset+chunkSize])

		case chunkXMLElementStart:
			elem, err := p.parseElementStart(data[offset : offset+chunkSize])
			if err != nil {
				offset += chunkSize
				continue
			}

			elementStack = append(elementStack, *elem)

			elemName := p.getString(int(elem.NameIdx))

			switch elemName {
			case "manifest":
				p.processManifest(elem, m)
			case "uses-sdk":
				p.processUsesSdk(elem, m)
			case "uses-permission":
				p.processUsesPermission(elem, m)
			case "uses-feature":
				p.processUsesFeature(elem, m)
			case "application":
				p.processApplication(elem, m)
			case "activity", "activity-alias":
				comp := p.processComponent(elem, ComponentActivity)
				currentComponent = comp
				m.Components = append(m.Components, *comp)
			case "service":
				comp := p.processComponent(elem, ComponentService)
				currentComponent = comp
				m.Components = append(m.Components, *comp)
			case "receiver":
				comp := p.processComponent(elem, ComponentReceiver)
				currentComponent = comp
				m.Components = append(m.Components, *comp)
			case "provider":
				comp := p.processComponent(elem, ComponentProvider)
				currentComponent = comp
				m.Components = append(m.Components, *comp)
			case "intent-filter":
				currentFilter = &IntentFilter{}
			case "action":
				if currentFilter != nil {
					name := p.getAttrStringByResID(elem, attrName)
					if name != "" {
						currentFilter.Actions = append(currentFilter.Actions, name)
					}
				}
			case "category":
				if currentFilter != nil {
					name := p.getAttrStringByResID(elem, attrName)
					if name != "" {
						currentFilter.Categories = append(currentFilter.Categories, name)
					}
				}
			case "data":
				if currentFilter != nil {
					d := IntentFilterData{
						Scheme:   p.getAttrStringByResID(elem, attrScheme),
						Host:     p.getAttrStringByResID(elem, attrHost),
						Path:     p.getAttrStringByResID(elem, attrPath),
						MimeType: p.getAttrStringByResID(elem, attrMimeType),
					}
					if d.Scheme != "" || d.Host != "" || d.Path != "" || d.MimeType != "" {
						currentFilter.Data = append(currentFilter.Data, d)
					}
				}
			}

		case chunkXMLElementEnd:
			if len(elementStack) > 0 {
				closing := elementStack[len(elementStack)-1]
				elementStack = elementStack[:len(elementStack)-1]
				closingName := p.getString(int(closing.NameIdx))

				if closingName == "intent-filter" && currentFilter != nil && currentComponent != nil {
					// Attach to last component.
					idx := len(m.Components) - 1
					if idx >= 0 {
						m.Components[idx].IntentFilters = append(m.Components[idx].IntentFilters, *currentFilter)
					}

					currentFilter = nil
				}

				switch closingName {
				case "activity", "activity-alias", "service", "receiver", "provider":
					currentComponent = nil
				}
			}

		case chunkXMLNamespaceStart, chunkXMLNamespaceEnd, chunkXMLCData:
			// Skip namespace and CDATA chunks.
		}

		offset += chunkSize
	}

	return m, nil
}

// parseStringPool decodes the string pool chunk.
func (p *axmlParser) parseStringPool(chunk []byte) error {
	if len(chunk) < 28 {
		return fmt.Errorf("string pool too short")
	}

	stringCount := int(binary.LittleEndian.Uint32(chunk[8:12]))
	flags := binary.LittleEndian.Uint32(chunk[16:20])
	stringsStart := int(binary.LittleEndian.Uint32(chunk[20:24]))

	isUTF8 := flags&(1<<8) != 0

	if stringCount == 0 {
		return nil
	}

	// SEC: cap stringCount against the actual chunk data and an absolute maximum.
	// This prevents make([]int, ~500M) on a crafted AXML with a giant chunk.
	const maxStringPoolEntries = 1 << 17 // 131 072; far more than any real manifest needs
	if stringCount > maxStringPoolEntries {
		return fmt.Errorf("string pool: stringCount %d exceeds limit %d", stringCount, maxStringPoolEntries)
	}

	// Read string offsets.
	offsetsStart := 28
	if offsetsStart+stringCount*4 > len(chunk) {
		return fmt.Errorf("string offsets overflow")
	}

	offsets := make([]int, stringCount)
	for i := range stringCount {
		offsets[i] = int(binary.LittleEndian.Uint32(chunk[offsetsStart+i*4:]))
	}

	p.stringPool = make([]string, stringCount)

	for i, off := range offsets {
		absOff := stringsStart + off
		if absOff >= len(chunk) {
			continue
		}

		if isUTF8 {
			p.stringPool[i] = decodeUTF8String(chunk[absOff:])
		} else {
			p.stringPool[i] = decodeUTF16String(chunk[absOff:])
		}
	}

	return nil
}

// decodeUTF8String decodes a string pool UTF-8 entry.
// Format: charLen (1 or 2 bytes), byteLen (1 or 2 bytes), data, null terminator.
func decodeUTF8String(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	pos := 0

	// Skip char length (1 or 2 bytes).
	if data[pos]&0x80 != 0 {
		pos += 2
	} else {
		pos++
	}

	if pos >= len(data) {
		return ""
	}

	// Byte length (1 or 2 bytes).
	byteLen := 0

	if data[pos]&0x80 != 0 {
		if pos+1 >= len(data) {
			return ""
		}

		byteLen = int(data[pos]&0x7f)<<8 | int(data[pos+1])
		pos += 2
	} else {
		byteLen = int(data[pos])
		pos++
	}

	if pos+byteLen > len(data) {
		byteLen = len(data) - pos
	}

	return string(data[pos : pos+byteLen])
}

// decodeUTF16String decodes a string pool UTF-16LE entry.
// Format: charLen (2 or 4 bytes), data, null terminator.
func decodeUTF16String(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	charLen := int(binary.LittleEndian.Uint16(data[0:2]))
	pos := 2

	// High bit set means 4-byte length.
	if charLen&0x8000 != 0 {
		if len(data) < 4 {
			return ""
		}

		charLen = (charLen&0x7fff)<<16 | int(binary.LittleEndian.Uint16(data[2:4]))
		pos = 4
	}

	end := min(pos+charLen*2, len(data))

	// Decode UTF-16LE.
	var result []byte

	for i := pos; i+1 < end; i += 2 {
		c := binary.LittleEndian.Uint16(data[i : i+2])
		if c == 0 {
			break
		}

		if c < 0x80 {
			result = append(result, byte(c))
		} else if c < 0x800 {
			result = append(result, byte(0xc0|c>>6), byte(0x80|c&0x3f))
		} else {
			result = append(result, byte(0xe0|c>>12), byte(0x80|(c>>6)&0x3f), byte(0x80|c&0x3f))
		}
	}

	return string(result)
}

// parseResourceIDs decodes the resource ID map chunk.
func (p *axmlParser) parseResourceIDs(chunk []byte) {
	if len(chunk) < 8 {
		return
	}

	headerSize := int(binary.LittleEndian.Uint16(chunk[2:4]))
	count := (len(chunk) - headerSize) / 4

	p.resourceIDs = make([]uint32, count)
	for i := range count {
		off := headerSize + i*4
		if off+4 <= len(chunk) {
			p.resourceIDs[i] = binary.LittleEndian.Uint32(chunk[off:])
		}
	}
}

// parseElementStart decodes an XML element start chunk.
func (p *axmlParser) parseElementStart(chunk []byte) (*axmlElement, error) {
	headerSize := int(binary.LittleEndian.Uint16(chunk[2:4]))
	if len(chunk) < headerSize+20 {
		return nil, fmt.Errorf("element start chunk too short")
	}

	elem := &axmlElement{
		NamespaceIdx: int32(binary.LittleEndian.Uint32(chunk[headerSize:])),
		NameIdx:      int32(binary.LittleEndian.Uint32(chunk[headerSize+4:])),
	}

	attrStart := headerSize + int(binary.LittleEndian.Uint16(chunk[headerSize+8:]))
	attrCount := int(binary.LittleEndian.Uint16(chunk[headerSize+12:]))

	attrSize := int(binary.LittleEndian.Uint16(chunk[headerSize+10:]))
	// SEC: attrSize==0 is invalid per spec (must be exactly 20); treat as error
	// rather than silently defaulting so callers get accurate parse failures.
	if attrSize == 0 {
		return nil, fmt.Errorf("element start: attrSize is 0, expected 20")
	}

	// SEC: validate attrStart is within the chunk before indexing.
	if attrStart >= len(chunk) {
		return nil, fmt.Errorf("element start: attrStart %d exceeds chunk length %d", attrStart, len(chunk))
	}

	for i := range attrCount {
		off := attrStart + i*attrSize
		if off+20 > len(chunk) {
			break
		}

		attr := axmlAttribute{
			NamespaceIdx: int32(binary.LittleEndian.Uint32(chunk[off:])),
			NameIdx:      int32(binary.LittleEndian.Uint32(chunk[off+4:])),
			ValueStrIdx:  int32(binary.LittleEndian.Uint32(chunk[off+8:])),
			ValueType:    uint32(chunk[off+15]) >> 0, // TypedValue type byte
			ValueData:    binary.LittleEndian.Uint32(chunk[off+16:]),
		}
		// The type byte is at offset+15 (size=8 is at +12, res0 at +13, dataType at +15).
		attr.ValueType = uint32(chunk[off+15])

		elem.Attrs = append(elem.Attrs, attr)
	}

	return elem, nil
}

// getString returns a string from the pool, or "" if out of range.
func (p *axmlParser) getString(idx int) string {
	if idx < 0 || idx >= len(p.stringPool) {
		return ""
	}

	return p.stringPool[idx]
}

// getResourceID returns the Android resource ID for a string pool index.
func (p *axmlParser) getResourceID(nameIdx int) uint32 {
	if nameIdx < 0 || nameIdx >= len(p.resourceIDs) {
		return 0
	}

	return p.resourceIDs[nameIdx]
}

// getAttrStringByResID finds an attribute by its Android resource ID and
// returns its string value.
func (p *axmlParser) getAttrStringByResID(elem *axmlElement, resID uint32) string {
	for _, attr := range elem.Attrs {
		rid := p.getResourceID(int(attr.NameIdx))
		if rid == resID {
			return p.attrStringValue(&attr)
		}
	}

	return ""
}

// getAttrIntByResID finds an attribute by its Android resource ID and
// returns its integer value.
func (p *axmlParser) getAttrIntByResID(elem *axmlElement, resID uint32) (int64, bool) {
	for _, attr := range elem.Attrs {
		rid := p.getResourceID(int(attr.NameIdx))
		if rid == resID {
			switch attr.ValueType {
			case typeInt, typeHex:
				return int64(attr.ValueData), true
			}
		}
	}

	return 0, false
}

// getAttrBoolByResID finds a boolean attribute by its Android resource ID.
func (p *axmlParser) getAttrBoolByResID(elem *axmlElement, resID uint32) (bool, bool) {
	for _, attr := range elem.Attrs {
		rid := p.getResourceID(int(attr.NameIdx))
		if rid == resID {
			switch attr.ValueType {
			case typeBool:
				return attr.ValueData != 0, true
			case typeInt, typeHex:
				return attr.ValueData != 0, true
			}
		}
	}

	return false, false
}

// attrStringValue extracts the string value from an attribute.
func (p *axmlParser) attrStringValue(attr *axmlAttribute) string {
	switch attr.ValueType {
	case typeString:
		return p.getString(int(attr.ValueStrIdx))
	case typeReference:
		return fmt.Sprintf("@0x%08x", attr.ValueData)
	case typeInt:
		return fmt.Sprintf("%d", attr.ValueData)
	case typeHex:
		return fmt.Sprintf("0x%x", attr.ValueData)
	case typeBool:
		if attr.ValueData != 0 {
			return "true"
		}

		return "false"
	default:
		// Fallback: try raw string index.
		if attr.ValueStrIdx >= 0 {
			return p.getString(int(attr.ValueStrIdx))
		}

		return ""
	}
}

// processManifest extracts package, versionCode, versionName from <manifest>.
func (p *axmlParser) processManifest(elem *axmlElement, m *Manifest) {
	// Package is typically the first string-type attribute named "package".
	// Since "package" is not in the android: namespace resource IDs,
	// we look for it by string name.
	for _, attr := range elem.Attrs {
		name := p.getString(int(attr.NameIdx))
		switch name {
		case "package":
			m.Package = p.attrStringValue(&attr)
		case "platformBuildVersionCode", "compileSdkVersion":
			// Skip these.
		}
	}

	if v, ok := p.getAttrIntByResID(elem, attrVersionCode); ok {
		m.VersionCode = v
	}

	m.VersionName = p.getAttrStringByResID(elem, attrVersionName)
}

// processUsesSdk extracts minSdkVersion and targetSdkVersion.
func (p *axmlParser) processUsesSdk(elem *axmlElement, m *Manifest) {
	if v, ok := p.getAttrIntByResID(elem, attrMinSdkVersion); ok {
		m.MinSDK = int(v)
	}

	if v, ok := p.getAttrIntByResID(elem, attrTargetSdkVersion); ok {
		m.TargetSDK = int(v)
	}
}

// processUsesPermission adds a permission to the manifest.
func (p *axmlParser) processUsesPermission(elem *axmlElement, m *Manifest) {
	name := p.getAttrStringByResID(elem, attrName)
	if name == "" {
		// Try raw string match.
		for _, attr := range elem.Attrs {
			if p.getString(int(attr.NameIdx)) == "name" {
				name = p.attrStringValue(&attr)
				break
			}
		}
	}

	if name == "" {
		return
	}

	m.Permissions = append(m.Permissions, Permission{
		Name:      name,
		RiskLevel: ClassifyPermission(name),
	})
}

// processUsesFeature adds a feature to the manifest.
func (p *axmlParser) processUsesFeature(elem *axmlElement, m *Manifest) {
	name := p.getAttrStringByResID(elem, attrName)
	if name == "" {
		for _, attr := range elem.Attrs {
			if p.getString(int(attr.NameIdx)) == "name" {
				name = p.attrStringValue(&attr)
				break
			}
		}
	}

	if name != "" {
		m.Features = append(m.Features, name)
	}
}

// processApplication extracts security flags from <application>.
func (p *axmlParser) processApplication(elem *axmlElement, m *Manifest) {
	if v, ok := p.getAttrBoolByResID(elem, attrDebuggable); ok {
		m.Security.Debuggable = v
	}

	if v, ok := p.getAttrBoolByResID(elem, attrAllowBackup); ok {
		m.Security.AllowBackup = v
	}

	if v, ok := p.getAttrBoolByResID(elem, attrUsesCleartextTraffic); ok {
		m.Security.UsesCleartextTraffic = v
	}
	// networkSecurityConfig is a resource reference, so just check existence.
	nsc := p.getAttrStringByResID(elem, attrNetworkSecurityConfig)
	if nsc != "" {
		m.Security.NetworkSecurityConfig = true
	}
}

// processComponent extracts a component declaration.
func (p *axmlParser) processComponent(elem *axmlElement, compType ComponentType) *Component {
	comp := &Component{
		Type: compType,
	}

	comp.Name = p.getAttrStringByResID(elem, attrName)
	if comp.Name == "" {
		for _, attr := range elem.Attrs {
			if p.getString(int(attr.NameIdx)) == "name" {
				comp.Name = p.attrStringValue(&attr)
				break
			}
		}
	}

	if v, ok := p.getAttrBoolByResID(elem, attrExported); ok {
		comp.Exported = &v
	}

	comp.Permission = p.getAttrStringByResID(elem, attrPermission)

	return comp
}
