package ios

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// ParseXMLPlist parses an XML property list into a map.
// It handles the common plist value types: dict, array, string, integer, real, true, false, data, and date.
// Binary plist format is not supported; pass only XML plist data.
func ParseXMLPlist(data []byte) (map[string]any, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("plist data too short")
	}

	// Quick check for binary plist
	if len(data) >= 6 && string(data[:6]) == "bplist" {
		return nil, fmt.Errorf("binary plist format not supported; convert to XML with 'plutil -convert xml1' or 'plistutil'")
	}

	var plist xmlPlist
	if err := xml.Unmarshal(data, &plist); err != nil {
		return nil, fmt.Errorf("xml unmarshal: %w", err)
	}

	if plist.Dict == nil {
		return nil, fmt.Errorf("no root <dict> found in plist")
	}

	return convertDict(plist.Dict)
}

// XML structures for plist parsing

type xmlPlist struct {
	XMLName xml.Name `xml:"plist"`
	Dict    *xmlDict `xml:"dict"`
}

type xmlDict struct {
	Items []xmlDictItem
}

type xmlDictItem struct {
	Key   string
	Value xmlValue
}

type xmlValue struct {
	Type     string
	Str      string
	Int      int64
	Float    float64
	Bool     bool
	Dict     *xmlDict
	Array    []xmlValue
	RawBytes []byte
}

// UnmarshalXML decodes a <dict> element which contains alternating <key> and value elements.
func (d *xmlDict) UnmarshalXML(dec *xml.Decoder, start xml.StartElement) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}

		switch t := tok.(type) {
		case xml.EndElement:
			return nil
		case xml.StartElement:
			if t.Name.Local != "key" {
				return fmt.Errorf("expected <key>, got <%s>", t.Name.Local)
			}
			var key string
			if err := dec.DecodeElement(&key, &t); err != nil {
				return fmt.Errorf("decode key: %w", err)
			}

			val, err := decodeNextValue(dec)
			if err != nil {
				return fmt.Errorf("decode value for %q: %w", key, err)
			}
			d.Items = append(d.Items, xmlDictItem{Key: key, Value: val})
		}
	}
}

func decodeNextValue(dec *xml.Decoder) (xmlValue, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return xmlValue{}, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue // skip whitespace
		}
		return decodeValueElement(dec, se)
	}
}

func decodeValueElement(dec *xml.Decoder, se xml.StartElement) (xmlValue, error) {
	switch se.Name.Local {
	case "string", "date":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return xmlValue{}, err
		}
		return xmlValue{Type: "string", Str: s}, nil

	case "integer":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return xmlValue{}, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return xmlValue{}, fmt.Errorf("invalid integer %q: %w", s, err)
		}
		return xmlValue{Type: "integer", Int: n}, nil

	case "real":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return xmlValue{}, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return xmlValue{}, fmt.Errorf("invalid real %q: %w", s, err)
		}
		return xmlValue{Type: "real", Float: f}, nil

	case "true":
		if err := dec.Skip(); err != nil {
			return xmlValue{}, err
		}
		return xmlValue{Type: "bool", Bool: true}, nil

	case "false":
		if err := dec.Skip(); err != nil {
			return xmlValue{}, err
		}
		return xmlValue{Type: "bool", Bool: false}, nil

	case "data":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return xmlValue{}, err
		}
		cleaned := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
				return -1
			}
			return r
		}, s)
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(cleaned)
			if err != nil {
				return xmlValue{Type: "string", Str: s}, nil
			}
		}
		return xmlValue{Type: "data", RawBytes: decoded}, nil

	case "dict":
		var child xmlDict
		if err := dec.DecodeElement(&child, &se); err != nil {
			return xmlValue{}, err
		}
		return xmlValue{Type: "dict", Dict: &child}, nil

	case "array":
		var arr xmlValue
		arr.Type = "array"
		for {
			tok, err := dec.Token()
			if err != nil {
				return xmlValue{}, err
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return arr, nil
			case xml.StartElement:
				v, err := decodeValueElement(dec, t)
				if err != nil {
					return xmlValue{}, err
				}
				arr.Array = append(arr.Array, v)
			}
		}

	default:
		if err := dec.Skip(); err != nil {
			return xmlValue{}, err
		}
		return xmlValue{Type: "unknown"}, nil
	}
}

func convertDict(d *xmlDict) (map[string]any, error) {
	if d == nil {
		return nil, nil
	}
	result := make(map[string]any, len(d.Items))
	for _, item := range d.Items {
		result[item.Key] = convertValue(item.Value)
	}
	return result, nil
}

func convertValue(v xmlValue) any {
	switch v.Type {
	case "string":
		return v.Str
	case "integer":
		return v.Int
	case "real":
		return v.Float
	case "bool":
		return v.Bool
	case "data":
		return string(v.RawBytes)
	case "dict":
		m, _ := convertDict(v.Dict)
		return m
	case "array":
		arr := make([]any, len(v.Array))
		for i, item := range v.Array {
			arr[i] = convertValue(item)
		}
		return arr
	default:
		return nil
	}
}
