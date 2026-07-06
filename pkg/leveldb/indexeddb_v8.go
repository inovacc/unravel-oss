package leveldb

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"
)

// Chromium IndexedDB stores record values as Blink-wrapped V8 structured-clone
// (V8 ValueSerializer) blobs, NOT plain UTF-8/UTF-16. The leveldb parser
// therefore surfaces them only as raw_value_hex / "[binary data]". This file
// decodes the common subset of that format into Go values so every
// Electron/WebView2 app's IndexedDB (Teams, Slack, Discord, VS Code, ...) yields
// structured records instead of opaque bytes.
//
// On-disk layout of one value:
//
//	[Blink wrapper]  FF <ver> FE <16-byte trailer/flags>   (optional, version-dependent)
//	[V8 payload]     FF <ver 0x0A..0x15> <value-tag> ...
//
// We locate the V8 payload (the FF immediately followed by a version byte and a
// value tag), then parse the V8 ValueSerializer tag stream. Validated against
// real Teams (teams.live.com / teams.microsoft.com) IndexedDB stores.

// V8 ValueSerializer tags (the subset Chromium IndexedDB values use).
const (
	v8TagUndefined   = '_' // 0x5F
	v8TagNull        = '0' // 0x30
	v8TagTrue        = 'T' // 0x54
	v8TagFalse       = 'F' // 0x46
	v8TagInt32       = 'I' // 0x49  zigzag varint
	v8TagUint32      = 'U' // 0x55  varint
	v8TagDouble      = 'N' // 0x4E  8-byte LE
	v8TagDate        = 'D' // 0x44  8-byte LE (ms since epoch)
	v8TagUtf8String  = 'S' // 0x53  varint len + utf8
	v8TagOneByteStr  = '"' // 0x22  varint len + latin1
	v8TagTwoByteStr  = 'c' // 0x63  varint len + utf16-le
	v8TagBeginObject = 'o' // 0x6F  pairs until '{', then count
	v8TagEndObject   = '{' // 0x7B
	v8TagBeginArray  = 'A' // 0x41  count, items, props until '$', then 2 varints
	v8TagEndArray    = '$' // 0x24
	v8TagBigInt      = 'Z' // 0x5A  bitfield varint + (bitfield>>4) bytes
)

const (
	// maxIndexedDBValueBytes bounds the decode of a single value (defense vs a
	// pathological length field driving a huge allocation).
	maxIndexedDBValueBytes = 16 << 20
	// maxV8Depth bounds nested object/array recursion.
	maxV8Depth = 96
	// v8ScanWindow bounds the search for the V8 payload start. The Blink wrapper
	// is tiny, so the payload always begins within the first few dozen bytes.
	v8ScanWindow = 80
	// maxV8ArrayPrealloc caps the initial slice capacity hint from a length field.
	maxV8ArrayPrealloc = 4096

	// v8VersionMin/Max bound the plausible V8 ValueSerializer / Blink version
	// byte that follows the 0xFF tag. Kept wide so the sweep tolerates the
	// several wrapper/serializer versions Chromium has shipped (~v9..v22)
	// instead of pinning one.
	v8VersionMin = 0x09
	v8VersionMax = 0x16
	// maxV8Candidates caps how many payload-start variants the sweep tries.
	maxV8Candidates = 12
	// minAcceptScore rejects lone false-positive starts (a stray 0xFF mid-blob
	// that "decodes" to a tiny scalar) — see scoreDecode.
	minAcceptScore = 40
)

// DecodeIndexedDBValue decodes a Chromium IndexedDB record value (V8
// structured-clone behind the Blink wrapper) into a Go value
// (map[string]any / []any / string / int64 / uint64 / float64 / bool / nil).
//
// Returns (value, true) on success; (nil, false) when the bytes carry no V8
// structured-clone payload or cannot be parsed cleanly. Safe to call on any
// value — it self-gates via the payload scan and never panics on malformed input.
//
// Hardening: rather than trusting the first plausible payload start, it SWEEPS
// every candidate start in the scan window (covering the bare-V8, Blink
// trailer-wrapped, and double-version wrapper variants across Chromium versions),
// fully decodes each, and returns the best-scoring clean result — i.e. it tests
// many variants and keeps the one that decodes correctly.
func DecodeIndexedDBValue(raw []byte) (any, bool) {
	v, _, ok := decodeIndexedDBBest(raw)
	return v, ok
}

// decodeIndexedDBBest sweeps candidate V8 payload starts and returns the
// best-scoring clean decode plus its winning start offset (-1 if none).
func decodeIndexedDBBest(raw []byte) (any, int, bool) {
	if len(raw) == 0 || len(raw) > maxIndexedDBValueBytes {
		return nil, -1, false
	}
	var (
		bestVal   any
		bestScore = -1
		bestStart = -1
		tried     int
	)
	lim := len(raw) - 2
	if lim > v8ScanWindow {
		lim = v8ScanWindow
	}
	for i := 0; i <= lim; i++ {
		if raw[i] != 0xFF {
			continue
		}
		if ver := raw[i+1]; ver < v8VersionMin || ver > v8VersionMax {
			continue
		}
		if !isV8ValueTag(raw[i+2]) {
			continue
		}
		tried++
		if tried > maxV8Candidates {
			break
		}
		r := &v8Reader{b: raw, i: i}
		r.u8()      // FF version tag
		r.uvarint() // version number
		v := r.value(0)
		if r.err {
			continue
		}
		if s := scoreDecode(v, r.i-i, len(raw)-i); s > bestScore {
			bestScore, bestVal, bestStart = s, v, i
		}
	}
	if bestStart < 0 || bestScore < minAcceptScore {
		return nil, -1, false
	}
	return bestVal, bestStart, true
}

// scoreDecode ranks a candidate decode: prefer richer container types and
// candidates that consume more of the remaining bytes. Lone tiny scalars from a
// stray mid-blob 0xFF score below minAcceptScore and are rejected.
func scoreDecode(v any, consumed, span int) int {
	kind := 0
	switch t := v.(type) {
	case map[string]any:
		if len(t) > 0 {
			kind = 100
		} else {
			kind = 30
		}
	case []any:
		if len(t) > 0 {
			kind = 80
		} else {
			kind = 25
		}
	case string:
		kind = 25
	case bool, int64, uint64, float64:
		kind = 10
	default: // nil / unknown
		kind = 0
	}
	frac := 0
	if span > 0 {
		frac = consumed * 50 / span
	}
	return kind + frac
}

func isV8ValueTag(t byte) bool {
	switch t {
	case v8TagBeginObject, v8TagBeginArray, v8TagOneByteStr, v8TagTwoByteStr,
		v8TagUtf8String, v8TagInt32, v8TagUint32, v8TagDouble, v8TagDate,
		v8TagTrue, v8TagFalse, v8TagNull, v8TagUndefined, v8TagBigInt:
		return true
	}
	return false
}

type v8Reader struct {
	b   []byte
	i   int
	err bool
}

func (r *v8Reader) u8() byte {
	if r.i >= len(r.b) {
		r.err = true
		return 0
	}
	c := r.b[r.i]
	r.i++
	return c
}

func (r *v8Reader) uvarint() uint64 {
	var res uint64
	var shift uint
	for {
		if r.i >= len(r.b) || shift > 63 {
			r.err = true
			return res
		}
		c := r.b[r.i]
		r.i++
		res |= uint64(c&0x7F) << shift
		if c&0x80 == 0 {
			return res
		}
		shift += 7
	}
}

func (r *v8Reader) zigzag() int64 {
	n := r.uvarint()
	return int64(n>>1) ^ -int64(n&1)
}

func (r *v8Reader) value(depth int) any {
	if r.err || depth > maxV8Depth || r.i >= len(r.b) {
		r.err = true
		return nil
	}
	switch tag := r.u8(); tag {
	case v8TagUndefined, v8TagNull:
		return nil
	case v8TagTrue:
		return true
	case v8TagFalse:
		return false
	case v8TagInt32:
		return r.zigzag()
	case v8TagUint32:
		return r.uvarint()
	case v8TagDouble, v8TagDate:
		if r.i+8 > len(r.b) {
			r.err = true
			return nil
		}
		bits := binary.LittleEndian.Uint64(r.b[r.i:])
		r.i += 8
		return math.Float64frombits(bits)
	case v8TagUtf8String:
		return r.readString(strUTF8)
	case v8TagOneByteStr:
		return r.readString(strLatin1)
	case v8TagTwoByteStr:
		return r.readString(strUTF16LE)
	case v8TagBeginObject:
		obj := map[string]any{}
		for !r.err && r.i < len(r.b) && r.b[r.i] != v8TagEndObject {
			k := r.value(depth + 1)
			v := r.value(depth + 1)
			obj[keyString(k)] = v
		}
		r.u8()      // '{'
		r.uvarint() // property count
		return obj
	case v8TagBeginArray:
		n := r.uvarint()
		if r.err || n > uint64(len(r.b)) {
			r.err = true
			return nil
		}
		arr := make([]any, 0, clampPrealloc(n))
		for j := uint64(0); j < n && !r.err; j++ {
			arr = append(arr, r.value(depth+1))
		}
		for !r.err && r.i < len(r.b) && r.b[r.i] != v8TagEndArray {
			r.value(depth + 1) // trailing sparse/object properties (rare)
		}
		r.u8()      // '$'
		r.uvarint() // properties count
		r.uvarint() // length
		return arr
	case v8TagBigInt:
		bitfield := r.uvarint()
		r.i += int(bitfield >> 4)
		if r.i > len(r.b) {
			r.err = true
		}
		return nil // numeric value not reconstructed; presence is enough
	default:
		r.err = true
		return nil
	}
}

type strEncoding int

const (
	strUTF8 strEncoding = iota
	strLatin1
	strUTF16LE
)

func (r *v8Reader) readString(enc strEncoding) string {
	n := r.uvarint()
	if r.err || n > uint64(len(r.b)-r.i) {
		r.err = true
		return ""
	}
	raw := r.b[r.i : r.i+int(n)]
	r.i += int(n)
	switch enc {
	case strUTF16LE:
		if n%2 != 0 {
			return ""
		}
		u := make([]uint16, n/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(raw[i*2:])
		}
		return string(utf16.Decode(u))
	case strLatin1:
		runes := make([]rune, n)
		for i, b := range raw {
			runes[i] = rune(b)
		}
		return string(runes)
	default: // strUTF8
		return string(raw)
	}
}

func keyString(k any) string {
	if s, ok := k.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", k)
}

func clampPrealloc(n uint64) int {
	if n > maxV8ArrayPrealloc {
		return maxV8ArrayPrealloc
	}
	return int(n)
}
