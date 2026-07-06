// Package sig decodes ECMA-335 II.23.2 signature blobs (MethodDef, Field,
// LocalVar) into a TypeSig element-type tree with an IL-style printer.
package sig

import (
	"errors"
	"fmt"
	"io"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"
)

// ErrIllegalCompressedInt is returned when a compressed integer uses a
// reserved lead-byte form (0xE0..0xFF). Obfuscators emit these to desync
// length-prefixed parsers; we fail loud rather than mask.
var ErrIllegalCompressedInt = errors.New("illegal compressed integer encoding")

// ErrShortBlob is returned when a signature blob ends mid-element.
var ErrShortBlob = errors.New("signature blob truncated")

// decompressUint decodes one II.23.2 compressed unsigned integer from the
// front of b, returning the value and the number of bytes consumed.
func decompressUint(b []byte) (uint32, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("compressed uint: %w", io.ErrUnexpectedEOF)
	}
	switch lead := b[0]; {
	case lead&0x80 == 0x00: // 0xxxxxxx -> 1 byte
		return uint32(lead), 1, nil
	case lead&0xC0 == 0x80: // 10xxxxxx -> 2 bytes
		if len(b) < 2 {
			return 0, 0, fmt.Errorf("compressed uint (2-byte): %w", io.ErrUnexpectedEOF)
		}
		return (uint32(lead&0x3F) << 8) | uint32(b[1]), 2, nil
	case lead&0xE0 == 0xC0: // 110xxxxx -> 4 bytes
		if len(b) < 4 {
			return 0, 0, fmt.Errorf("compressed uint (4-byte): %w", io.ErrUnexpectedEOF)
		}
		return (uint32(lead&0x1F) << 24) | (uint32(b[1]) << 16) |
			(uint32(b[2]) << 8) | uint32(b[3]), 4, nil
	default: // 111xxxxx reserved/illegal
		return 0, 0, fmt.Errorf("lead byte %#02x: %w", lead, ErrIllegalCompressedInt)
	}
}

// Calling-convention bits (ECMA-335 II.23.2.3).
const (
	ccHasThis      = 0x20
	ccExplicitThis = 0x40
	ccGeneric      = 0x10
	ccMaskKind     = 0x0F
)

// DecodeMethodSig decodes a MethodDefSig / MethodRefSig blob (II.23.2.1).
func DecodeMethodSig(blob []byte) (MethodSig, error) {
	c := &cursor{b: blob}
	cc, err := c.byte()
	if err != nil {
		return MethodSig{}, fmt.Errorf("method sig: %w", err)
	}
	ms := MethodSig{
		HasThis:  cc&ccHasThis != 0,
		CallConv: cc & ccMaskKind,
	}
	if cc&ccGeneric != 0 {
		if _, err := c.uint(); err != nil { // GenParamCount, recorded by skipping
			return MethodSig{}, fmt.Errorf("method sig genparamcount: %w", err)
		}
	}
	paramCount, err := c.uint()
	if err != nil {
		return MethodSig{}, fmt.Errorf("method sig paramcount: %w", err)
	}
	ret, err := decodeType(c)
	if err != nil {
		return MethodSig{}, fmt.Errorf("method sig ret: %w", err)
	}
	ms.Ret = ret
	ms.Params = make([]TypeSig, 0, paramCount)
	for i := uint32(0); i < paramCount; i++ {
		p, err := decodeType(c)
		if err != nil {
			return MethodSig{}, fmt.Errorf("method sig param %d: %w", i, err)
		}
		ms.Params = append(ms.Params, p)
	}
	return ms, nil
}

// fieldSigLead is the leading calling-convention byte for FieldSig (II.23.2.4).
const fieldSigLead = 0x06

// DecodeFieldSig decodes a FieldSig blob: FIELD CustomMod* Type (II.23.2.4).
func DecodeFieldSig(blob []byte) (TypeSig, error) {
	c := &cursor{b: blob}
	lead, err := c.byte()
	if err != nil {
		return TypeSig{}, fmt.Errorf("field sig: %w", err)
	}
	if lead != fieldSigLead {
		return TypeSig{}, fmt.Errorf("field sig: bad lead byte %#02x, want 0x06", lead)
	}
	ts, err := decodeType(c)
	if err != nil {
		return TypeSig{}, fmt.Errorf("field sig type: %w", err)
	}
	return ts, nil
}

// cursor is a forward-only blob reader shared by the decoders.
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) eof() bool { return c.pos >= len(c.b) }

func (c *cursor) byte() (byte, error) {
	if c.pos >= len(c.b) {
		return 0, fmt.Errorf("read byte: %w", ErrShortBlob)
	}
	v := c.b[c.pos]
	c.pos++
	return v, nil
}

func (c *cursor) uint() (uint32, error) {
	v, n, err := decompressUint(c.b[c.pos:])
	if err != nil {
		return 0, err
	}
	c.pos += n
	return v, nil
}

// typeDefOrRefTags maps the 2-bit II.23.2.8 tag to a metadata table id.
var typeDefOrRefTags = [4]byte{0x02, 0x01, 0x1B, 0x00} // TypeDef, TypeRef, TypeSpec, (unused)

// decodeTypeDefOrRef reads a compressed coded index and returns a clrtok.Token.
func decodeTypeDefOrRef(c *cursor) (clrtok.Token, error) {
	coded, err := c.uint()
	if err != nil {
		return 0, err
	}
	tag := coded & 0x3
	rid := coded >> 2
	table := typeDefOrRefTags[tag]
	if table == 0x00 {
		return 0, fmt.Errorf("typedeforref: reserved tag %d", tag)
	}
	return clrtok.Token(uint32(table)<<24 | (rid & 0x00FFFFFF)), nil
}

// decodeType decodes one TypeSig from the cursor (II.23.2.12), skipping
// custom modifiers and PINNED markers per II.23.2.7.
func decodeType(c *cursor) (TypeSig, error) {
	for {
		et, err := c.byte()
		if err != nil {
			return TypeSig{}, err
		}
		switch ElementType(et) {
		case etCModReqd, etCModOpt:
			if _, err := decodeTypeDefOrRef(c); err != nil {
				return TypeSig{}, err
			}
			continue // modifier prefixes the following type
		case etPinned, etSentinel:
			continue
		}
		return decodeTypeBody(c, ElementType(et))
	}
}

func decodeTypeBody(c *cursor, et ElementType) (TypeSig, error) {
	switch et {
	case ETVoid, ETBoolean, ETChar, ETI1, ETU1, ETI2, ETU2, ETI4, ETU4,
		ETI8, ETU8, ETR4, ETR8, ETString, ETI, ETU, ETObject, ETTypedByRef:
		return TypeSig{Kind: et}, nil
	case ETClass, ETValueType:
		tok, err := decodeTypeDefOrRef(c)
		if err != nil {
			return TypeSig{}, err
		}
		return TypeSig{Kind: et, Token: tok}, nil
	case ETPtr, ETByRef, ETSZArray:
		inner, err := decodeType(c)
		if err != nil {
			return TypeSig{}, err
		}
		return TypeSig{Kind: et, Elem: &inner}, nil
	case ETVar, ETMVar:
		idx, err := c.uint()
		if err != nil {
			return TypeSig{}, err
		}
		return TypeSig{Kind: et, GenIndex: idx}, nil
	case ETGenericInst:
		base, err := decodeType(c)
		if err != nil {
			return TypeSig{}, err
		}
		argc, err := c.uint()
		if err != nil {
			return TypeSig{}, err
		}
		args := make([]TypeSig, 0, argc)
		for i := uint32(0); i < argc; i++ {
			a, err := decodeType(c)
			if err != nil {
				return TypeSig{}, err
			}
			args = append(args, a)
		}
		return TypeSig{Kind: et, Elem: &base, Args: args}, nil
	case ETArray:
		return decodeArrayShape(c)
	default:
		return TypeSig{}, fmt.Errorf("unsupported element type %#02x", byte(et))
	}
}

// decodeArrayShape decodes ARRAY: Type rank numSizes size* numLoBounds lo*
// (II.23.2.13). Sizes/bounds are consumed but only Rank is retained.
func decodeArrayShape(c *cursor) (TypeSig, error) {
	inner, err := decodeType(c)
	if err != nil {
		return TypeSig{}, err
	}
	rank, err := c.uint()
	if err != nil {
		return TypeSig{}, err
	}
	numSizes, err := c.uint()
	if err != nil {
		return TypeSig{}, err
	}
	for i := uint32(0); i < numSizes; i++ {
		if _, err := c.uint(); err != nil {
			return TypeSig{}, err
		}
	}
	numLo, err := c.uint()
	if err != nil {
		return TypeSig{}, err
	}
	for i := uint32(0); i < numLo; i++ {
		if _, err := c.uint(); err != nil {
			return TypeSig{}, err
		}
	}
	return TypeSig{Kind: ETArray, Elem: &inner, Rank: rank}, nil
}

// localSigLead is the leading byte for LocalVarSig (II.23.2.6).
const localSigLead = 0x07

// DecodeLocalVarSig decodes a LocalVarSig blob: LOCAL_SIG Count (Constraint*
// ByRef? Type)+ (II.23.2.6). Constraint (PINNED) and custom-mod prefixes are
// skipped by decodeType.
func DecodeLocalVarSig(blob []byte) ([]TypeSig, error) {
	c := &cursor{b: blob}
	lead, err := c.byte()
	if err != nil {
		return nil, fmt.Errorf("localvar sig: %w", err)
	}
	if lead != localSigLead {
		return nil, fmt.Errorf("localvar sig: bad lead byte %#02x, want 0x07", lead)
	}
	count, err := c.uint()
	if err != nil {
		return nil, fmt.Errorf("localvar sig count: %w", err)
	}
	locals := make([]TypeSig, 0, count)
	for i := uint32(0); i < count; i++ {
		ts, err := decodeType(c)
		if err != nil {
			return nil, fmt.Errorf("localvar sig local %d: %w", i, err)
		}
		locals = append(locals, ts)
	}
	return locals, nil
}

// tokenString formats a metadata token as 0xTTRRRRRR (table byte + 24-bit RID).
func tokenString(t clrtok.Token) string {
	return fmt.Sprintf("0x%08x", uint32(t))
}
