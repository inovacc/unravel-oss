/*
Copyright (c) 2026 Security Research
*/

// Package il reads CLR method bodies and disassembles IL (ECMA-335 II.25.4).
package il

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"
)

// Token is the metadata token type, aliased from the canonical clr package.
type Token = clrtok.Token

// EHClause is one exception-handling region (ECMA-335 II.25.4.6).
//
// ClassTokenOrFilter is a tagged union discriminated by Flags: when
// Flags&COR_ILEXCEPTION_CLAUSE_FILTER (0x0001) is set the handler is a filter
// and ClassTokenOrFilter holds the byte offset of the filter clause within the
// method body; otherwise (a typed catch) it holds the metadata class token of
// the caught exception type. For finally/fault clauses (Flags 0x0002/0x0004)
// the field is unused and reads as 0.
type EHClause struct {
	Flags                                                                  uint32
	TryOffset, TryLength, HandlerOffset, HandlerLength, ClassTokenOrFilter uint32
}

// IsFilter reports whether this clause's handler is a filter, in which case
// ClassTokenOrFilter is a filter offset rather than a class token.
func (e EHClause) IsFilter() bool { return e.Flags&ehFlagFilter != 0 }

// MethodBody is a decoded managed method body. IsNative is true when the
// method has no IL body (native/runtime/extern); Code/EH are then empty.
type MethodBody struct {
	MaxStack       uint16
	Code           []byte
	LocalVarSigTok Token
	EH             []EHClause
	IsNative       bool
}

const (
	corILMethodTinyFormat = 0x02
	corILMethodFatFormat  = 0x03
	corILMethodMoreSects  = 0x08
	corILMethodInitLocals = 0x10

	tinyMaxStack = 8 // ECMA-335 II.25.4.2: tiny bodies have an implicit maxstack of 8.

	// ehFlagFilter is COR_ILEXCEPTION_CLAUSE_FILTER (ECMA-335 II.25.4.6): when set
	// on an EHClause, ClassTokenOrFilter is a filter offset, not a class token.
	// Declared here (not in M1-T7) so EHClause.IsFilter() compiles from M1-T1.
	ehFlagFilter = 0x0001

	// maxMethodCodeSize caps a single fat method body's IL byte count. A real
	// method body is far smaller; this only rejects malformed/hostile headers
	// that would otherwise drive a ~4 GiB allocation from codeSize.
	maxMethodCodeSize = 64 << 20 // 64 MiB

	// maxEHSections bounds the chained EH section walk so a crafted MoreSects
	// chain cannot spin forever.
	maxEHSections = 4096
)

var (
	errShortBody     = errors.New("method body truncated")
	errOversizedBody = errors.New("method body code size exceeds cap")
)

// ReadMethodBody reads the method body at rva. implFlags gates native methods
// (see gateNative). On a native/extern method it returns a body with
// IsNative=true and no error.
func ReadMethodBody(ra io.ReaderAt, rvaToOffset func(uint32) (int, bool), rva uint32, implFlags uint16) (*MethodBody, error) {
	if mb, native := gateNative(rva, implFlags); native {
		return mb, nil
	}
	off, ok := rvaToOffset(rva)
	if !ok {
		return nil, fmt.Errorf("method body rva %#x: %w", rva, errUnmappableRVA)
	}
	var first [1]byte
	if _, err := ra.ReadAt(first[:], int64(off)); err != nil {
		return nil, fmt.Errorf("read body header at %#x: %w", off, err)
	}
	switch first[0] & 0x03 {
	case corILMethodTinyFormat:
		return readTiny(ra, off, first[0])
	case corILMethodFatFormat:
		return readFat(ra, off)
	default:
		return nil, fmt.Errorf("body at %#x: %w: header byte %#x", off, errBadHeader, first[0])
	}
}

var (
	errUnmappableRVA = errors.New("method body rva not mappable to file offset")
	errBadHeader     = errors.New("unrecognized method body header")
)

func readTiny(ra io.ReaderAt, off int, hdr byte) (*MethodBody, error) {
	codeLen := int(hdr >> 2)
	code := make([]byte, codeLen)
	if _, err := ra.ReadAt(code, int64(off)+1); err != nil {
		return nil, fmt.Errorf("read tiny code: %w", errShortBody)
	}
	return &MethodBody{MaxStack: tinyMaxStack, Code: code}, nil
}

func readFat(ra io.ReaderAt, off int) (*MethodBody, error) {
	var h [12]byte
	if _, err := ra.ReadAt(h[:], int64(off)); err != nil {
		return nil, fmt.Errorf("read fat header: %w", errShortBody)
	}
	flagsAndSize := binary.LittleEndian.Uint16(h[0:])
	flags := flagsAndSize & 0x0FFF
	hdrDwords := int(flagsAndSize >> 12)
	if hdrDwords < 3 {
		return nil, fmt.Errorf("fat header dwords=%d: %w", hdrDwords, errBadHeader)
	}
	maxStack := binary.LittleEndian.Uint16(h[2:])
	codeSize := binary.LittleEndian.Uint32(h[4:])
	localTok := Token(binary.LittleEndian.Uint32(h[8:]))

	// SEC (resource-exhaustion): codeSize is attacker-controlled (up to ~4 GiB).
	// Reject anything past a sane ceiling BEFORE allocating, so a tiny crafted
	// PE with codeSize=0xFFFFFFFF cannot OOM the host. Real IL method bodies are
	// orders of magnitude smaller than maxMethodCodeSize and by definition must
	// fit within the image.
	if codeSize > maxMethodCodeSize {
		return nil, fmt.Errorf("fat code size %d exceeds cap: %w", codeSize, errOversizedBody)
	}

	hdrLen := hdrDwords * 4
	code := make([]byte, codeSize)
	if _, err := ra.ReadAt(code, int64(off)+int64(hdrLen)); err != nil {
		return nil, fmt.Errorf("read fat code: %w", errShortBody)
	}
	mb := &MethodBody{MaxStack: maxStack, Code: code, LocalVarSigTok: localTok}
	if flags&corILMethodMoreSects != 0 {
		eh, err := readEHSections(ra, off+hdrLen+int(codeSize))
		if err != nil {
			return nil, err
		}
		mb.EH = eh
	}
	_ = flags & corILMethodInitLocals // initlocals not surfaced in M1
	return mb, nil
}

// CorMethodImpl flags (ECMA-335 II.23.1.11 / CorHdr.h). A method with any of
// these, or with RVA==0, has no IL body to disassemble.
const (
	miCodeTypeMask = 0x0003 // miIL=0, miNative=1, miOPTIL=2, miRuntime=3
	miNative       = 0x0001
	miOPTIL        = 0x0002
	miRuntime      = 0x0003
	miManagedMask  = 0x0004 // bit set => miUnmanaged
	miInternalCall = 0x1000
	miPInvoke      = 0x2000 // miForwardRef + DllImport surrogate in our gate
)

// gateNative reports whether the method has no managed IL body. When true it
// returns a populated *MethodBody{IsNative:true}; callers must not parse bytes.
func gateNative(rva uint32, implFlags uint16) (*MethodBody, bool) {
	codeType := implFlags & miCodeTypeMask
	native := rva == 0 ||
		codeType == miNative ||
		codeType == miOPTIL ||
		codeType == miRuntime ||
		implFlags&miManagedMask != 0 ||
		implFlags&miInternalCall != 0 ||
		implFlags&miPInvoke != 0
	if !native {
		return nil, false
	}
	return &MethodBody{IsNative: true}, true
}

// EH section kind flags (ECMA-335 II.25.4.5).
const (
	corILMethodSectEHTable    = 0x01
	corILMethodSectOptILTable = 0x02
	corILMethodSectFatFormat  = 0x40
	corILMethodSectMoreSects  = 0x80
)

// ehFlagFilter (COR_ILEXCEPTION_CLAUSE_FILTER, 0x0001) is declared in M1-T1's
// const block alongside EHClause.IsFilter() — do NOT redeclare it here.

// readEHSections reads one or more chained EH section descriptors starting at
// off (already 4-byte aligned past the code).
func readEHSections(ra io.ReaderAt, off int) ([]EHClause, error) {
	var clauses []EHClause
	for sections := 0; ; sections++ {
		// SEC (resource-exhaustion): bound the chained-section walk so a crafted
		// MoreSects chain cannot spin forever.
		if sections >= maxEHSections {
			return nil, fmt.Errorf("EH section chain exceeds %d: %w", maxEHSections, errBadHeader)
		}
		// 4-byte align section start.
		if off%4 != 0 {
			off += 4 - off%4
		}
		var hdr [4]byte
		if _, err := ra.ReadAt(hdr[:], int64(off)); err != nil {
			return nil, fmt.Errorf("read EH section header: %w", errShortBody)
		}
		kind := hdr[0]
		fat := kind&corILMethodSectFatFormat != 0
		var dataSize int
		if fat {
			dataSize = int(hdr[1]) | int(hdr[2])<<8 | int(hdr[3])<<16 // 24-bit
		} else {
			dataSize = int(hdr[1])
		}
		if kind&corILMethodSectEHTable != 0 {
			cs, err := readEHClauses(ra, off+4, dataSize, fat)
			if err != nil {
				return nil, err
			}
			clauses = append(clauses, cs...)
		}
		if kind&corILMethodSectMoreSects == 0 {
			break
		}
		// SEC (infinite-loop): a valid EH section header is at least 4 bytes; a
		// dataSize < 4 (e.g. 0) would make `off += dataSize` a no-op once aligned
		// and re-read the same header forever. Require forward progress.
		if dataSize < 4 {
			return nil, fmt.Errorf("EH section dataSize %d too small: %w", dataSize, errBadHeader)
		}
		off += dataSize
	}
	return clauses, nil
}

func readEHClauses(ra io.ReaderAt, off, dataSize int, fat bool) ([]EHClause, error) {
	clauseSize := 12
	if fat {
		clauseSize = 24
	}
	n := (dataSize - 4) / clauseSize
	buf := make([]byte, n*clauseSize)
	if _, err := ra.ReadAt(buf, int64(off)); err != nil {
		return nil, fmt.Errorf("read EH clauses: %w", errShortBody)
	}
	out := make([]EHClause, 0, n)
	for i := 0; i < n; i++ {
		c := buf[i*clauseSize:]
		var e EHClause
		if fat {
			e = EHClause{
				Flags:              binary.LittleEndian.Uint32(c[0:]),
				TryOffset:          binary.LittleEndian.Uint32(c[4:]),
				TryLength:          binary.LittleEndian.Uint32(c[8:]),
				HandlerOffset:      binary.LittleEndian.Uint32(c[12:]),
				HandlerLength:      binary.LittleEndian.Uint32(c[16:]),
				ClassTokenOrFilter: binary.LittleEndian.Uint32(c[20:]),
			}
		} else {
			e = EHClause{
				Flags:              uint32(binary.LittleEndian.Uint16(c[0:])),
				TryOffset:          uint32(binary.LittleEndian.Uint16(c[2:])),
				TryLength:          uint32(c[4]),
				HandlerOffset:      uint32(binary.LittleEndian.Uint16(c[5:])),
				HandlerLength:      uint32(c[7]),
				ClassTokenOrFilter: binary.LittleEndian.Uint32(c[8:]),
			}
		}
		out = append(out, e)
	}
	return out, nil
}
