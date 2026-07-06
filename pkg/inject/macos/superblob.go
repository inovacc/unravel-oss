/*
Copyright (c) 2026 Security Research
*/
package macos

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// Hardened-runtime / library-validation flag bits in CodeDirectory.flags.
const (
	FlagHardenedRuntime   = 0x00010000
	FlagLibraryValidation = 0x00002000
)

const (
	magicSuperBlob     = 0xfade0cc0
	magicCodeDirectory = 0xfade0c02
	slotCodeDirectory  = 0
)

// SignatureFlags is the parsed CodeDirectory.flags value.
type SignatureFlags uint32

// Has reports whether bit is set.
func (f SignatureFlags) Has(bit uint32) bool { return uint32(f)&bit != 0 }

// ParseSuperBlob parses raw bytes from LC_CODE_SIGNATURE and returns the
// CodeDirectory flags. Returns an error when magic mismatches, lengths
// overflow, or the CodeDirectory slot is absent.
func ParseSuperBlob(b []byte) (SignatureFlags, error) {
	if len(b) < 12 {
		return 0, errors.New("superblob: too short")
	}
	magic := binary.BigEndian.Uint32(b[0:4])
	if magic != magicSuperBlob {
		return 0, fmt.Errorf("superblob: bad magic %#x", magic)
	}
	length := binary.BigEndian.Uint32(b[4:8])
	if int(length) > len(b) {
		return 0, errors.New("superblob: length overflow")
	}
	count := binary.BigEndian.Uint32(b[8:12])
	if 12+int(count)*8 > int(length) {
		return 0, errors.New("superblob: index overflow")
	}
	for i := range count {
		off := 12 + i*8
		slotType := binary.BigEndian.Uint32(b[off : off+4])
		slotOff := binary.BigEndian.Uint32(b[off+4 : off+8])
		if slotType != slotCodeDirectory {
			continue
		}
		if int(slotOff)+16 > len(b) {
			return 0, errors.New("superblob: cd offset overflow")
		}
		cdMagic := binary.BigEndian.Uint32(b[slotOff : slotOff+4])
		if cdMagic != magicCodeDirectory {
			return 0, fmt.Errorf("superblob: bad cd magic %#x", cdMagic)
		}
		flags := binary.BigEndian.Uint32(b[slotOff+12 : slotOff+16])
		return SignatureFlags(flags), nil
	}
	return 0, errors.New("superblob: no CodeDirectory slot")
}

// SigningBlockStrings returns canonical block names for the flags set on f.
// Order: hardened-runtime, library-validation.
func SigningBlockStrings(f SignatureFlags) []string {
	var out []string
	if f.Has(FlagHardenedRuntime) {
		out = append(out, "hardened-runtime")
	}
	if f.Has(FlagLibraryValidation) {
		out = append(out, "library-validation")
	}
	return out
}

// DowngradeConfidence steps c one tier toward low. high→medium,
// medium→low, low→low. Mirrors D-11/D-12/D-13 single-step rule (severity
// downgrade not removal). pkg/inject/scorer.go is confidence-only — the
// CONTEXT "halving" decision maps to a one-tier confidence step here.
func DowngradeConfidence(c inject.Confidence) inject.Confidence {
	switch c {
	case inject.ConfidenceHigh:
		return inject.ConfidenceMedium
	case inject.ConfidenceMedium:
		return inject.ConfidenceLow
	default:
		return inject.ConfidenceLow
	}
}
