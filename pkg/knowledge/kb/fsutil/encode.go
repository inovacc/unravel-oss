package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// reservedRE matches Windows-reserved filename characters and ASCII control
// characters. Any match is replaced with `_`.
var reservedRE = regexp.MustCompile(`[<>:|?*"\\/]|[\x00-\x1f]`)

// underscoreRunRE collapses runs of `_` produced by sanitization back into a
// single underscore, so that pathological inputs do not yield unbounded folder
// names.
var underscoreRunRE = regexp.MustCompile(`_+`)

const maxVersionSegment = 64

// EncodeKsID converts a DB-form ks_id ("<kb_id>:<version>:<captured_at>")
// into a filesystem-safe folder name ("<kb_id>_<version_safe>_<captured_at>").
//
// Sanitization rules applied to the version segment (per D-29-KSID-FORMAT-FS):
//   - Replace each Windows-reserved character `<>:|?*"\/` with `_`.
//   - Replace each ASCII control character (\x00-\x1f) with `_`.
//   - Collapse runs of `_` into a single `_`.
//   - Trim trailing dots and spaces (Windows reserves these).
//   - Truncate to 64 chars and append `_<sha8(originalVersion)>` if longer.
//   - Empty version becomes the literal `unknown`.
func EncodeKsID(ksID string) (string, error) {
	parts := strings.SplitN(ksID, ":", 3)
	if len(parts) != 3 {
		return "", errors.New("invalid ks_id: missing colon separator")
	}
	kbID, version, capturedAt := parts[0], parts[1], parts[2]
	return kbID + "_" + sanitizeVersion(version) + "_" + capturedAt, nil
}

func sanitizeVersion(v string) string {
	if v == "" {
		return "unknown"
	}
	s := reservedRE.ReplaceAllString(v, "_")
	s = underscoreRunRE.ReplaceAllString(s, "_")
	s = strings.TrimRight(s, ". ")
	if s == "" {
		return "unknown"
	}
	if len(s) > maxVersionSegment {
		sum := sha256.Sum256([]byte(v))
		s = s[:maxVersionSegment] + "_" + hex.EncodeToString(sum[:4])
	}
	return s
}
